"""Build the engine's evidence for one payment attempt from this app's own ledger and the browser's
measurements. Pure data in, plain dict out; the only database access is read-only queries.

Where a value can't be known, the key is left out (the engine then lists it as missing data instead of
guessing). Nothing here comes from PayPal webhooks: the sandbox only moves the money.

Sources, by field:
- ledger: payments, devices, networks and complaints recorded by this app
- browser: measurements the checkout page sends (client-controlled, so a real deployment would need
  device attestation; here they are heuristics, and the README says so)
- simulated: fields a demo user may switch on for things only telecoms, issuers or consortia can see
"""

from __future__ import annotations

import hashlib
import statistics
from collections import defaultdict, deque
from datetime import datetime, timedelta
from decimal import Decimal
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..models import AppComplaint, AppPayment, AppUser

COMPLETED = "captured"
CONFIRMED_FRAUD = ("refund_approved", "refunded")
NO_CHANGE_ON_RECORD_HOURS = 1_000_000  # "never changed" must read as known-and-old, not as missing
NOT_LINKED = 99  # hops to the nearest confirmed-fraud account when the ledger shows no link within 2

# Fields a demo user may switch on. All are things this app cannot observe itself.
SIMULATABLE: dict[str, type] = {
    "active_call": bool,
    "remote_access_or_overlay": bool,
    "device_compromised": bool,
    "credentials_in_breach": bool,
    "anonymising_asn": bool,
    "on_negative_list": bool,
    "network_risk_score_high": bool,
    "sim_swap_days_ago": int,
}


def fingerprint_hash(fp: dict[str, Any]) -> str:
    parts = [str(fp.get(k, ""))[:200] for k in ("ua", "platform", "tz", "lang", "screen")]
    return hashlib.sha256("|".join(parts).encode()).hexdigest()[:32]


def sanitize_simulated(sim: dict[str, Any]) -> dict[str, Any]:
    """Keep only known fields with the right type. Anything else is dropped, never trusted."""
    out: dict[str, Any] = {}
    for key, kind in SIMULATABLE.items():
        value = sim.get(key)
        if kind is bool and isinstance(value, bool):
            out[key] = value
        elif kind is int and isinstance(value, int) and not isinstance(value, bool) and 0 <= value <= 365:
            out[key] = value
    return out


def _days(later: datetime, earlier: datetime) -> int:
    return max(0, (later - earlier).days)


def _fraud_accounts(session: Session) -> set[int]:
    """Accounts that received a payment a reviewer confirmed as fraud (refund approved)."""
    rows = session.execute(
        select(AppPayment.payee_id)
        .join(AppComplaint, AppComplaint.payment_id == AppPayment.id)
        .where(AppComplaint.status.in_(CONFIRMED_FRAUD))
    ).all()
    return {r[0] for r in rows}


def _hops_to_fraud(session: Session, payee_id: int, fraud: set[int], now: datetime) -> int:
    """Shortest link, over completed payments in the last 30 days, from this account to a confirmed one."""
    if payee_id in fraud:
        return 0
    if not fraud:
        return NOT_LINKED
    rows = session.execute(
        select(AppPayment.payer_id, AppPayment.payee_id).where(
            AppPayment.status == COMPLETED, AppPayment.created_at >= now - timedelta(days=30)
        )
    ).all()
    graph: dict[int, set[int]] = defaultdict(set)
    for a, b in rows:
        graph[a].add(b)
        graph[b].add(a)
    seen = {payee_id}
    queue = deque([(payee_id, 0)])
    while queue:
        node, dist = queue.popleft()
        if dist == 2:
            continue
        for nxt in graph[node]:
            if nxt in seen:
                continue
            if nxt in fraud:
                return dist + 1
            seen.add(nxt)
            queue.append((nxt, dist + 1))
    return NOT_LINKED


def build_evidence(
    session: Session,
    payer: AppUser,
    payee: AppUser,
    *,
    amount: Decimal,
    reference: str,
    payee_name_typed: str,
    device_id: str,
    ip_hash: str,
    fp: dict[str, Any],
    behaviour: dict[str, Any],
    simulated: dict[str, Any],
    now: datetime,
    high_value_usd: int,
) -> dict[str, Any]:
    e: dict[str, Any] = {}
    amount_f = float(amount)

    attempts = list(
        session.scalars(
            select(AppPayment)
            .where(AppPayment.payer_id == payer.id, AppPayment.created_at >= now - timedelta(days=90))
            .order_by(AppPayment.created_at)
            .limit(1000)
        )
    )
    done = [p for p in attempts if p.status == COMPLETED]
    to_payee = [p for p in done if p.payee_id == payee.id]

    # ---- identity metadata used by the learning code (not signals)
    e["sender"], e["recipient"] = payer.handle, payee.handle

    # ---- account
    e["account_tenure_days"] = _days(now, payer.created_at)
    complaints = list(session.scalars(select(AppComplaint).where(AppComplaint.payer_id == payer.id)))
    e["account_disputes"] = len(complaints)
    if attempts:
        e["dormant_days"] = _days(now, attempts[-1].created_at)
    e["is_high_value"] = amount >= Decimal(high_value_usd)

    # ---- relationship with the payee
    e["recipient_prior_payments"] = len(to_payee)
    e["new_payee"] = not to_payee
    e["recipient_relationship_days"] = _days(now, to_payee[0].created_at) if to_payee else 0
    payee_payment_ids = {p.id for p in to_payee}
    e["recipient_disputes_by_sender"] = sum(1 for c in complaints if c.payment_id in payee_payment_ids)
    e["matches_recurring_pattern"] = sum(1 for p in to_payee if p.amount == amount) >= 3
    e["payee_name_mismatch"] = payee_name_typed.strip().lower() != payee.display_name.strip().lower()

    # ---- the payer's own devices and networks. The baseline is built from COMPLETED payments only: a
    # device that merely tried (and was held or blocked) must not become "known" on its second attempt.
    if done:
        first_device: dict[str, datetime] = {}
        first_net: dict[str, datetime] = {}
        for p in done:
            if p.device_id:
                first_device.setdefault(p.device_id, p.created_at)
            if p.ip_hash:
                first_net.setdefault(p.ip_hash, p.created_at)
        e["new_device"] = device_id not in first_device
        e["device_seen_days"] = _days(now, first_device[device_id]) if device_id in first_device else 0
        e["network_seen_days"] = _days(now, first_net[ip_hash]) if ip_hash in first_net else 0
        e["fresh_device_on_old_account"] = e["new_device"] and e["account_tenure_days"] >= 30
        # the device must match what we saw from it before: same device id, different browser details
        fp_now = fingerprint_hash(fp)
        earlier = [p for p in done if p.device_id == device_id and (p.client or {}).get("fp_hash")]
        if earlier:
            e["fingerprint_inconsistent"] = earlier[-1].client["fp_hash"] != fp_now
        if payer.credentials_changed_device:
            e["credential_change_from_known_device"] = payer.credentials_changed_device in first_device

    # ---- credential changes
    if payer.credentials_changed_at:
        e["credential_change_hours_ago"] = int((now - payer.credentials_changed_at).total_seconds() // 3600)
    else:
        e["credential_change_hours_ago"] = NO_CHANGE_ON_RECORD_HOURS

    # ---- amounts and velocity
    amounts = [float(p.amount) for p in done]
    if len(amounts) >= 3 and statistics.pstdev(amounts) > 0:
        e["amount_zscore_90d"] = round((amount_f - statistics.mean(amounts)) / statistics.pstdev(amounts), 2)
    if len(amounts) >= 2:
        e["amount_vs_norm_ratio"] = round(amount_f / statistics.median(amounts), 2)
    day_ago, hour_ago, half_ago = now - timedelta(hours=24), now - timedelta(hours=1), now - timedelta(minutes=30)
    recent_day = [p for p in attempts if p.created_at >= day_ago]
    new_payees_24h = {p.payee_id for p in recent_day if p.payee_id not in {q.payee_id for q in done if q.id != p.id}}
    if e["new_payee"]:
        new_payees_24h.add(payee.id)
    e["new_recipients_24h"] = len(new_payees_24h)
    spend_30d = sum(float(p.amount) for p in done if p.created_at >= now - timedelta(days=30))
    if spend_30d > 0:
        spend_1h = sum(float(p.amount) for p in done if p.created_at >= hour_ago) + amount_f
        e["spend_1h_vs_daily_avg_ratio"] = round(spend_1h / (spend_30d / 30), 2)
    near_line = sum(
        1 for p in recent_day if Decimal(high_value_usd) * Decimal("0.9") <= p.amount < Decimal(high_value_usd)
    )
    if Decimal(high_value_usd) * Decimal("0.9") <= amount < Decimal(high_value_usd):
        near_line += 1
    e["amounts_just_under_threshold_24h"] = near_line
    micro = sum(1 for p in attempts if p.created_at >= half_ago and p.amount <= Decimal("1.00")) + (
        1 if amount <= Decimal("1.00") else 0
    )
    e["card_testing_pattern"] = micro >= 3
    blocked_recent = [
        p
        for p in attempts
        if p.created_at >= half_ago and p.payee_id == payee.id and p.status in ("blocked", "held", "declined")
    ]
    e["declined_retry_altered_amount"] = bool(blocked_recent) and all(p.amount != amount for p in blocked_recent)

    # ---- devices and networks shared with other accounts (7 days)
    week = now - timedelta(days=7)
    sharing = list(
        session.execute(
            select(AppPayment.payer_id, AppPayment.device_id, AppPayment.ip_hash).where(
                AppPayment.created_at >= week, (AppPayment.device_id == device_id) | (AppPayment.ip_hash == ip_hash)
            )
        ).all()
    )
    e["accounts_on_device_or_ip_7d"] = len({r[0] for r in sharing} | {payer.id})
    e["accounts_on_device_7d"] = len({r[0] for r in sharing if r[1] == device_id} | {payer.id})
    fraud = _fraud_accounts(session)
    e["device_linked_to_fraud"] = any(r[0] in fraud and r[1] == device_id for r in sharing)
    e["ip_shared_with_fraud_accounts"] = any(r[0] in fraud and r[2] == ip_hash for r in sharing)

    # ---- the payee
    e["recipient_account_age_days"] = _days(now, payee.created_at)
    inbound = list(
        session.scalars(
            select(AppPayment).where(
                AppPayment.payee_id == payee.id, AppPayment.status == COMPLETED, AppPayment.created_at >= week
            )
        )
    )
    e["recipient_senders_7d"] = len({p.payer_id for p in inbound} | {payer.id})
    in_30 = sum(float(p.amount) for p in inbound if p.created_at >= half_ago)
    out_30 = sum(
        float(p.amount)
        for p in session.scalars(
            select(AppPayment).where(
                AppPayment.payer_id == payee.id, AppPayment.status == COMPLETED, AppPayment.created_at >= half_ago
            )
        )
    )
    if in_30 > 0:
        e["recipient_passthrough_ratio_30m"] = round(out_30 / in_30, 2)
    payee_payment_ids_all = select(AppPayment.id).where(AppPayment.payee_id == payee.id)
    e["recipient_prior_complaints"] = len(
        set(session.scalars(select(AppComplaint.payer_id).where(AppComplaint.payment_id.in_(payee_payment_ids_all))))
    )
    e["recipient_hops_to_fraud"] = _hops_to_fraud(session, payee.id, fraud, now)
    e["on_negative_list"] = payee.id in fraud

    # ---- what the payer typed and how
    e["payment_reference"] = reference
    cps = behaviour.get("typing_cps")
    blur, pauses = int(behaviour.get("blur_count") or 0), int(behaviour.get("pause_count") or 0)
    seconds = behaviour.get("seconds_on_page")
    pasted = bool(behaviour.get("paste_used"))
    e["scripted_input"] = bool(
        (isinstance(cps, (int, float)) and cps > 25) or (pasted and isinstance(seconds, (int, float)) and seconds < 4)
    )
    e["coaching_signs"] = blur >= 3 or pauses >= 4
    past_cps = [
        p.client["typing_cps"] for p in attempts if isinstance((p.client or {}).get("typing_cps"), (int, float))
    ]
    if isinstance(cps, (int, float)) and len(past_cps) >= 3:
        mean = statistics.mean(past_cps)
        e["typing_deviation"] = bool(mean > 0 and (cps < 0.4 * mean or cps > 2.5 * mean))
    if done:
        e["direct_to_new_payee_max_amount"] = bool(e["new_payee"] and amount_f >= 2 * max(amounts))

    # ---- simulated (only things this app cannot observe), clearly marked
    sim = sanitize_simulated(simulated)
    e.update(sim)
    if sim:
        e["simulated_fields"] = sorted(sim)
    return e
