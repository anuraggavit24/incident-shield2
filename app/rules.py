"""Guard: deterministic detection rules. Pure functions, no I/O, no AI.

Every rule is evaluated "as of" an event time (never the wall clock), so the same
input always gives the same result, live or in replay.

These thresholds are Incident Shield's own heuristics. PayPal publishes trigger
CATEGORIES (volume spikes, disputes, unusual activity) but not numbers.
A hit is a risk indicator, not proof of fraud, takeover or laundering.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from decimal import Decimal
from typing import Any

COUNTABLE_STATUSES = frozenset({"COMPLETED", "SUCCESS"})
# Currencies where one unit is roughly a dollar or more, so "under 1.00" is a tiny payment
# even when PayPal gives no USD value (e.g. the money stays in that currency's balance).
ONE_UNIT_AT_LEAST_ABOUT_A_DOLLAR = frozenset({"USD", "EUR", "GBP", "CHF", "CAD", "AUD", "NZD", "SGD"})


@dataclass(frozen=True)
class RuleConfig:
    burst_window: timedelta = timedelta(minutes=30)
    burst_min_new_senders: int = 3
    passthrough_window: timedelta = timedelta(minutes=60)
    # Mules move out most of what arrives; a shop paying a supplier usually doesn't.
    passthrough_min_ratio: Decimal = Decimal("0.8")
    # A recipient is "established" only with at least this many earlier payouts, together worth at
    # least this share of the new payout, so one tiny warm-up payment isn't enough.
    # This is NOT attacker-proof: paying your own cash-out account first costs nothing (see README).
    established_min_payouts: int = 2
    established_min_share: Decimal = Decimal("0.5")
    probe_max_usd: Decimal = Decimal("1.00")
    probe_window: timedelta = timedelta(minutes=60)
    currency_window: timedelta = timedelta(minutes=60)
    currency_min_distinct: int = 3
    min_prior_history: int = 3
    sequence_max_gap: timedelta = timedelta(minutes=60)


DEFAULT_CONFIG = RuleConfig()
LOOKBACK = max(
    DEFAULT_CONFIG.burst_window,
    DEFAULT_CONFIG.passthrough_window,
    DEFAULT_CONFIG.probe_window,
    DEFAULT_CONFIG.currency_window,
)


@dataclass(frozen=True)
class RuleTxn:
    paypal_id: str
    direction: str
    amount: Decimal
    amount_usd: Decimal | None
    currency: str
    counterparty_key: str | None
    identity_strength: str
    occurred_at: datetime
    status: str


@dataclass(frozen=True)
class RecipientHistory:
    payouts: int
    total_usd: Decimal


@dataclass(frozen=True)
class Hit:
    rule_id: str
    rule_version: int
    severity: str
    window_start: datetime
    window_end: datetime
    transaction_ids: tuple[str, ...]
    values: dict[str, Any] = field(default_factory=dict)

    @property
    def dedupe_key(self) -> str:
        raw = f"{self.rule_id}|{self.rule_version}|{','.join(sorted(self.transaction_ids))}"
        return hashlib.sha256(raw.encode()).hexdigest()


def _countable(txns: list[RuleTxn]) -> list[RuleTxn]:
    return [t for t in txns if t.status in COUNTABLE_STATUSES]


def _in_window(txns: list[RuleTxn], start: datetime, end: datetime) -> list[RuleTxn]:
    return [t for t in txns if start <= t.occurred_at <= end]


def _is_new(t: RuleTxn, known: set[str]) -> bool:
    # No identity at all counts as new: missing data must not hide a burst.
    return t.counterparty_key is None or t.counterparty_key not in known


def _sum_usd(txns: list[RuleTxn]) -> tuple[Decimal, int]:
    """Sum of USD values, plus how many transactions had no USD value (excluded, reported)."""
    total = Decimal("0")
    missing = 0
    for t in txns:
        if t.amount_usd is None:
            missing += 1
        else:
            total += abs(t.amount_usd)
    return total, missing


def r1_burst_new_senders(
    as_of: datetime, recent: list[RuleTxn], known: set[str], prior_count: int, cfg: RuleConfig = DEFAULT_CONFIG
) -> Hit | None:
    start = as_of - cfg.burst_window
    new_in = [t for t in _in_window(recent, start, as_of) if t.direction == "in" and _is_new(t, known)]
    senders = {t.counterparty_key or f"unknown:{t.paypal_id}" for t in new_in}
    if len(senders) < cfg.burst_min_new_senders:
        return None
    total, missing = _sum_usd(new_in)
    weak = sum(1 for t in new_in if t.identity_strength != "strong")
    insufficient = prior_count < cfg.min_prior_history
    return Hit(
        rule_id="R1_BURST_NEW_SENDERS",
        rule_version=1,
        severity="low" if insufficient else "medium",
        window_start=start,
        window_end=as_of,
        transaction_ids=tuple(sorted(t.paypal_id for t in new_in)),
        values={
            "new_sender_count": len(senders),
            "payment_count": len(new_in),
            "total_usd": str(total),
            "payments_without_usd_value": missing,
            "weak_identity_payments": weak,
            "prior_transaction_count": prior_count,
            "history": "insufficient" if insufficient else "ok",
        },
    )


def r2_pass_through(
    as_of: datetime,
    recent: list[RuleTxn],
    known: set[str],
    known_recipients: dict[str, RecipientHistory],
    cfg: RuleConfig = DEFAULT_CONFIG,
) -> Hit | None:
    """Most of the money from new senders leaving to a recipient without established history.

    Established = at least `established_min_payouts` earlier payouts worth together at least
    `established_min_share` of this payout. A single $1 payment an hour earlier doesn't qualify.
    Informational on its own; it matters inside the probe -> burst -> out sequence."""
    start = as_of - cfg.passthrough_window
    window = _in_window(recent, start, as_of)
    new_in = [t for t in window if t.direction == "in" and _is_new(t, known)]
    if not new_in:
        return None
    first_new = min(t.occurred_at for t in new_in)
    all_outs = [t for t in window if t.direction == "out" and t.occurred_at >= first_new]

    def established(t: RuleTxn) -> bool:
        history = known_recipients.get(t.counterparty_key or "")
        if history is None or history.payouts < cfg.established_min_payouts:
            return False
        if t.amount_usd is None:
            return history.total_usd > 0
        return history.total_usd >= abs(t.amount_usd) * cfg.established_min_share

    outs = [t for t in all_outs if not established(t)]
    if not outs:
        return None
    total_in, _ = _sum_usd(new_in)
    total_out, _ = _sum_usd(outs)
    if total_in <= 0 or total_out < total_in * cfg.passthrough_min_ratio:
        return None
    return Hit(
        rule_id="R2_PASS_THROUGH",
        rule_version=2,  # v2: 80% ratio + established recipients (review round 2)
        severity="low",
        window_start=start,
        window_end=as_of,
        transaction_ids=tuple(sorted(t.paypal_id for t in new_in + outs)),
        values={
            "inflow_from_new_senders_usd": str(total_in),
            "outflow_to_unestablished_recipients_usd": str(total_out),
            "outflows_to_established_recipients_excluded": len(all_outs) - len(outs),
            "ratio": str((total_out / total_in).quantize(Decimal("0.01"))),
            "minutes_from_first_inflow_to_last_outflow": round(
                (max(t.occurred_at for t in outs) - first_new).total_seconds() / 60, 1
            ),
        },
    )


def r3_probe_payments(
    as_of: datetime, recent: list[RuleTxn], known: set[str], cfg: RuleConfig = DEFAULT_CONFIG
) -> list[Hit]:
    """Tiny payment from an unknown sender: a common way to test whether an account is live."""
    start = as_of - cfg.probe_window
    hits = []
    for t in _in_window(recent, start, as_of):
        if t.direction != "in" or not _is_new(t, known):
            continue
        if t.amount_usd is not None:
            tiny, basis = t.amount_usd < cfg.probe_max_usd, "usd"
        elif t.currency in ONE_UNIT_AT_LEAST_ABOUT_A_DOLLAR:
            tiny, basis = t.amount < cfg.probe_max_usd, f"original_currency_{t.currency}"
        else:
            continue  # no USD value and no safe unit comparison: not evaluated
        if tiny:
            hits.append(
                Hit(
                    rule_id="R3_PROBE_PAYMENT",
                    rule_version=1,
                    severity="low",
                    window_start=t.occurred_at,
                    window_end=t.occurred_at,
                    transaction_ids=(t.paypal_id,),
                    values={
                        "amount": str(t.amount),
                        "currency": t.currency,
                        "amount_usd": str(t.amount_usd) if t.amount_usd is not None else None,
                        "threshold": str(cfg.probe_max_usd),
                        "threshold_basis": basis,
                    },
                )
            )
    return hits


def r4_currency_mix(as_of: datetime, recent: list[RuleTxn], cfg: RuleConfig = DEFAULT_CONFIG) -> Hit | None:
    """Inflows in several ORIGINAL currencies in a short window (conversions don't count)."""
    start = as_of - cfg.currency_window
    inflows = [t for t in _in_window(recent, start, as_of) if t.direction == "in"]
    currencies = sorted({t.currency for t in inflows})
    if len(currencies) < cfg.currency_min_distinct:
        return None
    return Hit(
        rule_id="R4_CURRENCY_MIX",
        rule_version=1,
        severity="low",
        window_start=start,
        window_end=as_of,
        transaction_ids=tuple(sorted(t.paypal_id for t in inflows)),
        values={"currencies": currencies, "payment_count": len(inflows)},
    )


def evaluate(
    as_of: datetime,
    recent: list[RuleTxn],
    known: set[str],
    prior_count: int,
    cfg: RuleConfig = DEFAULT_CONFIG,
    known_recipients: dict[str, RecipientHistory] | None = None,
) -> list[Hit]:
    """Run every rule. `recent` should cover at least LOOKBACK before `as_of`;
    `known` = senders seen before the lookback window; `known_recipients` = payout history per
    recipient before it."""
    txns = _countable(recent)
    hits: list[Hit] = []
    for hit in (
        r1_burst_new_senders(as_of, txns, known, prior_count, cfg),
        r2_pass_through(as_of, txns, known, known_recipients or {}, cfg),
        r4_currency_mix(as_of, txns, cfg),
    ):
        if hit is not None:
            hits.append(hit)
    hits.extend(r3_probe_payments(as_of, txns, known, cfg))
    return hits


@dataclass(frozen=True)
class SequenceMatch:
    probe: Hit
    burst: Hit
    passthrough: Hit


@dataclass(frozen=True)
class PartialMatch:
    """Two of the three sequence steps, in order: (step name, hit) pairs."""

    steps: tuple[tuple[str, Hit], tuple[str, Hit]]


def detect_partial_sequence(hits: list[Hit], cfg: RuleConfig = DEFAULT_CONFIG) -> PartialMatch | None:
    """Two of probe -> burst -> money out, in order and within the gap (probe -> out may span two gaps,
    since the burst between them is missing). This is what an evader who stays under one threshold
    leaves behind, e.g. draining 79% or paying a "warmed-up" recipient. Returns the earliest pair."""
    by_rule = {
        name: sorted((h for h in hits if h.rule_id == rule), key=lambda h: h.window_end)
        for name, rule in (
            ("probe", "R3_PROBE_PAYMENT"),
            ("burst", "R1_BURST_NEW_SENDERS"),
            ("passthrough", "R2_PASS_THROUGH"),
        )
    }
    pairs = (("probe", "burst", 1), ("burst", "passthrough", 1), ("probe", "passthrough", 2))
    found: list[PartialMatch] = []
    for first, second, gaps in pairs:
        for a in by_rule[first]:
            b = next(
                (
                    h
                    for h in by_rule[second]
                    if a.window_end <= h.window_end <= a.window_end + gaps * cfg.sequence_max_gap
                ),
                None,
            )
            if b is not None:
                found.append(PartialMatch(steps=((first, a), (second, b))))
                break
    return min(found, key=lambda m: m.steps[0][1].window_end, default=None)


def detect_mule_sequence(hits: list[Hit], cfg: RuleConfig = DEFAULT_CONFIG) -> SequenceMatch | None:
    """Probe payment -> burst from new senders -> money moved out, each step within
    `sequence_max_gap` of the previous one. Returns the earliest complete match."""
    probes = sorted((h for h in hits if h.rule_id == "R3_PROBE_PAYMENT"), key=lambda h: h.window_end)
    bursts = sorted((h for h in hits if h.rule_id == "R1_BURST_NEW_SENDERS"), key=lambda h: h.window_end)
    passes = sorted((h for h in hits if h.rule_id == "R2_PASS_THROUGH"), key=lambda h: h.window_end)
    for probe in probes:
        for burst in bursts:
            if not (probe.window_end <= burst.window_end <= probe.window_end + cfg.sequence_max_gap):
                continue
            for out in passes:
                if burst.window_end <= out.window_end <= burst.window_end + cfg.sequence_max_gap:
                    return SequenceMatch(probe=probe, burst=burst, passthrough=out)
    return None
