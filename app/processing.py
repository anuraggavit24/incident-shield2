"""Turn stored webhook events into transactions, rule hits and incidents.

Runs after the webhook has been acknowledged (background task + periodic sweep), so a slow
PayPal lookup or a crash never delays or loses the delivery: the event stays 'pending' or
'failed' in the database until it's processed.
"""

from __future__ import annotations

import logging
import threading
from collections.abc import Callable
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from . import db
from .models import Incident, IncidentEvent, RuleHit, Transaction, WebhookEvent
from .normalize import (
    STATUS_RANK,
    NormalizationError,
    NormalizedTxn,
    decide_transition,
    normalize_event,
    parse_order_identity,
)
from .rules import DEFAULT_CONFIG, LOOKBACK, Hit, RuleTxn, detect_mule_sequence, evaluate

log = logging.getLogger("incident_shield.processing")

MAX_ATTEMPTS = 5
SEVERITY_ORDER = {"low": 1, "medium": 2, "high": 3}
OrderLookup = Callable[[str], dict[str, Any]]

_process_lock = threading.Lock()


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _max_severity(*levels: str) -> str:
    return max(levels, key=lambda s: SEVERITY_ORDER.get(s, 0))


# --------------------------------------------------------------------------- transactions


def _with_identity(txn: NormalizedTxn, lookup: OrderLookup | None) -> tuple[NormalizedTxn, list[str]]:
    """Captures carry no payer data, so look up the order. A failed lookup leaves identity unknown."""
    if txn.kind != "capture" or not txn.order_id or lookup is None:
        return txn, []
    try:
        identity = parse_order_identity(lookup(txn.order_id))
    except Exception as exc:  # noqa: BLE001 - identity is best effort; detection must go on
        log.warning("order lookup failed for %s: %r", txn.order_id, exc)
        return txn, ["identity_lookup_failed"]
    if identity is None:
        return txn, ["identity_not_found"]
    return (
        NormalizedTxn(
            **{
                **txn.__dict__,
                "counterparty_key": identity.key,
                "counterparty_label": identity.label,
                "identity_strength": identity.strength,
                "untrusted_text": identity.untrusted_text,
            }
        ),
        [],
    )


def upsert_transaction(
    session: Session, txn: NormalizedTxn, event_at: datetime | None, flags: list[str]
) -> Transaction:
    row = session.scalar(select(Transaction).where(Transaction.paypal_id == txn.paypal_id))
    if row is None:
        row = Transaction(
            paypal_id=txn.paypal_id,
            kind=txn.kind,
            direction=txn.direction,
            amount=txn.amount,
            currency=txn.currency,
            amount_usd=txn.amount_usd,
            status=txn.status,
            status_rank=STATUS_RANK.get(txn.status, 0),
            occurred_at=txn.occurred_at,
            last_event_at=event_at,
            order_id=txn.order_id,
            custom_id=txn.custom_id,
            counterparty_key=txn.counterparty_key,
            counterparty_label=txn.counterparty_label,
            identity_strength=txn.identity_strength,
            untrusted_text=txn.untrusted_text,
            source="webhook",
            flags=list(flags),
        )
        session.add(row)
        session.flush()
        return row
    apply, flag = decide_transition(row.status, row.last_event_at, txn.status, event_at)
    new_flags = list(row.flags or []) + flags + ([flag] if flag else [])
    if apply:
        row.status = txn.status
        row.status_rank = STATUS_RANK.get(txn.status, 0)
        row.last_event_at = event_at
    if row.counterparty_key is None and txn.counterparty_key:
        row.counterparty_key = txn.counterparty_key
        row.counterparty_label = txn.counterparty_label
        row.identity_strength = txn.identity_strength
        row.untrusted_text = txn.untrusted_text
    row.flags = new_flags
    return row


# --------------------------------------------------------------------------- rules


def _to_rule_txn(row: Transaction) -> RuleTxn:
    return RuleTxn(
        paypal_id=row.paypal_id,
        direction=row.direction,
        amount_usd=row.amount_usd,
        currency=row.currency,
        counterparty_key=row.counterparty_key,
        identity_strength=row.identity_strength,
        occurred_at=row.occurred_at,
        status=row.status,
    )


def _to_hit(row: RuleHit) -> Hit:
    return Hit(
        rule_id=row.rule_id,
        rule_version=row.rule_version,
        severity=row.severity,
        window_start=row.window_start,
        window_end=row.window_end,
        transaction_ids=tuple(row.transaction_ids),
        values=dict(row.values),
    )


def run_rules(session: Session, as_of: datetime) -> list[RuleHit]:
    window_start = as_of - LOOKBACK
    recent = session.scalars(
        select(Transaction).where(Transaction.occurred_at >= window_start, Transaction.occurred_at <= as_of)
    ).all()
    known = set(
        session.scalars(
            select(Transaction.counterparty_key)
            .where(Transaction.direction == "in", Transaction.occurred_at < window_start)
            .where(Transaction.counterparty_key.is_not(None))
            .distinct()
        ).all()
    )
    prior_count = session.scalar(
        select(func.count(Transaction.id)).where(Transaction.occurred_at < as_of - DEFAULT_CONFIG.burst_window)
    )
    new_rows: list[RuleHit] = []
    for hit in evaluate(as_of, [_to_rule_txn(r) for r in recent], known, int(prior_count or 0)):
        if session.scalar(select(RuleHit.id).where(RuleHit.dedupe_key == hit.dedupe_key)) is not None:
            continue
        row = RuleHit(
            rule_id=hit.rule_id,
            rule_version=hit.rule_version,
            severity=hit.severity,
            window_start=hit.window_start,
            window_end=hit.window_end,
            values=hit.values,
            transaction_ids=list(hit.transaction_ids),
            dedupe_key=hit.dedupe_key,
        )
        session.add(row)
        new_rows.append(row)
    session.flush()
    for row in new_rows:
        _supersede_subsets(session, row)
    return new_rows


def _supersede_subsets(session: Session, new: RuleHit) -> None:
    """A rule re-evaluated on each payment produces growing hits (3 senders, then 4...). The larger
    hit replaces the smaller ones it fully contains, so the incident shows one hit per burst.
    Hits already linked into a money-mule incident are never touched (that evidence is fixed)."""
    new_ids = set(new.transaction_ids)
    older = session.scalars(
        select(RuleHit).where(
            RuleHit.rule_id == new.rule_id,
            RuleHit.id != new.id,
            RuleHit.superseded_by.is_(None),
            RuleHit.window_end >= new.window_start,
        )
    ).all()
    for old in older:
        if not set(old.transaction_ids) < new_ids:
            continue
        if old.incident_id is not None:
            incident = session.get(Incident, old.incident_id)
            if incident is not None and incident.kind == "money_mule_pattern":
                continue
            if incident is not None:
                _log(session, incident, "rule_hit_superseded", {"rule_hit_id": old.id, "superseded_by": new.id})
        old.superseded_by = new.id
    session.flush()


# --------------------------------------------------------------------------- incidents


def _log(session: Session, incident: Incident, action: str, details: dict[str, Any]) -> None:
    session.add(IncidentEvent(incident_id=incident.id, actor="system", action=action, details=details))


def _get_or_create_incident(session: Session, dedupe_key: str, kind: str, severity: str, at: datetime) -> Incident:
    incident = session.scalar(select(Incident).where(Incident.dedupe_key == dedupe_key))
    if incident is None:
        incident = Incident(
            kind=kind, severity=severity, status="detected", opened_at=at, updated_at=at, dedupe_key=dedupe_key
        )
        session.add(incident)
        session.flush()
        _log(session, incident, "opened", {"kind": kind, "severity": severity})
    return incident


def attach_hits(session: Session, new_hits: list[RuleHit], as_of: datetime) -> None:
    """Group new hits into an indicator incident for the day, then look for the mule sequence."""
    for hit in new_hits:
        day_key = f"indicators:{hit.window_end.astimezone(timezone.utc).date().isoformat()}"
        incident = _get_or_create_incident(session, day_key, "risk_indicators", hit.severity, as_of)
        hit.incident_id = incident.id
        if SEVERITY_ORDER[hit.severity] > SEVERITY_ORDER[incident.severity]:
            incident.severity = hit.severity
        incident.updated_at = as_of
        _log(session, incident, "rule_hit_attached", {"rule_id": hit.rule_id, "rule_hit_id": hit.id})
    session.flush()

    candidates = session.scalars(
        select(RuleHit).where(
            RuleHit.window_end >= as_of - 3 * DEFAULT_CONFIG.sequence_max_gap, RuleHit.superseded_by.is_(None)
        )
    ).all()
    by_key = {row.dedupe_key: row for row in candidates}
    match = detect_mule_sequence([_to_hit(r) for r in candidates])
    if match is None:
        return
    mule = _get_or_create_incident(session, f"mule:{match.probe.dedupe_key}", "money_mule_pattern", "high", as_of)
    for step, hit in (("probe", match.probe), ("burst", match.burst), ("passthrough", match.passthrough)):
        row = by_key[hit.dedupe_key]
        if row.incident_id == mule.id:
            continue
        previous = row.incident_id
        row.incident_id = mule.id
        _log(session, mule, "sequence_step_linked", {"step": step, "rule_hit_id": row.id, "moved_from": previous})
    mule.updated_at = as_of
    session.flush()


# --------------------------------------------------------------------------- event processing


def process_event(session: Session, event: WebhookEvent, lookup: OrderLookup | None) -> str:
    normalized = normalize_event(event.payload)
    if normalized is None:
        return "ignored"
    normalized, flags = _with_identity(normalized, lookup)
    txn = upsert_transaction(session, normalized, event.event_created_at, flags)
    hits = run_rules(session, txn.occurred_at)
    attach_hits(session, hits, txn.occurred_at)
    return "processed"


def process_pending(lookup: OrderLookup | None, limit: int = 50) -> int:
    """Process pending (and retryable failed) events oldest first. Safe to call concurrently:
    one runner at a time, and each event commits in its own transaction."""
    if not _process_lock.acquire(blocking=False):
        return 0
    done = 0
    try:
        with db.session_scope() as session:
            ids = session.scalars(
                select(WebhookEvent.id)
                .where(
                    (WebhookEvent.status == "pending")
                    | ((WebhookEvent.status == "failed") & (WebhookEvent.attempts < MAX_ATTEMPTS))
                )
                .order_by(WebhookEvent.id)
                .limit(limit)
            ).all()
        for event_id in ids:
            try:
                with db.session_scope() as session:
                    event = session.get(WebhookEvent, event_id)
                    if event is None or event.status in ("processed", "ignored"):
                        continue
                    event.status = process_event(session, event, lookup)
                    event.attempts += 1
                    event.processed_at = _utcnow()
                    event.last_error = None
                done += 1
            except (NormalizationError, Exception) as exc:  # noqa: BLE001 - recorded, retried later
                log.exception("processing failed for webhook event %s", event_id)
                with db.session_scope() as session:
                    event = session.get(WebhookEvent, event_id)
                    if event is not None:
                        event.status = "failed"
                        event.attempts += 1
                        event.last_error = repr(exc)[:500]
    finally:
        _process_lock.release()
    return done
