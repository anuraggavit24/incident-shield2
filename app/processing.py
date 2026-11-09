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
from decimal import Decimal
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
from .rules import (
    COUNTABLE_STATUSES,
    DEFAULT_CONFIG,
    LOOKBACK,
    Hit,
    RecipientHistory,
    RuleTxn,
    detect_mule_sequence,
    detect_partial_sequence,
    evaluate,
)

log = logging.getLogger("incident_shield.processing")

MAX_ATTEMPTS = 5
# A failed payer lookup is retried this many times (one sweep apart) before the payment is
# processed with an unknown payer. A brief PayPal API outage must not turn repeat buyers into
# a false "burst of new senders".
IDENTITY_RETRY_ATTEMPTS = 3
SEVERITY_ORDER = {"low": 1, "medium": 2, "high": 3}
OrderLookup = Callable[[str], dict[str, Any]]

_process_lock = threading.Lock()


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _max_severity(*levels: str) -> str:
    return max(levels, key=lambda s: SEVERITY_ORDER.get(s, 0))


# --------------------------------------------------------------------------- transactions


class RetryLater(RuntimeError):
    """Processing should be retried on a later sweep."""


def _with_identity(
    txn: NormalizedTxn, lookup: OrderLookup | None, attempts_so_far: int
) -> tuple[NormalizedTxn, list[str]]:
    """Captures carry no payer data, so look up the order. A failed lookup is retried on later
    sweeps; only after IDENTITY_RETRY_ATTEMPTS does the payment go ahead with an unknown payer."""
    if txn.kind != "capture" or not txn.order_id or lookup is None:
        return txn, []
    try:
        identity = parse_order_identity(lookup(txn.order_id))
    except Exception as exc:  # noqa: BLE001 - recorded and retried
        log.warning("order lookup failed for %s: %r", txn.order_id, exc)
        if attempts_so_far + 1 < IDENTITY_RETRY_ATTEMPTS:
            raise RetryLater(f"payer lookup failed, will retry: {exc!r}") from exc
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
        amount=row.amount,
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
    known_recipients = {
        key: RecipientHistory(payouts=int(count), total_usd=Decimal(total or 0))
        for key, count, total in session.execute(
            select(Transaction.counterparty_key, func.count(Transaction.id), func.sum(func.abs(Transaction.amount_usd)))
            .where(Transaction.direction == "out", Transaction.occurred_at < window_start)
            .where(Transaction.counterparty_key.is_not(None), Transaction.status.in_(COUNTABLE_STATUSES))
            .group_by(Transaction.counterparty_key)
        ).all()
    }
    prior_count = session.scalar(
        select(func.count(Transaction.id)).where(Transaction.occurred_at < as_of - DEFAULT_CONFIG.burst_window)
    )
    new_rows: list[RuleHit] = []
    rule_txns = [_to_rule_txn(r) for r in recent]
    for hit in evaluate(as_of, rule_txns, known, int(prior_count or 0), known_recipients=known_recipients):
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
            if incident is not None:
                if incident.kind in PATTERN_KINDS:
                    # The bigger hit takes the old one's place in the sequence, so the incident never
                    # counts the same burst twice. The audit log keeps both IDs.
                    new.incident_id = incident.id
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


PATTERN_KINDS = ("money_mule_pattern", "partial_pattern")


def open_sequence_incident(session: Session, as_of: datetime) -> None:
    """Full probe -> burst -> out sequence: `money_mule_pattern` (medium/high).
    Two of the three steps in order: `partial_pattern`, low severity, "needs review". It's upgraded in
    place if the missing step shows up later, so one pattern is always one incident.

    A single rule firing is stored and listed at GET /rule-hits, but never opens an incident: R1 has
    no per-account baseline, so a busy sales hour from new customers looks exactly like a burst."""
    candidates = session.scalars(
        select(RuleHit).where(
            RuleHit.window_end >= as_of - 3 * DEFAULT_CONFIG.sequence_max_gap, RuleHit.superseded_by.is_(None)
        )
    ).all()
    by_key = {row.dedupe_key: row for row in candidates}
    hits = [_to_hit(r) for r in candidates]
    match = detect_mule_sequence(hits)
    steps: tuple[tuple[str, Hit], ...]
    if match is not None:
        kind, prefix = "money_mule_pattern", "mule"
        # Without enough history, "new sender" may include regular customers: say so in the severity.
        severity = "high" if match.burst.values.get("history") == "ok" else "medium"
        steps = (("probe", match.probe), ("burst", match.burst), ("passthrough", match.passthrough))
    else:
        partial = detect_partial_sequence(hits)
        if partial is None:
            return
        kind, prefix, severity = "partial_pattern", "partial", "low"
        steps = partial.steps
    # A late webhook can reveal an EARLIER probe for a pattern that already has an incident. Keying
    # only on the earliest probe would then open a second incident for the same pattern, so reuse
    # the oldest incident any of the matched hits is already linked to.
    linked_ids = [by_key[h.dedupe_key].incident_id for _, h in steps if by_key[h.dedupe_key].incident_id is not None]
    existing = (
        session.scalar(
            select(Incident)
            .where(Incident.id.in_(linked_ids), Incident.kind.in_(PATTERN_KINDS))
            .order_by(Incident.id)
            .limit(1)
        )
        if linked_ids
        else None
    )
    mule = existing or _get_or_create_incident(session, f"{prefix}:{steps[0][1].dedupe_key}", kind, severity, as_of)
    if existing is not None and kind == "money_mule_pattern" and mule.kind == "partial_pattern":
        mule.kind, mule.severity = kind, severity
        _log(session, mule, "upgraded_to_full_pattern", {"severity": severity})
    elif existing is not None and SEVERITY_ORDER[severity] > SEVERITY_ORDER[mule.severity]:
        mule.severity = severity
        _log(session, mule, "severity_raised", {"severity": severity})
    for step, hit in steps:
        row = by_key[hit.dedupe_key]
        if row.incident_id == mule.id:
            continue
        previous = row.incident_id
        row.incident_id = mule.id
        _log(session, mule, "sequence_step_linked", {"step": step, "rule_hit_id": row.id, "moved_from": previous})
    mule.updated_at = as_of
    session.flush()


# --------------------------------------------------------------------------- event processing


def evaluation_times(session: Session, txn: Transaction) -> list[datetime]:
    """The new transaction's own time, plus every stored transaction time within LOOKBACK after it.

    Webhooks can arrive late (PayPal retries for days). A late payment can complete a pattern that
    was evaluated earlier without it, so every later evaluation point it falls into is re-run.
    """
    later = session.scalars(
        select(Transaction.occurred_at)
        .where(Transaction.occurred_at > txn.occurred_at, Transaction.occurred_at <= txn.occurred_at + LOOKBACK)
        .distinct()
    ).all()
    return sorted({txn.occurred_at, *later})


def process_event(session: Session, event: WebhookEvent, lookup: OrderLookup | None) -> str:
    normalized = normalize_event(event.payload)
    if normalized is None:
        return "ignored"
    normalized, flags = _with_identity(normalized, lookup, event.attempts)
    txn = upsert_transaction(session, normalized, event.event_created_at, flags)
    times = evaluation_times(session, txn)
    for as_of in times:
        run_rules(session, as_of)
    open_sequence_incident(session, times[-1])
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
            except (RetryLater, NormalizationError, Exception) as exc:  # noqa: BLE001 - recorded, retried later
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
