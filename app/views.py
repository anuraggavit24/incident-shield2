"""Read models shared by the API and the Copilot: one incident, with its evidence and audit trail."""

from __future__ import annotations

from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from .models import Incident, IncidentEvent, RuleHit, Transaction

DISCLAIMER = "Rule hits are risk indicators from Incident Shield's own heuristics, not proof of fraud."


def txn_out(t: Transaction) -> dict[str, Any]:
    return {
        "paypal_id": t.paypal_id,
        "kind": t.kind,
        "direction": t.direction,
        "amount": str(t.amount),
        "currency": t.currency,
        "amount_usd": str(t.amount_usd) if t.amount_usd is not None else None,
        "status": t.status,
        "occurred_at": t.occurred_at.isoformat(),
        "counterparty": t.counterparty_label,
        "counterparty_key": t.counterparty_key,
        "identity_strength": t.identity_strength,
        "order_id": t.order_id,
        "custom_id": t.custom_id,
        "flags": t.flags,
        # Attacker-controllable: labelled so no consumer mistakes it for trusted data.
        "untrusted_text": t.untrusted_text,
    }


def incident_record(session: Session, incident_id: int) -> dict[str, Any] | None:
    incident = session.get(Incident, incident_id)
    if incident is None:
        return None
    hits = session.scalars(
        select(RuleHit)
        .where(RuleHit.incident_id == incident_id, RuleHit.superseded_by.is_(None))
        .order_by(RuleHit.window_end, RuleHit.id)
    ).all()
    superseded = session.scalar(
        select(func.count(RuleHit.id)).where(RuleHit.incident_id == incident_id, RuleHit.superseded_by.is_not(None))
    )
    txn_ids = sorted({tid for h in hits for tid in h.transaction_ids})
    txns = session.scalars(select(Transaction).where(Transaction.paypal_id.in_(txn_ids))).all() if txn_ids else []
    events = session.scalars(
        select(IncidentEvent).where(IncidentEvent.incident_id == incident_id).order_by(IncidentEvent.id)
    ).all()
    return {
        "id": incident.id,
        "kind": incident.kind,
        "severity": incident.severity,
        "status": incident.status,
        "opened_at": incident.opened_at.isoformat(),
        "updated_at": incident.updated_at.isoformat(),
        "disclaimer": DISCLAIMER,
        "rule_hits": [
            {
                "id": h.id,
                "rule_id": h.rule_id,
                "rule_version": h.rule_version,
                "severity": h.severity,
                "window_start": h.window_start.isoformat(),
                "window_end": h.window_end.isoformat(),
                "values": h.values,
                "transaction_ids": h.transaction_ids,
            }
            for h in hits
        ],
        "superseded_rule_hits": int(superseded or 0),
        "transactions": [txn_out(t) for t in sorted(txns, key=lambda t: t.occurred_at)],
        "audit": [{"at": e.at.isoformat(), "actor": e.actor, "action": e.action, "details": e.details} for e in events],
    }
