"""Seed ONE complete money-mule pattern so you can demo incidents and the Copilot.

Why this exists: the sandbox CAN run the whole pattern live (real card captures and a real payout;
see SPIKE.md), but it can't backdate payments. A live run without a history phase more than an hour
earlier is reported at medium severity, and since round 3 a single rule firing never opens an
incident, so a fresh deployment shows nothing until someone runs the attack. This gives a ready,
repeatable incident for judges and for the Copilot. Prefer the live sandbox run for the video.

Usage:   python scripts/demo_seed.py --confirm   (needs DATABASE_URL in .env; run `alembic upgrade head` first)
         python scripts/demo_seed.py --remove    (deletes the DEMO- data and everything built from it)
Effect:  inserts clearly-labelled DEMO webhook events (ids start with "DEMO-") and runs the real
         pipeline on them, with card names supplied locally instead of looking them up on PayPal.
         These events are NOT from PayPal and were never signature-verified. Their fake "regular
         buyers" also count as history for real events, so use a demo database only.
         Safe to run twice: existing DEMO events are skipped.
"""

from __future__ import annotations

import os
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

from dotenv import load_dotenv

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from sqlalchemy import delete, select, update  # noqa: E402

from app import db  # noqa: E402
from app.config import normalize_database_url  # noqa: E402
from app.models import CopilotCall, Incident, IncidentEvent, RuleHit, Transaction, WebhookEvent  # noqa: E402
from app.processing import process_pending  # noqa: E402

PAYERS = {
    "DEMO-ORD-H1": "Regular Buyer One",
    "DEMO-ORD-H2": "Regular Buyer Two",
    "DEMO-ORD-H3": "Regular Buyer Three",
    "DEMO-ORD-P": "Test Prober",
    "DEMO-ORD-A": "New Payer A",
    "DEMO-ORD-B": "New Payer B",
    "DEMO-ORD-C": "New Payer C",
}


def _ts(t: datetime) -> str:
    return t.strftime("%Y-%m-%dT%H:%M:%SZ")


def _capture(tag: str, at: datetime, amount: str, order: str) -> dict:
    return {
        "id": f"DEMO-{tag}",
        "event_type": "PAYMENT.CAPTURE.COMPLETED",
        "create_time": _ts(at),
        "resource": {
            "id": f"DEMOCAP{tag}",
            "amount": {"currency_code": "USD", "value": amount},
            "status": "COMPLETED",
            "create_time": _ts(at),
            "supplementary_data": {"related_ids": {"order_id": order}},
        },
    }


def _payout(tag: str, at: datetime, amount: str, receiver: str) -> dict:
    return {
        "id": f"DEMO-{tag}",
        "event_type": "PAYMENT.PAYOUTS-ITEM.SUCCEEDED",
        "create_time": _ts(at),
        "resource": {
            "transaction_id": f"DEMOOUT{tag}",
            "transaction_status": "SUCCESS",
            "time_processed": _ts(at),
            "payout_item": {"amount": {"currency": "USD", "value": amount}, "receiver": receiver},
        },
    }


def build_events(now: datetime) -> list[dict]:
    """Three regular buyers 3-5 hours ago (gives the account history), then, ending ~20 minutes
    ago: a $0.79 probe, three new $100 payers within 3 minutes, and a $290 payout to an outside address."""
    start = now.replace(second=0, microsecond=0) - timedelta(minutes=30)
    return [
        _capture("H1", start - timedelta(hours=5), "25.00", "DEMO-ORD-H1"),
        _capture("H2", start - timedelta(hours=4), "30.00", "DEMO-ORD-H2"),
        _capture("H3", start - timedelta(hours=3), "28.00", "DEMO-ORD-H3"),
        _capture("PRB", start, "0.79", "DEMO-ORD-P"),
        _capture("A", start + timedelta(minutes=5), "100.00", "DEMO-ORD-A"),
        _capture("B", start + timedelta(minutes=6), "100.00", "DEMO-ORD-B"),
        _capture("C", start + timedelta(minutes=7), "100.00", "DEMO-ORD-C"),
        _payout("OUT", start + timedelta(minutes=9), "290.00", "exchange@example.com"),
    ]


def card_lookup(order_id: str) -> dict:
    return {"payment_source": {"card": {"name": PAYERS[order_id], "last_digits": "4242", "brand": "VISA"}}}


def seed(now: datetime | None = None) -> int:
    """Insert the demo events that are not there yet, process them, return the mule incident id."""
    now = now or datetime.now(timezone.utc)
    events = build_events(now)
    with db.session_scope() as session:
        have = set(session.scalars(select(WebhookEvent.event_id).where(WebhookEvent.event_id.like("DEMO-%"))))
        for e in events:
            if e["id"] in have:
                continue
            res = e["resource"]
            session.add(
                WebhookEvent(
                    event_id=e["id"],
                    event_type=e["event_type"],
                    resource_id=res.get("id") or res.get("transaction_id"),
                    event_created_at=datetime.fromisoformat(e["create_time"].replace("Z", "+00:00")),
                    payload=e,
                    status="pending",
                )
            )
    process_pending(card_lookup)
    with db.session_scope() as session:
        incident = session.scalar(
            select(Incident).where(Incident.kind == "money_mule_pattern").order_by(Incident.id.desc()).limit(1)
        )
        return incident.id if incident else 0


def remove() -> dict[str, int]:
    """Delete DEMO- events, their transactions, every rule hit that used one of them, and incidents
    left with demo hits (with their audit log and Copilot answers). Mixed incidents are removed too:
    any incident that touched demo data is no longer trustworthy evidence."""
    with db.session_scope() as session:
        demo_txns = set(session.scalars(select(Transaction.paypal_id).where(Transaction.paypal_id.like("DEMO%"))))
        hits = [h for h in session.scalars(select(RuleHit)) if demo_txns.intersection(h.transaction_ids or [])]
        hit_ids = {h.id for h in hits}
        incident_ids = {h.incident_id for h in hits if h.incident_id is not None}
        if incident_ids:
            # Hits from real data in those incidents stay, unlinked (they're still listed at /rule-hits).
            session.execute(update(RuleHit).where(RuleHit.incident_id.in_(incident_ids)).values(incident_id=None))
            session.execute(delete(CopilotCall).where(CopilotCall.incident_id.in_(incident_ids)))
            session.execute(delete(IncidentEvent).where(IncidentEvent.incident_id.in_(incident_ids)))
        if hit_ids:
            session.execute(update(RuleHit).where(RuleHit.superseded_by.in_(hit_ids)).values(superseded_by=None))
            session.execute(delete(RuleHit).where(RuleHit.id.in_(hit_ids)))
        if incident_ids:
            session.execute(delete(Incident).where(Incident.id.in_(incident_ids)))
        txns = session.execute(delete(Transaction).where(Transaction.paypal_id.like("DEMO%"))).rowcount
        events = session.execute(delete(WebhookEvent).where(WebhookEvent.event_id.like("DEMO-%"))).rowcount
    return {"events": events, "transactions": txns, "rule_hits": len(hit_ids), "incidents": len(incident_ids)}


def main() -> int:
    if "--remove" in sys.argv[1:]:
        load_dotenv()
        url = os.getenv("DATABASE_URL", "").strip()
        if not url:
            print("DATABASE_URL is not set (put it in .env).")
            return 1
        db.init_engine(normalize_database_url(url))
        print("Removed:", remove())
        return 0
    if "--confirm" not in sys.argv[1:]:
        print("This writes fake, unverified DEMO- events into DATABASE_URL and they affect real detection.")
        print("Use a demo database only, then run again with --confirm.")
        return 2
    load_dotenv()
    url = os.getenv("DATABASE_URL", "").strip()
    if not url:
        print("DATABASE_URL is not set (put it in .env).")
        return 1
    db.init_engine(normalize_database_url(url))
    incident_id = seed()
    if not incident_id:
        print("Events were processed but no incident opened. Is the database fresh and migrated?")
        return 1
    print(f"Demo incident ready: id {incident_id}")
    print(f"  GET /incidents/{incident_id}")
    print(f"  POST /incidents/{incident_id}/ask   (needs GEMINI_API_KEY for a model answer)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
