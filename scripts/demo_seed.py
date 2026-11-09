"""Seed ONE complete money-mule pattern so you can demo incidents and the Copilot.

Why this exists: the PayPal sandbox cannot produce the probe -> burst -> pass-through sequence in
real time, and since round 3 a single rule firing never opens an incident. Without this script a
fresh deployment shows no incidents at all.

Usage:   python scripts/demo_seed.py            (needs DATABASE_URL in .env; run `alembic upgrade head` first)
Effect:  inserts clearly-labelled DEMO webhook events (ids start with "DEMO-") and runs the real
         pipeline on them, with card names supplied locally instead of looking them up on PayPal.
         Safe to run twice: existing DEMO events are skipped. Use it on a demo database only.
"""

from __future__ import annotations

import os
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

from dotenv import load_dotenv

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from sqlalchemy import select  # noqa: E402

from app import db  # noqa: E402
from app.config import normalize_database_url  # noqa: E402
from app.models import Incident, WebhookEvent  # noqa: E402
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


def main() -> int:
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
