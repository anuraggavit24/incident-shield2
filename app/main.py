"""Incident Shield API.

Run locally:  uvicorn app.main:app --port 8000
"""

from __future__ import annotations

import asyncio
import hmac
import json
import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any

from fastapi import BackgroundTasks, Depends, FastAPI, Header, HTTPException, Query, Request
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import JSONResponse
from sqlalchemy import select, text
from sqlalchemy.exc import IntegrityError

from . import db
from .config import get_settings, hash_api_key
from .models import Incident, IncidentEvent, RuleHit, Transaction, WebhookEvent
from .normalize import parse_time
from .paypal_client import PayPalClient, PayPalError
from .processing import process_pending

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
log = logging.getLogger("incident_shield")

MAX_BODY_BYTES = 64 * 1024


class BodyTooLarge(Exception):
    pass


async def read_capped(request: Request, limit: int) -> bytes:
    received = bytearray()
    async for chunk in request.stream():
        received.extend(chunk)
        if len(received) > limit:
            raise BodyTooLarge
    return bytes(received)


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    settings = get_settings()
    db.init_engine(settings.database_url)
    app.state.paypal = PayPalClient(settings)
    app.state.sweeper = asyncio.create_task(_sweep_forever(app, settings.process_interval_s))
    try:
        yield
    finally:
        app.state.sweeper.cancel()
        app.state.paypal.close()


async def _sweep_forever(app: FastAPI, interval: float) -> None:
    """Startup + periodic sweep: anything left pending (e.g. a restart killed a background task) gets processed."""
    while True:
        try:
            await run_in_threadpool(process_pending, app.state.paypal.get_order)
        except Exception:  # noqa: BLE001 - the sweeper must never die
            log.exception("sweep failed")
        await asyncio.sleep(interval)


app = FastAPI(title="Incident Shield", version="0.1.0", lifespan=lifespan)


def require_owner(x_api_key: str = Header(default="")) -> None:
    expected = get_settings().owner_api_key_sha256
    if not x_api_key or not hmac.compare_digest(hash_api_key(x_api_key), expected):
        raise HTTPException(status_code=401, detail="invalid API key")


# --------------------------------------------------------------------------- health


@app.get("/health/live")
def live() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/health/ready")
def ready() -> JSONResponse:
    try:
        with db.get_engine().connect() as conn:
            conn.execute(text("SELECT 1"))
    except Exception:  # noqa: BLE001 - readiness reports, never raises
        return JSONResponse({"status": "database unavailable"}, status_code=503)
    return JSONResponse({"status": "ok"})


# --------------------------------------------------------------------------- webhook intake


@app.post("/webhooks/paypal")
async def paypal_webhook(request: Request, background: BackgroundTasks) -> JSONResponse:
    """Verify -> persist -> acknowledge -> process in the background.

    200: stored (or already stored: duplicates are harmless)
    400: bad body or invalid signature (never stored)
    413: body over 64 KB
    503: verification or database unavailable -> PayPal retries (up to 25 times over 3 days)
    """
    declared = request.headers.get("content-length", "")
    if declared.isdigit() and int(declared) > MAX_BODY_BYTES:
        return JSONResponse({"outcome": "too_large"}, status_code=413)
    try:
        raw = await read_capped(request, MAX_BODY_BYTES)
    except BodyTooLarge:
        return JSONResponse({"outcome": "too_large"}, status_code=413)
    try:
        event = json.loads(raw.decode("utf-8"))
    except ValueError:
        return JSONResponse({"outcome": "bad_json"}, status_code=400)
    if not isinstance(event, dict) or not isinstance(event.get("id"), str):
        return JSONResponse({"outcome": "bad_json"}, status_code=400)

    headers = {k.lower(): v for k, v in request.headers.items()}
    try:
        status = await run_in_threadpool(request.app.state.paypal.verify_webhook, headers, raw)
    except (PayPalError, Exception):  # noqa: BLE001 - any failure to verify means "try again later"
        log.warning("webhook verification unavailable", exc_info=True)
        return JSONResponse({"outcome": "verification_unavailable"}, status_code=503)
    if status != "SUCCESS":
        return JSONResponse({"outcome": "invalid_signature"}, status_code=400)

    resource = event.get("resource") if isinstance(event.get("resource"), dict) else {}
    row = WebhookEvent(
        event_id=event["id"][:128],
        event_type=str(event.get("event_type", ""))[:128],
        resource_id=str(resource.get("id") or resource.get("transaction_id") or "")[:128] or None,
        event_created_at=parse_time(event.get("create_time")),
        payload=event,
        status="pending",
    )
    try:
        with db.session_scope() as session:
            session.add(row)
    except IntegrityError:
        return JSONResponse({"outcome": "duplicate"}, status_code=200)
    except Exception:  # noqa: BLE001 - e.g. database cold start or outage
        log.warning("could not store webhook event", exc_info=True)
        return JSONResponse({"outcome": "storage_unavailable"}, status_code=503)

    background.add_task(process_pending, request.app.state.paypal.get_order)
    return JSONResponse({"outcome": "accepted"}, status_code=200)


# --------------------------------------------------------------------------- read API (owner)


def _txn_out(t: Transaction) -> dict[str, Any]:
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
        "identity_strength": t.identity_strength,
        "custom_id": t.custom_id,
        "flags": t.flags,
        # Attacker-controllable: labelled so no consumer mistakes it for trusted data.
        "untrusted_text": t.untrusted_text,
    }


@app.get("/transactions", dependencies=[Depends(require_owner)])
def list_transactions(limit: int = Query(100, ge=1, le=500)) -> list[dict[str, Any]]:
    with db.session_scope() as session:
        rows = session.scalars(select(Transaction).order_by(Transaction.occurred_at.desc()).limit(limit)).all()
        return [_txn_out(t) for t in rows]


@app.get("/incidents", dependencies=[Depends(require_owner)])
def list_incidents() -> list[dict[str, Any]]:
    with db.session_scope() as session:
        rows = session.scalars(select(Incident).order_by(Incident.updated_at.desc())).all()
        return [
            {
                "id": i.id,
                "kind": i.kind,
                "severity": i.severity,
                "status": i.status,
                "opened_at": i.opened_at.isoformat(),
                "updated_at": i.updated_at.isoformat(),
            }
            for i in rows
        ]


@app.get("/incidents/{incident_id}", dependencies=[Depends(require_owner)])
def get_incident(incident_id: int) -> dict[str, Any]:
    with db.session_scope() as session:
        incident = session.get(Incident, incident_id)
        if incident is None:
            raise HTTPException(status_code=404, detail="incident not found")
        hits = session.scalars(
            select(RuleHit).where(RuleHit.incident_id == incident_id).order_by(RuleHit.window_end)
        ).all()
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
            "disclaimer": "Rule hits are risk indicators from Incident Shield's own heuristics, not proof of fraud.",
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
            "transactions": [_txn_out(t) for t in sorted(txns, key=lambda t: t.occurred_at)],
            "audit": [
                {"at": e.at.isoformat(), "actor": e.actor, "action": e.action, "details": e.details} for e in events
            ],
        }
