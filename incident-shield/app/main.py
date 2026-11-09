"""Incident Shield API.

Run locally:  uvicorn app.main:app --port 8000
"""

from __future__ import annotations

import asyncio
import hmac
import json
import logging
import re
import threading
import time
from collections import deque
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any, Literal
from urllib.parse import urlparse

from fastapi import BackgroundTasks, Depends, FastAPI, HTTPException, Query, Request, Security
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import JSONResponse, RedirectResponse
from fastapi.security import APIKeyHeader
from pydantic import BaseModel, Field
from sqlalchemy import select, text
from sqlalchemy.exc import IntegrityError

from . import db
from .config import get_settings, hash_api_key
from .copilot import INTENTS, GeminiLLM
from .copilot import answer as copilot_answer
from .models import Incident, Transaction, WebhookEvent
from .normalize import parse_time
from .paypal_client import PayPalClient, PayPalError
from .policy import snapshot
from .processing import process_pending
from .views import incident_record, txn_out

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
log = logging.getLogger("incident_shield")

MAX_BODY_BYTES = 64 * 1024
PAYPAL_CERT_HOSTS = frozenset(
    {"api.paypal.com", "api.sandbox.paypal.com", "api-m.paypal.com", "api-m.sandbox.paypal.com"}
)
_TRANSMISSION_ID = re.compile(r"^[0-9A-Za-z-]{8,64}$")
_SIG = re.compile(r"^[A-Za-z0-9+/=]{16,1024}$")


def header_problem(headers: dict[str, str]) -> str | None:
    """Cheap local checks BEFORE calling PayPal, so junk requests can't make us spend a verify call.
    Real PayPal deliveries always pass these; passing them proves nothing (PayPal still verifies)."""
    if headers.get("paypal-auth-algo") != "SHA256withRSA":
        return "auth algorithm"
    cert = urlparse(headers.get("paypal-cert-url", ""))
    if (
        cert.scheme != "https"
        or cert.hostname not in PAYPAL_CERT_HOSTS
        or not cert.path.startswith("/v1/notifications/certs/")
    ):
        return "certificate URL"
    if not _TRANSMISSION_ID.fullmatch(headers.get("paypal-transmission-id", "")):
        return "transmission id"
    if not _SIG.fullmatch(headers.get("paypal-transmission-sig", "")):
        return "signature format"
    if parse_time(headers.get("paypal-transmission-time")) is None:
        return "transmission time"
    return None


class RateLimiter:
    """Sliding one-minute window over ALL webhook requests. Global, not per IP: behind a tunnel or
    Render's proxy every request shares one source address, and forwarded-for headers can be forged.
    Over the limit we answer 429; PayPal retries non-2xx deliveries for up to 3 days."""

    def __init__(self, per_minute: int) -> None:
        self.per_minute = per_minute
        self._hits: deque[float] = deque()
        self._lock = threading.Lock()

    def allow(self) -> bool:
        now = time.monotonic()
        with self._lock:
            while self._hits and now - self._hits[0] > 60:
                self._hits.popleft()
            if len(self._hits) >= self.per_minute:
                return False
            self._hits.append(now)
            return True


def payee_merchant_id(event: dict[str, Any]) -> str | None:
    resource = event.get("resource") if isinstance(event.get("resource"), dict) else {}
    payee = resource.get("payee") or {}
    if not payee:
        units = resource.get("purchase_units") or []
        payee = (units[0].get("payee") or {}) if units and isinstance(units[0], dict) else {}
    value = payee.get("merchant_id") if isinstance(payee, dict) else None
    return str(value) if value else None


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
    snapshot()  # fail at startup if the policy snapshot was tampered with
    db.init_engine(settings.database_url)
    app.state.paypal = PayPalClient(settings)
    app.state.llm = GeminiLLM(settings.gemini_api_key, settings.gemini_model) if settings.gemini_api_key else None
    app.state.webhook_limiter = RateLimiter(settings.webhook_rate_per_minute)
    app.state.verify_slots = threading.BoundedSemaphore(settings.verify_concurrency)
    if not settings.paypal_merchant_id:
        log.warning("PAYPAL_MERCHANT_ID not set: events for other merchants won't be quarantined")
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


api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False, description="Owner API key (not the hash)")


def require_owner(x_api_key: str | None = Security(api_key_header)) -> None:
    expected = get_settings().owner_api_key_sha256
    if not x_api_key or not hmac.compare_digest(hash_api_key(x_api_key), expected):
        raise HTTPException(status_code=401, detail="invalid API key")


@app.get("/", include_in_schema=False)
def root() -> RedirectResponse:
    return RedirectResponse("/docs")


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
    """Rate limit -> size cap -> header checks -> verify with PayPal -> persist -> acknowledge -> process later.

    200: stored (or already stored: duplicates are harmless), or quarantined (another merchant's event)
    400: bad body, malformed PayPal headers, or invalid signature (never stored)
    413: body over 64 KB
    429: too many webhook requests this minute -> PayPal retries
    503: verification or database unavailable, or too many verifications in flight -> PayPal retries
    """
    if not request.app.state.webhook_limiter.allow():
        return JSONResponse({"outcome": "rate_limited"}, status_code=429)
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
    problem = header_problem(headers)
    if problem is not None:
        return JSONResponse({"outcome": "bad_headers", "detail": problem}, status_code=400)
    slots = request.app.state.verify_slots
    if not slots.acquire(blocking=False):
        return JSONResponse({"outcome": "busy"}, status_code=503)
    try:
        status = await run_in_threadpool(request.app.state.paypal.verify_webhook, headers, raw)
    except (PayPalError, Exception):  # noqa: BLE001 - any failure to verify means "try again later"
        log.warning("webhook verification unavailable", exc_info=True)
        return JSONResponse({"outcome": "verification_unavailable"}, status_code=503)
    finally:
        slots.release()
    if status != "SUCCESS":
        return JSONResponse({"outcome": "invalid_signature"}, status_code=400)

    resource = event.get("resource") if isinstance(event.get("resource"), dict) else {}
    expected_merchant = get_settings().paypal_merchant_id
    payee = payee_merchant_id(event)
    # A valid signature proves PayPal sent it, not that it's about OUR account: park mismatches.
    quarantined = bool(expected_merchant and payee and payee != expected_merchant)
    row = WebhookEvent(
        event_id=event["id"][:128],
        event_type=str(event.get("event_type", ""))[:128],
        resource_id=str(resource.get("id") or resource.get("transaction_id") or "")[:128] or None,
        event_created_at=parse_time(event.get("create_time")),
        payload=event,
        status="quarantined" if quarantined else "pending",
        last_error=f"payee merchant {payee} is not {expected_merchant}" if quarantined else None,
    )
    try:
        with db.session_scope() as session:
            session.add(row)
    except IntegrityError:
        return JSONResponse({"outcome": "duplicate"}, status_code=200)
    except Exception:  # noqa: BLE001 - e.g. database cold start or outage
        log.warning("could not store webhook event", exc_info=True)
        return JSONResponse({"outcome": "storage_unavailable"}, status_code=503)

    if quarantined:
        log.warning("quarantined webhook %s for merchant %s", row.event_id, payee)
        return JSONResponse({"outcome": "quarantined"}, status_code=200)
    background.add_task(process_pending, request.app.state.paypal.get_order)
    return JSONResponse({"outcome": "accepted"}, status_code=200)


@app.get("/webhook-events", dependencies=[Depends(require_owner)])
def list_webhook_events(
    status: Literal["pending", "processed", "ignored", "failed", "quarantined"] | None = None,
    limit: int = Query(50, ge=1, le=500),
) -> list[dict[str, Any]]:
    """Stored (verified) deliveries, e.g. ?status=quarantined or ?status=failed."""
    with db.session_scope() as session:
        query = select(WebhookEvent).order_by(WebhookEvent.id.desc()).limit(limit)
        if status:
            query = query.where(WebhookEvent.status == status)
        return [
            {
                "event_id": e.event_id,
                "event_type": e.event_type,
                "resource_id": e.resource_id,
                "status": e.status,
                "attempts": e.attempts,
                "last_error": e.last_error,
                "received_at": e.received_at.isoformat() if e.received_at else None,
            }
            for e in session.scalars(query).all()
        ]


# --------------------------------------------------------------------------- read API (owner)


@app.get("/transactions", dependencies=[Depends(require_owner)])
def list_transactions(limit: int = Query(100, ge=1, le=500)) -> list[dict[str, Any]]:
    with db.session_scope() as session:
        rows = session.scalars(select(Transaction).order_by(Transaction.occurred_at.desc()).limit(limit)).all()
        return [txn_out(t) for t in rows]


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
        record = incident_record(session, incident_id)
    if record is None:
        raise HTTPException(status_code=404, detail="incident not found")
    return record


# --------------------------------------------------------------------------- Copilot


class AskRequest(BaseModel):
    intent: Literal["why_flagged", "what_first", "evidence", "rule_meaning", "is_confirmed"] | None = Field(
        default=None, description="Pick a suggested question. Takes priority over free text."
    )
    question: str | None = Field(default=None, max_length=500, description="Free text. Untrusted.")


@app.get("/copilot/questions")
def copilot_questions() -> list[dict[str, str]]:
    return [{"intent": k, "question": v} for k, v in INTENTS.items()]


@app.post("/incidents/{incident_id}/ask", dependencies=[Depends(require_owner)])
def ask(incident_id: int, body: AskRequest, request: Request) -> dict[str, Any]:
    if body.intent is None and not (body.question or "").strip():
        raise HTTPException(status_code=422, detail="give an intent or a question")
    settings = get_settings()
    with db.session_scope() as session:
        record = incident_record(session, incident_id)
        if record is None:
            raise HTTPException(status_code=404, detail="incident not found")
        return copilot_answer(
            session,
            record,
            question=body.question,
            intent=body.intent,
            llm=request.app.state.llm,
            scope="owner",
            daily_budget=settings.copilot_daily_budget,
        )
