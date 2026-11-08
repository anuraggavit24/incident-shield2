"""Spike webhook receiver.

Run:  uvicorn spike.webhook_server:app --port 8000

For every delivery it measures total handler time, enforces a streaming body cap,
asks PayPal's verification API about the signature, and answers PayPal the way
the real design will:
  verified                                 -> 200
  invalid signature                        -> 400 (never processed)
  verification call failed / no webhook ID -> 503 (PayPal should retry)
Set SPIKE_FORCE_503=1 to answer 503 to everything and observe PayPal's retries.

Only VERIFIED events are logged in full. Anything else is logged as metadata
(size, hash, claimed type), so a forged request can't pollute the spike's
answers. The tunnel URL is public.
"""

from __future__ import annotations

import hashlib
import json
import os
import time
from typing import Any

import httpx
from fastapi import FastAPI, Request
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import JSONResponse

from . import logs
from .config import load_settings, resolve_webhook_id
from .logs import append_jsonl, iso, parse_paypal_time, utcnow
from .paypal import PayPalClient, safe_json
from .signature import build_verify_body, missing_headers

MAX_BODY_BYTES = 64 * 1024
VERIFY_TIMEOUT_S = 8.0
# Stop logging unverified-request metadata once the log is this big (disk-fill guard).
MAX_UNVERIFIED_LOG_BYTES = 20 * 1024 * 1024

settings = load_settings()
client = PayPalClient(settings, settings.merchant, timeout=VERIFY_TIMEOUT_S)
app = FastAPI(title="Incident Shield - sandbox spike receiver")


class BodyTooLarge(Exception):
    pass


async def read_capped(request: Request, limit: int) -> bytes:
    """Read the body chunk by chunk and stop as soon as it exceeds `limit`.

    Checking Content-Length alone is not enough: a chunked request has no such header.
    """
    received = bytearray()
    async for chunk in request.stream():
        received.extend(chunk)
        if len(received) > limit:
            raise BodyTooLarge
    return bytes(received)


def verify(headers: dict[str, str], raw: bytes) -> dict[str, Any]:
    webhook_id = resolve_webhook_id()
    if not webhook_id:
        return {"status": "NO_WEBHOOK_ID"}
    missing = missing_headers(headers)
    if missing:
        return {"status": "MISSING_HEADERS", "missing": missing}
    started = time.perf_counter()
    try:
        response = client.request(
            "POST",
            "/v1/notifications/verify-webhook-signature",
            content=build_verify_body(headers, raw, webhook_id),
            content_type="application/json",
        )
    except (httpx.HTTPError, RuntimeError) as exc:  # transport failure or token failure
        return {
            "status": "VERIFY_CALL_ERROR",
            "error": repr(exc),
            "elapsed_ms": round((time.perf_counter() - started) * 1000, 1),
        }
    elapsed_ms = round((time.perf_counter() - started) * 1000, 1)
    body = safe_json(response)
    if response.status_code != 200 or not isinstance(body, dict):
        return {
            "status": "VERIFY_HTTP_ERROR",
            "http_status": response.status_code,
            "debug_id": response.headers.get("paypal-debug-id"),
            "elapsed_ms": elapsed_ms,
        }
    return {"status": body.get("verification_status", "UNKNOWN"), "elapsed_ms": elapsed_ms}


def _unverified_log_has_room() -> bool:
    path = logs.LOG_DIR / "webhooks.jsonl"
    return not path.exists() or path.stat().st_size < MAX_UNVERIFIED_LOG_BYTES


def _log(record: dict[str, Any], *, verified: bool) -> None:
    if verified or _unverified_log_has_room():
        append_jsonl("webhooks", record)


@app.get("/health")
def health() -> dict[str, Any]:
    return {"status": "ok", "webhook_id_configured": bool(resolve_webhook_id())}


@app.post("/webhooks/paypal")
async def paypal_webhook(request: Request) -> JSONResponse:
    started = time.perf_counter()
    received_at = utcnow()
    headers = {k.lower(): v for k, v in request.headers.items()}
    base: dict[str, Any] = {
        "received_at": iso(received_at),
        "transmission_id": headers.get("paypal-transmission-id"),
        "transmission_time": headers.get("paypal-transmission-time"),
    }

    def done(outcome: str, http_status: int, record: dict[str, Any], *, verified: bool) -> JSONResponse:
        record = {
            **base,
            **record,
            "outcome": outcome,
            "http_status": http_status,
            "handler_ms": round((time.perf_counter() - started) * 1000, 1),
        }
        _log(record, verified=verified)
        return JSONResponse({"outcome": outcome}, status_code=http_status)

    declared = headers.get("content-length", "")
    if declared.isdigit() and int(declared) > MAX_BODY_BYTES:
        return done("rejected_too_large", 413, {"declared_bytes": int(declared)}, verified=False)
    try:
        raw = await read_capped(request, MAX_BODY_BYTES)
    except BodyTooLarge:
        return done("rejected_too_large", 413, {"declared_bytes": declared or None}, verified=False)

    meta = {"size_bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}
    try:
        event = json.loads(raw)
        if not isinstance(event, dict):
            raise ValueError("event is not a JSON object")
    except (ValueError, UnicodeDecodeError):
        return done("rejected_bad_json", 400, meta, verified=False)

    claimed = {"claimed_event_id": event.get("id"), "claimed_event_type": event.get("event_type")}
    verification = await run_in_threadpool(verify, headers, raw)
    status = verification["status"]
    is_verified = status == "SUCCESS"

    if os.getenv("SPIKE_FORCE_503", "").strip() == "1":
        outcome, http_status = "forced_503", 503
    elif is_verified:
        outcome, http_status = "accepted", 200
    elif status == "FAILURE":
        outcome, http_status = "rejected_invalid_signature", 400
    else:
        outcome, http_status = "verification_unavailable", 503

    if not is_verified:
        return done(outcome, http_status, {**meta, **claimed, "verification": verification}, verified=False)

    created = parse_paypal_time(event.get("create_time"))
    return done(
        outcome,
        http_status,
        {
            **meta,
            "verified": True,
            "event_id": event.get("id"),
            "event_type": event.get("event_type"),
            "resource_type": event.get("resource_type"),
            "create_time": event.get("create_time"),
            "delivery_delay_s": round((received_at - created).total_seconds(), 1) if created else None,
            "verification": verification,
            "paypal_headers": {k: v for k, v in headers.items() if k.startswith("paypal-")},
            "event": event,
        },
        verified=True,
    )
