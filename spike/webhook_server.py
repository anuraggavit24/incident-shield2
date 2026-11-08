"""Spike webhook receiver.

Run:  uvicorn spike.webhook_server:app --port 8000

For every delivery it records headers, the event, delivery delay, and the result
of PayPal's signature verification API, then answers PayPal the way the real
design will:
  verified          -> 200
  invalid signature -> 400 (never processed)
  verification call failed / no webhook ID -> 503 (PayPal should retry)
Set SPIKE_FORCE_503=1 to answer 503 to everything and observe PayPal's retry timing.
"""

from __future__ import annotations

import json
import os
import time
from typing import Any

from fastapi import FastAPI, Request
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import JSONResponse

from .config import load_settings, resolve_webhook_id
from .logs import append_jsonl, iso, parse_paypal_time, utcnow
from .paypal import PayPalClient, safe_json
from .signature import build_verify_body, missing_headers

MAX_BODY_BYTES = 64 * 1024

settings = load_settings()
client = PayPalClient(settings, settings.merchant)
app = FastAPI(title="Incident Shield - sandbox spike receiver")


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
    except Exception as exc:  # spike: record any failure of the verification call itself
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


@app.get("/health")
def health() -> dict[str, Any]:
    return {"status": "ok", "webhook_id_configured": bool(resolve_webhook_id())}


@app.post("/webhooks/paypal")
async def paypal_webhook(request: Request) -> JSONResponse:
    received_at = utcnow()
    headers = {k.lower(): v for k, v in request.headers.items()}
    base: dict[str, Any] = {
        "received_at": iso(received_at),
        "transmission_id": headers.get("paypal-transmission-id"),
        "transmission_time": headers.get("paypal-transmission-time"),
    }

    declared = headers.get("content-length", "")
    if declared.isdigit() and int(declared) > MAX_BODY_BYTES:
        append_jsonl("webhooks", {**base, "outcome": "rejected_too_large", "declared_bytes": int(declared)})
        return JSONResponse({"outcome": "rejected_too_large"}, status_code=413)

    raw = await request.body()
    base["size_bytes"] = len(raw)
    if len(raw) > MAX_BODY_BYTES:
        append_jsonl("webhooks", {**base, "outcome": "rejected_too_large"})
        return JSONResponse({"outcome": "rejected_too_large"}, status_code=413)

    try:
        event = json.loads(raw)
    except (json.JSONDecodeError, UnicodeDecodeError):
        append_jsonl("webhooks", {**base, "outcome": "rejected_bad_json"})
        return JSONResponse({"outcome": "rejected_bad_json"}, status_code=400)

    verification = await run_in_threadpool(verify, headers, raw)
    status = verification["status"]
    if os.getenv("SPIKE_FORCE_503", "").strip() == "1":
        http_status, outcome = 503, "forced_503"
    elif status == "SUCCESS":
        http_status, outcome = 200, "accepted"
    elif status == "FAILURE":
        http_status, outcome = 400, "rejected_invalid_signature"
    else:
        http_status, outcome = 503, "verification_unavailable"

    created = parse_paypal_time(event.get("create_time"))
    append_jsonl(
        "webhooks",
        {
            **base,
            "event_id": event.get("id"),
            "event_type": event.get("event_type"),
            "resource_type": event.get("resource_type"),
            "create_time": event.get("create_time"),
            "delivery_delay_s": round((received_at - created).total_seconds(), 1) if created else None,
            "verification": verification,
            "outcome": outcome,
            "http_status": http_status,
            "paypal_headers": {k: v for k, v in headers.items() if k.startswith("paypal-")},
            "event": event,
        },
    )
    return JSONResponse({"outcome": outcome}, status_code=http_status)
