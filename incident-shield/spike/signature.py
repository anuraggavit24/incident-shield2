"""Building the request body for PayPal's verify-webhook-signature API.

Kept free of side effects so it can be unit-tested without credentials.
"""

from __future__ import annotations

import json

# PayPal delivery header -> field name expected by /v1/notifications/verify-webhook-signature
HEADER_MAP = {
    "paypal-auth-algo": "auth_algo",
    "paypal-cert-url": "cert_url",
    "paypal-transmission-id": "transmission_id",
    "paypal-transmission-sig": "transmission_sig",
    "paypal-transmission-time": "transmission_time",
}


def missing_headers(headers: dict[str, str]) -> list[str]:
    return [h for h in HEADER_MAP if h not in headers]


def build_verify_body(headers: dict[str, str], raw: bytes, webhook_id: str) -> bytes:
    """Splice the raw event bytes in unchanged.

    Re-serialising the parsed event can reorder keys or change number formatting,
    which can make verification fail even for genuine events.
    `headers` must use lower-case keys.
    """
    fields = {body_key: headers[header] for header, body_key in HEADER_MAP.items()}
    fields["webhook_id"] = webhook_id
    prefix = json.dumps(fields)
    return (prefix[:-1] + ',"webhook_event":' + raw.decode("utf-8") + "}").encode("utf-8")
