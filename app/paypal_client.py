"""PayPal REST client for the application (sandbox only)."""

from __future__ import annotations

import threading
import time
from typing import Any

import httpx

from .config import Settings, assert_sandbox
from .signature import build_verify_body, missing_headers


class PayPalError(RuntimeError):
    pass


class PayPalClient:
    def __init__(self, settings: Settings, timeout: float = 8.0, transport: httpx.BaseTransport | None = None):
        self.base = assert_sandbox(settings.paypal_api_base)
        self._id = settings.paypal_client_id
        self._secret = settings.paypal_client_secret
        self.webhook_id = settings.paypal_webhook_id
        self._http = httpx.Client(timeout=timeout, transport=transport)
        self._token: str | None = None
        self._expires_at = 0.0
        self._lock = threading.Lock()

    def close(self) -> None:
        self._http.close()

    def _token_value(self) -> str:
        with self._lock:
            if self._token and time.monotonic() < self._expires_at - 60:
                return self._token
            response = self._http.post(
                f"{self.base}/v1/oauth2/token",
                auth=(self._id, self._secret),
                data={"grant_type": "client_credentials"},
                headers={"Accept": "application/json"},
            )
            if response.status_code != 200:
                raise PayPalError(f"OAuth token request failed: HTTP {response.status_code}")
            body = response.json()
            self._token = body["access_token"]
            self._expires_at = time.monotonic() + int(body.get("expires_in", 0))
            return self._token

    def _get(self, path: str) -> dict[str, Any]:
        response = self._http.get(
            f"{self.base}{path}",
            headers={"Authorization": f"Bearer {self._token_value()}", "Accept": "application/json"},
        )
        if response.status_code != 200:
            raise PayPalError(f"GET {path} failed: HTTP {response.status_code}")
        return response.json()

    def verify_webhook(self, headers: dict[str, str], raw: bytes) -> str:
        """Return PayPal's verification_status ('SUCCESS' / 'FAILURE').

        Raises PayPalError if the check itself couldn't be done (caller answers 503 so PayPal retries).
        """
        if missing_headers(headers):
            return "FAILURE"
        try:
            body = build_verify_body(headers, raw, self.webhook_id)
        except ValueError:  # not UTF-8
            return "FAILURE"
        response = self._http.post(
            f"{self.base}/v1/notifications/verify-webhook-signature",
            content=body,
            headers={
                "Authorization": f"Bearer {self._token_value()}",
                "Content-Type": "application/json",
                "Accept": "application/json",
            },
        )
        if response.status_code != 200:
            raise PayPalError(f"verify-webhook-signature failed: HTTP {response.status_code}")
        return str(response.json().get("verification_status", "FAILURE"))

    def get_order(self, order_id: str) -> dict[str, Any]:
        if not order_id.replace("-", "").isalnum():
            raise PayPalError("invalid order id")
        return self._get(f"/v2/checkout/orders/{order_id}")
