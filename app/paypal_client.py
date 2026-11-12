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


def _reason(response: httpx.Response) -> str:
    """PayPal's own error name, issue and debug id, for the log. These describe the request, not the
    credentials: no token, secret or customer data is included."""
    try:
        body = response.json()
    except ValueError:
        return ""
    if not isinstance(body, dict):
        return ""
    parts = [str(body.get("name") or body.get("error") or "")]
    details = body.get("details")
    if isinstance(details, list) and details and isinstance(details[0], dict):
        parts.append(str(details[0].get("issue") or ""))
        parts.append(str(details[0].get("field") or ""))
    parts.append(str(body.get("error_description") or ""))
    if body.get("debug_id"):
        parts.append(f"debug_id {body['debug_id']}")
    text = ", ".join(p for p in parts if p)
    return f" ({text[:160]})" if text else ""


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
                raise PayPalError(f"OAuth token request failed: HTTP {response.status_code}{_reason(response)}")
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

    def _post(self, path: str, body: dict[str, Any], request_id: str) -> dict[str, Any]:
        """POST JSON. `request_id` makes the call idempotent: PayPal returns the first result for a repeat."""
        response = self._http.post(
            f"{self.base}{path}",
            json=body,
            headers={
                "Authorization": f"Bearer {self._token_value()}",
                "Content-Type": "application/json",
                "Accept": "application/json",
                "PayPal-Request-Id": request_id,
            },
        )
        if response.status_code not in (200, 201):
            raise PayPalError(f"POST {path} failed: HTTP {response.status_code}{_reason(response)}")
        return response.json()

    def create_order(
        self, amount: str, currency: str, custom_id: str, return_url: str, cancel_url: str, request_id: str
    ) -> dict[str, Any]:
        """Create a CAPTURE order and return {"id", "status", "approve_url"}. The buyer approves it at PayPal."""
        body = {
            "intent": "CAPTURE",
            "purchase_units": [
                {
                    "custom_id": custom_id,
                    "amount": {"currency_code": currency, "value": amount},
                    "description": "Incident Shield demo payment",
                }
            ],
            "payment_source": {
                "paypal": {
                    "experience_context": {
                        "return_url": return_url,
                        "cancel_url": cancel_url,
                        "user_action": "PAY_NOW",
                        "shipping_preference": "NO_SHIPPING",
                    }
                }
            },
        }
        order = self._post("/v2/checkout/orders", body, request_id)
        links = {link.get("rel"): link.get("href") for link in order.get("links", []) if isinstance(link, dict)}
        approve = links.get("payer-action") or links.get("approve")
        if not approve or not str(approve).startswith("https://"):
            raise PayPalError("order has no approval link")
        return {"id": str(order["id"]), "status": str(order.get("status", "")), "approve_url": str(approve)}

    def capture_order(self, order_id: str, request_id: str) -> dict[str, Any]:
        """Capture an approved order. Returns {"status", "capture_id", "amount", "currency"}."""
        if not order_id.replace("-", "").isalnum():
            raise PayPalError("invalid order id")
        body = self._post(f"/v2/checkout/orders/{order_id}/capture", {}, request_id)
        units = body.get("purchase_units") or [{}]
        captures = ((units[0].get("payments") or {}).get("captures")) or [{}]
        first = captures[0]
        amount = first.get("amount") or {}
        return {
            "status": str(first.get("status") or body.get("status") or ""),
            "capture_id": str(first.get("id") or ""),
            "amount": str(amount.get("value", "")),
            "currency": str(amount.get("currency_code", "")),
        }

    def refund_capture(self, capture_id: str, amount: str, currency: str, note: str, request_id: str) -> dict[str, Any]:
        """Refund a captured payment to the original payer (PayPal only refunds to the original source)."""
        if not capture_id.replace("-", "").isalnum():
            raise PayPalError("invalid capture id")
        body = {"amount": {"value": amount, "currency_code": currency}, "note_to_payer": note[:255]}
        result = self._post(f"/v2/payments/captures/{capture_id}/refund", body, request_id)
        return {"id": str(result.get("id", "")), "status": str(result.get("status", ""))}

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
