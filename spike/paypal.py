"""Minimal PayPal REST client for the spike.

- Caches the OAuth access token until shortly before it expires.
- Logs every call (status, timing, PayPal debug ID, response) to spike_logs/api_calls.jsonl.
- Never raises on HTTP error status: the spike's job is to record what PayPal does.
"""

from __future__ import annotations

import time
import uuid
from typing import Any

import httpx

from .config import AppCreds, Settings, assert_sandbox
from .logs import append_jsonl


def new_request_id() -> str:
    return str(uuid.uuid4())


def safe_json(response: httpx.Response) -> Any:
    try:
        return response.json()
    except ValueError:
        return {"_non_json_body": response.text[:2000]}


class PayPalClient:
    def __init__(self, settings: Settings, creds: AppCreds, timeout: float = 30.0) -> None:
        # Defence in depth: re-check the lock even though load_settings already did.
        self.base = assert_sandbox(settings.api_base)
        self.creds = creds
        self._token: str | None = None
        self._expires_at = 0.0
        self.last_token_info: dict[str, Any] = {}
        self._http = httpx.Client(timeout=timeout)

    def close(self) -> None:
        self._http.close()

    def invalidate_token(self) -> None:
        """Drop the cached token. A token's scopes are fixed when it's issued, so after a
        permission change (or a 401/403) only a fresh token can pick up the new scopes."""
        self._token = None
        self._expires_at = 0.0

    def token(self) -> str:
        if self._token and time.monotonic() < self._expires_at - 60:
            return self._token
        started = time.perf_counter()
        response = self._http.post(
            f"{self.base}/v1/oauth2/token",
            auth=(self.creds.client_id, self.creds.client_secret),
            data={"grant_type": "client_credentials"},
            headers={"Accept": "application/json"},
        )
        elapsed_ms = round((time.perf_counter() - started) * 1000, 1)
        body = safe_json(response)
        ok = response.status_code == 200 and isinstance(body, dict) and "access_token" in body
        info = {
            "app": self.creds.label,
            "status": response.status_code,
            "elapsed_ms": elapsed_ms,
            "app_id": body.get("app_id") if isinstance(body, dict) else None,
            "expires_in": body.get("expires_in") if isinstance(body, dict) else None,
            "scopes": (body.get("scope", "") or "").split() if isinstance(body, dict) else [],
        }
        append_jsonl("api_calls", {"kind": "oauth_token", **info, "error": None if ok else body})
        if not ok:
            raise RuntimeError(f"OAuth token request failed for {self.creds.label}: HTTP {response.status_code} {body}")
        self._token = body["access_token"]
        self._expires_at = time.monotonic() + int(body.get("expires_in", 0))
        self.last_token_info = info
        return self._token

    def request(
        self,
        method: str,
        path: str,
        *,
        json_body: Any = None,
        params: dict[str, Any] | None = None,
        request_id: str | None = None,
        content: bytes | None = None,
        content_type: str | None = None,
        files: dict[str, Any] | None = None,
    ) -> httpx.Response:
        headers = {"Authorization": f"Bearer {self.token()}", "Accept": "application/json"}
        if request_id:
            headers["PayPal-Request-Id"] = request_id
        if content_type:
            headers["Content-Type"] = content_type
        started = time.perf_counter()
        base_record = {
            "kind": "api",
            "app": self.creds.label,
            "method": method,
            "path": path,
            "params": params,
            "request_id": request_id,
            "request_body": json_body,
        }
        try:
            response = self._http.request(
                method,
                f"{self.base}{path}",
                json=json_body,
                params=params,
                headers=headers,
                content=content,
                files=files,
            )
        except httpx.HTTPError as exc:
            append_jsonl(
                "api_calls",
                {
                    **base_record,
                    "transport_error": repr(exc),
                    "elapsed_ms": round((time.perf_counter() - started) * 1000, 1),
                },
            )
            raise
        append_jsonl(
            "api_calls",
            {
                **base_record,
                "status": response.status_code,
                "elapsed_ms": round((time.perf_counter() - started) * 1000, 1),
                "debug_id": response.headers.get("paypal-debug-id"),
                "response": safe_json(response),
            },
        )
        return response
