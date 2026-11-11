"""scripts/warm_copilot.py against a fake API (no network, no database)."""

from __future__ import annotations

import json

import httpx

from scripts import warm_copilot


def run(monkeypatch, responder) -> tuple[int, list[dict]]:
    seen: list[dict] = []

    def handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        seen.append({"path": request.url.path, "key": request.headers.get("x-api-key"), **body})
        return responder(body)

    real_client = httpx.Client
    monkeypatch.setattr(warm_copilot.httpx, "Client", lambda **kw: real_client(transport=httpx.MockTransport(handler)))
    monkeypatch.setattr(warm_copilot, "PAUSE_S", 0)
    monkeypatch.setattr(warm_copilot.getpass, "getpass", lambda prompt: "raw-owner-key")
    monkeypatch.setattr(warm_copilot.sys, "argv", ["warm", "http://x/", "7"])
    return warm_copilot.main(), seen


def test_asks_every_intent_with_the_owner_key(monkeypatch) -> None:
    ok = {"cached": False, "ai_interpretation": {"status": "passed_checks", "model": "gemini-3.5-flash"}}
    code, seen = run(monkeypatch, lambda body: httpx.Response(200, json=ok))
    assert code == 0
    assert [s["intent"] for s in seen] == warm_copilot.INTENTS
    assert {s["path"] for s in seen} == {"/incidents/7/ask"} and {s["key"] for s in seen} == {"raw-owner-key"}


def test_rate_limited_answers_are_reported_as_not_cached(monkeypatch) -> None:
    limited = {"cached": False, "ai_interpretation": {"status": "unavailable", "reason": "Gemini HTTP 429"}}
    code, _ = run(monkeypatch, lambda body: httpx.Response(200, json=limited))
    assert code == 1
