"""Incident Shield sandbox spike CLI.

Run from the repo root:  python -m spike.run_spike <command> --help

Every command logs raw PayPal requests/responses to spike_logs/. The goal is to
record what the sandbox actually does, not to be a product.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import statistics
import sys
import time
from collections import Counter, defaultdict
from collections.abc import Callable, Iterator
from datetime import datetime, timedelta
from decimal import Decimal, InvalidOperation
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import httpx

from .config import LOG_DIR, WEBHOOK_ID_FILE, ConfigError, Settings, load_settings
from .logs import append_jsonl, iso, parse_paypal_time, read_jsonl, utcnow
from .paypal import PayPalClient, new_request_id, safe_json

# Keys whose location inside webhook / API payloads the spike needs to learn.
INTERESTING_KEYS = frozenset(
    {
        "merchant_id",
        "payee",
        "payer",
        "payer_id",
        "email_address",
        "custom_id",
        "invoice_id",
        "description",
        "note",
        "note_to_payer",
        "transaction_note",
        "sender_batch_id",
        "sender_item_id",
        "reason",
        "dispute_reason",
        "disputed_transactions",
        "seller_transaction_id",
        "buyer_transaction_id",
        "currency_code",
    }
)
SCOPE_HINTS = ("dispute", "payout", "reporting", "checkout", "payments", "webhook")

# Clearly fictional names for synthetic senders.
SYNTHETIC_SENDERS = [
    "Test Sender Alpha",
    "Test Sender Bravo",
    "Test Sender Charlie",
    "Test Sender Delta",
    "Test Sender Echo",
]
BURST_AMOUNTS = ["60.00", "136.43", "62.68", "90.73", "187.19"]


# --------------------------------------------------------------------------- helpers


def money(value: str) -> str:
    try:
        amount = Decimal(value)
    except InvalidOperation as exc:
        raise argparse.ArgumentTypeError(f"not a valid amount: {value!r}") from exc
    if amount <= 0:
        raise argparse.ArgumentTypeError("amount must be positive")
    return str(amount.quantize(Decimal("0.01")))


def currency(value: str) -> str:
    value = value.strip().upper()
    if len(value) != 3 or not value.isalpha():
        raise argparse.ArgumentTypeError(f"not an ISO currency code: {value!r}")
    return value


_ID_PATTERN = re.compile(r"^[A-Za-z0-9-]{1,64}$")


def paypal_id(value: str) -> str:
    """IDs end up in URL paths and file names, so only allow PayPal's ID alphabet."""
    if not _ID_PATTERN.fullmatch(value):
        raise argparse.ArgumentTypeError(f"not a valid PayPal ID: {value!r}")
    return value


def client_for(settings: Settings, app: str) -> PayPalClient:
    if app == "merchant":
        return PayPalClient(settings, settings.merchant)
    if settings.sender is None:
        raise ConfigError("SENDER_CLIENT_ID / SENDER_CLIENT_SECRET are not set in .env")
    return PayPalClient(settings, settings.sender)


def show(response: Any) -> Any:
    body = safe_json(response)
    print(f"HTTP {response.status_code}  debug_id={response.headers.get('paypal-debug-id')}")
    print(json.dumps(body, indent=2)[:6000])
    return body


def record_created(kind: str, **fields: Any) -> None:
    append_jsonl("created", {"kind": kind, "created_at": iso(utcnow()), **fields})


def finding(topic: str, **fields: Any) -> None:
    append_jsonl("findings", {"topic": topic, **fields})


def find_paths(obj: Any, prefix: str = "") -> Iterator[tuple[str, str]]:
    """Yield (json_path, short_value) for interesting keys anywhere in a payload."""
    if isinstance(obj, dict):
        for key, value in obj.items():
            path = f"{prefix}.{key}" if prefix else key
            if key in INTERESTING_KEYS:
                preview = json.dumps(value, default=str)
                yield path, (preview[:80] + "...") if len(preview) > 80 else preview
            yield from find_paths(value, path)
    elif isinstance(obj, list):
        for index, item in enumerate(obj):
            yield from find_paths(item, f"{prefix}[{index}]")


def capture_ids(order: Any) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    if not isinstance(order, dict):
        return out
    for unit in order.get("purchase_units", []) or []:
        for cap in (unit.get("payments") or {}).get("captures") or []:
            out.append({"capture_id": cap.get("id"), "status": cap.get("status")})
    return out


def capture_order(client: PayPalClient, order_id: str) -> Any:
    response = client.request(
        "POST", f"/v2/checkout/orders/{order_id}/capture", json_body={}, request_id=new_request_id()
    )
    return show(response)


# --------------------------------------------------------------------------- commands


def cmd_token(settings: Settings, args: argparse.Namespace) -> None:
    client = client_for(settings, args.app)
    client.token()
    info = client.last_token_info
    print(
        f"app={args.app} app_id={info.get('app_id')} expires_in={info.get('expires_in')}s "
        f"scopes={len(info.get('scopes', []))}"
    )
    relevant = [s for s in info.get("scopes", []) if any(h in s.lower() for h in SCOPE_HINTS)]
    for scope in relevant:
        print(f"  {scope}")
    finding("oauth_scopes", app=args.app, app_id=info.get("app_id"), relevant_scopes=relevant)


def cmd_webhooks_list(settings: Settings, args: argparse.Namespace) -> None:
    body = show(client_for(settings, "merchant").request("GET", "/v1/notifications/webhooks"))
    for hook in body.get("webhooks", []) if isinstance(body, dict) else []:
        print(f"  {hook.get('id')}  {hook.get('url')}  events={len(hook.get('event_types', []))}")


def cmd_webhook_register(settings: Settings, args: argparse.Namespace) -> None:
    if not args.url.startswith("https://"):
        raise ConfigError("PayPal only delivers webhooks to https URLs")
    client = client_for(settings, "merchant")
    if args.replace:
        listing = safe_json(client.request("GET", "/v1/notifications/webhooks"))
        for hook in listing.get("webhooks", []) if isinstance(listing, dict) else []:
            response = client.request("DELETE", f"/v1/notifications/webhooks/{hook['id']}")
            print(f"deleted {hook['id']} ({hook.get('url')}): HTTP {response.status_code}")
    body = show(
        client.request(
            "POST", "/v1/notifications/webhooks", json_body={"url": args.url, "event_types": [{"name": "*"}]}
        )
    )
    webhook_id = body.get("id") if isinstance(body, dict) else None
    if webhook_id:
        LOG_DIR.mkdir(parents=True, exist_ok=True)
        WEBHOOK_ID_FILE.write_text(webhook_id, encoding="utf-8")
        print(f"\nRegistered webhook {webhook_id}. The receiver picks it up automatically (no restart needed).")
        finding("webhook_registered", webhook_id=webhook_id, url=args.url)


def cmd_webhook_delete(settings: Settings, args: argparse.Namespace) -> None:
    show(client_for(settings, "merchant").request("DELETE", f"/v1/notifications/webhooks/{args.id}"))


def _card_payment(
    client: PayPalClient, amount: str, cur: str, name: str, custom_id: str | None, description: str | None
) -> None:
    number = os.getenv("SANDBOX_CARD_NUMBER", "").strip()
    expiry = os.getenv("SANDBOX_CARD_EXPIRY", "").strip()
    if not number or not expiry:
        raise ConfigError("Set SANDBOX_CARD_NUMBER and SANDBOX_CARD_EXPIRY (YYYY-MM) from the sandbox card generator")
    card: dict[str, Any] = {"number": number, "expiry": expiry, "name": name}
    cvv = os.getenv("SANDBOX_CARD_CVV", "").strip()
    if cvv:
        card["security_code"] = cvv
    unit: dict[str, Any] = {"amount": {"currency_code": cur, "value": amount}}
    if custom_id:
        unit["custom_id"] = custom_id
    if description:
        unit["description"] = description
    print(f"--- card payment {amount} {cur} from {name!r}")
    order = show(
        client.request(
            "POST",
            "/v2/checkout/orders",
            json_body={"intent": "CAPTURE", "purchase_units": [unit], "payment_source": {"card": card}},
            request_id=new_request_id(),
        )
    )
    order_id = order.get("id") if isinstance(order, dict) else None
    status = order.get("status") if isinstance(order, dict) else None
    if order_id and status != "COMPLETED":
        print(f"order {order_id} status={status}; capturing")
        order = capture_order(client, order_id)
    caps = capture_ids(order)
    record_created(
        "card_payment",
        order_id=order_id,
        captures=caps,
        amount=amount,
        currency=cur,
        sender_name=name,
        custom_id=custom_id,
    )
    finding("card_payment_result", order_id=order_id, initial_status=status, captures=caps)


def cmd_pay_card(settings: Settings, args: argparse.Namespace) -> None:
    _card_payment(
        client_for(settings, "merchant"), args.amount, args.currency, args.name, args.custom_id, args.description
    )


def cmd_burst(settings: Settings, args: argparse.Namespace) -> None:
    client = client_for(settings, "merchant")
    currencies = [currency(c) for c in args.currencies.split(",") if c.strip()]
    for i in range(args.count):
        _card_payment(
            client,
            BURST_AMOUNTS[i % len(BURST_AMOUNTS)],
            currencies[i % len(currencies)],
            SYNTHETIC_SENDERS[i % len(SYNTHETIC_SENDERS)],
            args.custom_id,
            None,
        )
        if i < args.count - 1:
            time.sleep(args.gap)


def cmd_pay_wallet(settings: Settings, args: argparse.Namespace) -> None:
    unit: dict[str, Any] = {"amount": {"currency_code": args.currency, "value": args.amount}}
    if args.custom_id:
        unit["custom_id"] = args.custom_id
    body = show(
        client_for(settings, "merchant").request(
            "POST",
            "/v2/checkout/orders",
            json_body={
                "intent": "CAPTURE",
                "purchase_units": [unit],
                "payment_source": {
                    "paypal": {
                        "experience_context": {
                            "return_url": "https://example.com/return",
                            "cancel_url": "https://example.com/cancel",
                            "user_action": "PAY_NOW",
                        }
                    }
                },
            },
            request_id=new_request_id(),
        )
    )
    order_id = body.get("id") if isinstance(body, dict) else None
    links = {link.get("rel"): link.get("href") for link in (body.get("links", []) if isinstance(body, dict) else [])}
    approve = links.get("payer-action") or links.get("approve")
    record_created(
        "wallet_order", order_id=order_id, amount=args.amount, currency=args.currency, custom_id=args.custom_id
    )
    print(f"\n1) Open this link and log in as a sandbox PERSONAL buyer account:\n   {approve}")
    print(f"2) After approving, run:  python -m spike.run_spike capture --order-id {order_id}")


def cmd_capture(settings: Settings, args: argparse.Namespace) -> None:
    order = capture_order(client_for(settings, "merchant"), args.order_id)
    caps = capture_ids(order)
    record_created("wallet_capture", order_id=args.order_id, captures=caps)


def cmd_payout(settings: Settings, args: argparse.Namespace) -> None:
    sender_batch_id = new_request_id()
    item: dict[str, Any] = {
        "recipient_type": "EMAIL",
        "amount": {"value": args.amount, "currency": args.currency},
        "receiver": args.to,
        "sender_item_id": new_request_id(),
    }
    if args.note:
        item["note"] = args.note
    body = show(
        client_for(settings, args.app).request(
            "POST",
            "/v1/payments/payouts",
            json_body={
                "sender_batch_header": {
                    "sender_batch_id": sender_batch_id,
                    "email_subject": "Spike payout",
                    "email_message": "Incident Shield sandbox spike",
                },
                "items": [item],
            },
        )
    )
    batch_id = ((body.get("batch_header") or {}).get("payout_batch_id")) if isinstance(body, dict) else None
    record_created(
        "payout",
        app=args.app,
        payout_batch_id=batch_id,
        sender_batch_id=sender_batch_id,
        receiver=args.to,
        amount=args.amount,
        currency=args.currency,
        has_note=bool(args.note),
    )
    print(
        f"\nCheck item status in ~30s:  python -m spike.run_spike payout-status --app {args.app} --batch-id {batch_id}"
    )


def cmd_payout_status(settings: Settings, args: argparse.Namespace) -> None:
    body = show(client_for(settings, args.app).request("GET", f"/v1/payments/payouts/{args.batch_id}"))
    items = body.get("items", []) if isinstance(body, dict) else []
    tx_ids = []
    for item in items:
        print(
            f"  item={item.get('payout_item_id')} tx={item.get('transaction_id')} "
            f"status={item.get('transaction_status')}"
        )
        if item.get("transaction_id"):
            tx_ids.append(item["transaction_id"])
    if tx_ids:
        record_created("payout_items", app=args.app, payout_batch_id=args.batch_id, transaction_ids=tx_ids)


def cmd_disputes_list(settings: Settings, args: argparse.Namespace) -> None:
    body = show(client_for(settings, "merchant").request("GET", "/v1/customer/disputes", params={"page_size": 50}))
    for d in body.get("items", []) if isinstance(body, dict) else []:
        amount = d.get("dispute_amount") or {}
        print(
            f"  {d.get('dispute_id')}  reason={d.get('reason')}  status={d.get('status')}  "
            f"{amount.get('value')} {amount.get('currency_code')}  created={d.get('create_time')}"
        )


def cmd_dispute_show(settings: Settings, args: argparse.Namespace) -> None:
    response = client_for(settings, "merchant").request("GET", f"/v1/customer/disputes/{args.id}")
    body = safe_json(response)
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    (LOG_DIR / f"dispute_{args.id}.json").write_text(json.dumps(body, indent=2), encoding="utf-8")
    print(f"HTTP {response.status_code}. Full body saved to spike_logs/dispute_{args.id}.json")
    if isinstance(body, dict):
        print(f"  reason={body.get('reason')} status={body.get('status')} stage={body.get('dispute_life_cycle_stage')}")
        print(f"  messages={len(body.get('messages', []) or [])}")
        for link in body.get("links", []) or []:
            print(f"  action link: {link.get('rel')}  {link.get('method')}")
        finding(
            "dispute_shape",
            dispute_id=args.id,
            reason=body.get("reason"),
            status=body.get("status"),
            has_buyer_messages=bool(body.get("messages")),
            action_links=[link.get("rel") for link in body.get("links", []) or []],
        )


def cmd_accept_claim(settings: Settings, args: argparse.Namespace) -> None:
    if not args.yes:
        raise ConfigError("accept-claim is irreversible (even in sandbox). Re-run with --yes to confirm.")
    request_id = new_request_id()
    response = client_for(settings, "merchant").request(
        "POST", f"/v1/customer/disputes/{args.id}/accept-claim", json_body={"note": args.note}, request_id=request_id
    )
    show(response)
    finding("accept_claim", dispute_id=args.id, http_status=response.status_code, request_id=request_id)


def cmd_evidence_probe(settings: Settings, args: argparse.Namespace) -> None:
    """Send the same evidence twice with the same PayPal-Request-Id and compare."""
    client = client_for(settings, "merchant")
    request_id = new_request_id()
    payload = {
        "evidences": [{"evidence_type": "OTHER", "notes": "Incident Shield spike: request-ID idempotency probe."}]
    }
    results = []
    for attempt in (1, 2):
        print(f"--- provide-evidence attempt {attempt} (PayPal-Request-Id {request_id})")
        response = client.request(
            "POST",
            f"/v1/customer/disputes/{args.id}/provide-evidence",
            files={"input": (None, json.dumps(payload), "application/json")},
            request_id=request_id,
        )
        show(response)
        results.append(response.status_code)
    finding("evidence_request_id_probe", dispute_id=args.id, request_id=request_id, statuses=results)
    print(f"\nStatuses: {results}. Now run dispute-show to check whether the evidence appears once or twice.")


AUTH_STATUSES = frozenset({401, 403})


class ProbeErrorPolicy:
    """Decides when the lag probe gives up.

    Auth errors (401/403) can mean a newly enabled reporting permission hasn't
    activated yet, so they're tolerated for `auth_grace_hours` from probe start.
    Any other error (or a network failure) counts toward `max_errors` in a row.
    A successful query resets the count.
    """

    def __init__(self, max_errors: int, auth_grace_hours: float) -> None:
        self.max_errors = max_errors
        self.auth_grace_hours = auth_grace_hours
        self.consecutive_errors = 0

    def record_success(self) -> None:
        self.consecutive_errors = 0

    def record_error(self, status: int | None, hours_since_start: float) -> bool:
        """Return True if the probe should abort."""
        if status in AUTH_STATUSES and hours_since_start < self.auth_grace_hours:
            return False
        self.consecutive_errors += 1
        return self.consecutive_errors >= self.max_errors


def _txsearch_targets() -> dict[str, str]:
    """Map transaction/capture IDs we created -> created_at."""
    targets: dict[str, str] = {}
    for rec in read_jsonl("created"):
        for cap in rec.get("captures", []) or []:
            if cap.get("capture_id"):
                targets[cap["capture_id"]] = rec.get("created_at", "")
        for tx in rec.get("transaction_ids", []) or []:
            targets[tx] = rec.get("created_at", "")
    return targets


def cmd_txsearch_probe(settings: Settings, args: argparse.Namespace) -> None:
    client = client_for(settings, "merchant")
    seen = {r["transaction_id"] for r in read_jsonl("txsearch") if r.get("event") == "first_seen"}
    started = time.monotonic()
    deadline = started + args.hours * 3600
    policy = ProbeErrorPolicy(args.max_errors, args.auth_grace_hours)
    print(f"Polling Transaction Search every {args.interval}s for up to {args.hours}h. Ctrl+C to stop.")
    print(
        "Reported lag is an UPPER BOUND: measured from when this script recorded the payment, "
        f"with {args.interval // 60}-minute resolution."
    )
    while True:
        end = utcnow() - timedelta(minutes=1)
        start = end - timedelta(hours=args.lookback_hours)
        targets = _txsearch_targets()
        found: dict[str, Any] = {}
        page, total_pages = 1, 1
        failed_status: int | None = None
        query_failed = False
        while page <= total_pages:
            try:
                response = client.request(
                    "GET",
                    "/v1/reporting/transactions",
                    params={
                        "start_date": start.strftime("%Y-%m-%dT%H:%M:%S%z"),
                        "end_date": end.strftime("%Y-%m-%dT%H:%M:%S%z"),
                        "fields": "all",
                        "page_size": 500,
                        "page": page,
                    },
                )
            except (httpx.HTTPError, RuntimeError) as exc:
                append_jsonl("txsearch", {"event": "query_error", "status": None, "error": repr(exc)})
                print(f"  query failed: {exc!r}")
                query_failed = True
                break
            body = safe_json(response)
            if response.status_code != 200 or not isinstance(body, dict):
                append_jsonl("txsearch", {"event": "query_error", "status": response.status_code, "body": body})
                hint = " (auth: tolerated during grace period)" if response.status_code in AUTH_STATUSES else ""
                print(f"  query error HTTP {response.status_code}{hint} (see spike_logs/txsearch.jsonl)")
                failed_status, query_failed = response.status_code, True
                break
            total_pages = int(body.get("total_pages") or 1)
            for detail in body.get("transaction_details", []) or []:
                tx_id = (detail.get("transaction_info") or {}).get("transaction_id")
                if tx_id:
                    found[tx_id] = detail
            page += 1

        if query_failed:
            hours_running = (time.monotonic() - started) / 3600
            if policy.record_error(failed_status, hours_running):
                finding("txsearch_aborted", consecutive_errors=policy.consecutive_errors, last_status=failed_status)
                print(
                    f"ABORTING: {policy.consecutive_errors} consecutive query errors. Check the app has "
                    "Transaction search enabled and the token has a reporting scope (run: token)."
                )
                return
        else:
            policy.record_success()

        now = utcnow()
        for tx_id, created_at in targets.items():
            if tx_id in found and tx_id not in seen:
                created = parse_paypal_time(created_at)
                lag = round((now - created).total_seconds() / 60, 1) if created else None
                detail = found[tx_id]
                append_jsonl(
                    "txsearch",
                    {
                        "event": "first_seen",
                        "transaction_id": tx_id,
                        "created_at": created_at,
                        "seen_at": iso(now),
                        "lag_minutes_upper_bound": lag,
                        "resolution_minutes": round(args.interval / 60, 1),
                        "transaction_info_keys": sorted((detail.get("transaction_info") or {}).keys()),
                        "payer_info_keys": sorted((detail.get("payer_info") or {}).keys()),
                        "detail": detail,
                    },
                )
                seen.add(tx_id)
                print(f"  FIRST SEEN {tx_id}: lag <= {lag} min (upper bound)")
        missing = [t for t in targets if t not in seen]
        print(
            f"[{iso(now)}] targets={len(targets)} seen={len(seen & set(targets))} still_missing={len(missing)} "
            f"(window has {len(found)} transactions)"
        )
        if time.monotonic() >= deadline:
            break
        time.sleep(args.interval)


def summarize(values: list[float]) -> str:
    """median / p95 / max. p95 needs at least 2 samples."""
    ordered = sorted(values)
    p95 = statistics.quantiles(ordered, n=20, method="inclusive")[-1] if len(ordered) >= 2 else ordered[0]
    return f"n={len(ordered)} median={statistics.median(ordered):.1f} p95={p95:.1f} max={ordered[-1]:.1f}"


def first_deliveries(hooks: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Earliest delivery per event ID. Redeliveries (e.g. after forced 503s) would inflate delay stats."""
    earliest: dict[Any, dict[str, Any]] = {}
    for hook in hooks:
        key = hook.get("event_id")
        if key not in earliest or hook.get("received_at", "") < earliest[key].get("received_at", ""):
            earliest[key] = hook
    return list(earliest.values())


def timing_hooks(hooks: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Verified deliveries usable for handler-time stats.

    Excludes the timeout experiment (deliberate ack delay) and forced-503 runs,
    which measure PayPal, not our handler.
    """
    return [
        h
        for h in hooks
        if isinstance(h.get("handler_ms"), (int, float))
        and not h.get("ack_delay_s")
        and h.get("outcome") != "forced_503"
    ]


def verified_hooks(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Only signature-verified deliveries may feed the spike's answers."""
    return [r for r in records if r.get("verified") is True and r.get("event_type")]


MARKER_DIR = LOG_DIR / "markers"


def read_marker(path: Path) -> datetime | None:
    """When this script last touched a resource (None if never, or unreadable)."""
    try:
        return datetime.fromisoformat(path.read_text(encoding="utf-8").strip())
    except (FileNotFoundError, ValueError):
        return None


def write_marker(path: Path, when: datetime) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(iso(when), encoding="utf-8")


def measure_attempts(
    repeat: int, operation: Callable[[], dict[str, Any]], marker: Path, now: Callable[[], datetime] = utcnow
) -> list[dict[str, Any]]:
    """Run `operation` `repeat` times, timing each one.

    The marker is written BEFORE each attempt: a failed or timed-out attempt may
    still have woken the resource, so the next run must not count as cold.
    A failure (timeout, refused connection, ...) is recorded as that attempt's
    outcome instead of crashing: a cold-start timeout is the most important result.
    """
    results = []
    for attempt in range(1, repeat + 1):
        write_marker(marker, now())
        started = time.perf_counter()
        try:
            outcome: dict[str, Any] = {"ok": True, **operation()}
        except Exception as exc:  # noqa: BLE001 - any failure is a measurement to record, not a crash
            outcome = {"ok": False, "error_type": type(exc).__name__, "error": str(exc)[:300]}
        results.append({"attempt": attempt, "total_ms": round((time.perf_counter() - started) * 1000), **outcome})
    return results


NOT_COLD_AFTER_S = 120.0


def coldness(attempt: int, process_age_s: float | None) -> str:
    """Classify a cold-start attempt using the service's own process age.

    Attempt 1 with a process older than NOT_COLD_AFTER_S means the instance never
    spun down, so the number is a warm start, whatever the idle time.
    """
    if attempt != 1:
        return "warm"
    if process_age_s is None:
        return "UNCONFIRMED"
    return "cold" if process_age_s <= NOT_COLD_AFTER_S else "NOT COLD"


def neon_endpoint_kind(url: str) -> str:
    """Neon's pooled endpoints have '-pooler' in the host. They behave differently from direct ones."""
    host = urlparse(url).hostname or ""
    return "pooled" if "-pooler" in host else "direct"


def idle_gate(last_used: datetime | None, now: datetime, min_idle_minutes: float) -> str | None:
    """Return a refusal message if this script touched the DB too recently, else None."""
    if last_used is None:
        return None
    idle_minutes = (now - last_used).total_seconds() / 60
    if idle_minutes < min_idle_minutes:
        return (
            f"This script last used the database {idle_minutes:.1f} min ago; wait until "
            f"{min_idle_minutes:.0f} min have passed (or pass --min-idle-minutes 0 to measure a warm start)."
        )
    return None


def _gate_or_raise(marker: Path, min_idle_minutes: float) -> datetime | None:
    last_used = read_marker(marker)
    refusal = idle_gate(last_used, utcnow(), min_idle_minutes)
    if refusal:
        raise ConfigError(refusal)
    if last_used is None:
        print("Note: no previous run recorded, so idle time is unknown (only this script's own use is tracked).")
    return last_used


def cmd_db_coldstart(settings: Settings | None, args: argparse.Namespace) -> None:
    """Time connect + SELECT 1 against Postgres after the DB has been idle."""
    try:
        import psycopg
    except ImportError as exc:
        raise ConfigError("pip install -r requirements-spike.txt (needs psycopg)") from exc
    url = os.getenv("DATABASE_URL", "").strip()
    if not url:
        raise ConfigError("Set DATABASE_URL in .env: the exact Neon connection string the app will use")
    marker = MARKER_DIR / "db_last_used.txt"
    last_used = _gate_or_raise(marker, args.min_idle_minutes)
    kind = neon_endpoint_kind(url)
    print(f"Endpoint: {kind}. Measured from THIS machine, not from Render.")

    def connect_and_query() -> dict[str, Any]:
        started = time.perf_counter()
        with psycopg.connect(url, connect_timeout=30) as conn:
            connected = time.perf_counter()
            conn.execute("SELECT 1").fetchone()
        return {"connect_ms": round((connected - started) * 1000)}

    idle = round((utcnow() - last_used).total_seconds() / 60, 1) if last_used else None
    for result in measure_attempts(args.repeat, connect_and_query, marker):
        if result["ok"]:
            print(
                f"attempt {result['attempt']}: connect={result['connect_ms']} ms, connect+query={result['total_ms']} ms"
            )
        else:
            print(
                f"attempt {result['attempt']}: FAILED after {result['total_ms']} ms: "
                f"{result['error_type']}: {result['error']}"
            )
        finding(
            "db_coldstart",
            **result,
            endpoint=kind,
            idle_minutes=idle if result["attempt"] == 1 else None,
            measured_from="local machine",
        )


def process_age_from(response: httpx.Response) -> float | None:
    try:
        value = response.json().get("process_age_s")
    except (ValueError, AttributeError):
        return None
    return float(value) if isinstance(value, (int, float)) else None


def cmd_http_coldstart(settings: Settings | None, args: argparse.Namespace) -> None:
    """Time GET requests to a deployed service after it has been idle (e.g. Render free tier spin-down)."""
    host = urlparse(args.url).hostname or "unknown"
    if not args.url.startswith("https://"):
        raise ConfigError("Use the service's https URL")
    marker = MARKER_DIR / f"http_last_used_{re.sub(r'[^A-Za-z0-9.-]', '_', host)}.txt"
    last_used = _gate_or_raise(marker, args.min_idle_minutes)

    def get() -> dict[str, Any]:
        response = httpx.get(args.url, timeout=args.timeout)
        return {"http_status": response.status_code, "process_age_s": process_age_from(response)}

    idle = round((utcnow() - last_used).total_seconds() / 60, 1) if last_used else None
    for result in measure_attempts(args.repeat, get, marker):
        attempt = result["attempt"]
        if result["ok"]:
            label = coldness(attempt, result["process_age_s"])
            print(
                f"attempt {attempt}: HTTP {result['http_status']} in {result['total_ms']} ms "
                f"(process_age_s={result['process_age_s']}) -> {label}"
            )
            if label == "NOT COLD":
                print("  The instance never spun down: this is a WARM number. Wait longer and re-run.")
        else:
            label = "FAILED"
            print(f"attempt {attempt}: FAILED after {result['total_ms']} ms: {result['error_type']}: {result['error']}")
        finding(
            "http_coldstart",
            **result,
            classification=label,
            url=args.url,
            idle_minutes=idle if attempt == 1 else None,
        )


def cmd_report(settings: Settings | None, args: argparse.Namespace) -> None:
    lines: list[str] = []
    out = lines.append
    records = read_jsonl("webhooks")
    hooks = verified_hooks(records)
    out(f"== Webhooks: {len(records)} requests received, {len(hooks)} VERIFIED")
    out("  (everything below except 'outcomes' and 'verification' uses verified events only)")
    out("  outcomes:     " + ", ".join(f"{k}={v}" for k, v in Counter(r.get("outcome") for r in records).items()))
    out(
        "  verification: "
        + ", ".join(
            f"{k}={v}"
            for k, v in Counter(
                (r.get("verification") or {}).get("status") for r in records if r.get("verification")
            ).items()
        )
    )
    for name, count in Counter(h["event_type"] for h in hooks).most_common():
        out(f"  {count:3d}  {name}")
    handler_ms = [h["handler_ms"] for h in timing_hooks(hooks)]
    if handler_ms:
        out(
            "  total handler ms, verified, excluding experiment runs (time until PayPal gets an answer): "
            f"{summarize(handler_ms)}"
        )
    delays = [
        h["delivery_delay_s"] for h in first_deliveries(hooks) if isinstance(h.get("delivery_delay_s"), (int, float))
    ]
    if delays:
        out(f"  delivery delay s, first deliveries only: {summarize(delays)}")
    verify_ms = [h["verification"]["elapsed_ms"] for h in hooks if h["verification"].get("elapsed_ms")]
    if verify_ms:
        out(f"  verify call ms: {summarize(verify_ms)}")
    retries = {k: v for k, v in Counter(h.get("event_id") for h in hooks).items() if v > 1}
    if retries:
        out("  redelivered events:")
        for event_id, count in retries.items():
            times = [h["received_at"] for h in hooks if h.get("event_id") == event_id]
            out(f"    {event_id}: {count} deliveries at {times}")

    out("\n== Where the interesting fields live, per event type")
    paths: dict[str, set[str]] = defaultdict(set)
    for hook in hooks:
        for path, preview in find_paths(hook.get("event", {})):
            paths[hook["event_type"]].add(f"{path} = {preview}")
    for event_type, found in sorted(paths.items()):
        out(f"  {event_type}")
        for entry in sorted(found):
            out(f"    {entry}")

    tx = [r for r in read_jsonl("txsearch") if r.get("event") == "first_seen"]
    out(f"\n== Transaction Search: {len(tx)} transactions first-seen (lag values are upper bounds)")
    for r in tx:
        out(
            f"  {r['transaction_id']}: lag <= {r.get('lag_minutes_upper_bound')} min "
            f"(resolution {r.get('resolution_minutes')} min); "
            f"transaction_info keys={r.get('transaction_info_keys')}"
        )
    missing = [t for t in _txsearch_targets() if t not in {r["transaction_id"] for r in tx}]
    out(f"  not yet seen: {missing}")

    out("\n== Findings log")
    for f in read_jsonl("findings"):
        topic = f.pop("topic", "?")
        f.pop("logged_at", None)
        out(f"  [{topic}] {json.dumps(f, default=str)[:300]}")

    text = "\n".join(lines)
    print(text)
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    (LOG_DIR / "report.txt").write_text(text, encoding="utf-8")
    print("\n(saved to spike_logs/report.txt)")


# --------------------------------------------------------------------------- CLI


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m spike.run_spike", description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("token", help="Get an OAuth token and list relevant scopes")
    p.add_argument("--app", choices=["merchant", "sender"], default="merchant")
    p.set_defaults(func=cmd_token)

    sub.add_parser("webhooks-list", help="List webhooks on the merchant app").set_defaults(func=cmd_webhooks_list)

    p = sub.add_parser("webhook-register", help="Register the tunnel URL for all event types")
    p.add_argument("--url", required=True, help="https://<tunnel>/webhooks/paypal")
    p.add_argument("--replace", action="store_true", help="Delete existing webhooks on the app first")
    p.set_defaults(func=cmd_webhook_register)

    p = sub.add_parser("webhook-delete", help="Delete one webhook")
    p.add_argument("--id", required=True, type=paypal_id)
    p.set_defaults(func=cmd_webhook_delete)

    p = sub.add_parser("pay-card", help="Inbound payment via sandbox card (no buyer login needed)")
    p.add_argument("--amount", type=money, required=True)
    p.add_argument("--currency", type=currency, default="USD")
    p.add_argument("--name", default=SYNTHETIC_SENDERS[0])
    p.add_argument("--custom-id")
    p.add_argument("--description")
    p.set_defaults(func=cmd_pay_card)

    p = sub.add_parser("burst", help="Several card payments from different synthetic senders")
    p.add_argument("--count", type=int, default=4)
    p.add_argument("--currencies", default="USD,EUR,GBP")
    p.add_argument("--gap", type=float, default=5.0, help="seconds between payments")
    p.add_argument("--custom-id")
    p.set_defaults(func=cmd_burst)

    p = sub.add_parser("pay-wallet", help="Inbound PayPal-wallet payment (buyer approves in browser)")
    p.add_argument("--amount", type=money, required=True)
    p.add_argument("--currency", type=currency, default="USD")
    p.add_argument("--custom-id")
    p.set_defaults(func=cmd_pay_wallet)

    p = sub.add_parser("capture", help="Capture an approved order")
    p.add_argument("--order-id", required=True, type=paypal_id)
    p.set_defaults(func=cmd_capture)

    p = sub.add_parser("payout", help="Send money out (merchant) or in (sender app) via Payouts")
    p.add_argument("--app", choices=["merchant", "sender"], default="merchant")
    p.add_argument("--to", required=True, help="recipient sandbox account email")
    p.add_argument("--amount", type=money, required=True)
    p.add_argument("--currency", type=currency, default="USD")
    p.add_argument("--note", help="free-text note shown to the recipient (attacker-controlled field)")
    p.set_defaults(func=cmd_payout)

    p = sub.add_parser("payout-status", help="Show payout items and record their transaction IDs")
    p.add_argument("--app", choices=["merchant", "sender"], default="merchant")
    p.add_argument("--batch-id", required=True, type=paypal_id)
    p.set_defaults(func=cmd_payout_status)

    sub.add_parser("disputes-list", help="List disputes on the merchant account").set_defaults(func=cmd_disputes_list)

    p = sub.add_parser("dispute-show", help="Show one dispute and save its full body")
    p.add_argument("--id", required=True, type=paypal_id)
    p.set_defaults(func=cmd_dispute_show)

    p = sub.add_parser("accept-claim", help="Accept a dispute claim (irreversible)")
    p.add_argument("--id", required=True, type=paypal_id)
    p.add_argument("--note", default="Incident Shield spike: accepting claim.")
    p.add_argument("--yes", action="store_true")
    p.set_defaults(func=cmd_accept_claim)

    p = sub.add_parser("evidence-probe", help="Test PayPal-Request-Id idempotency on provide-evidence")
    p.add_argument("--id", required=True, type=paypal_id)
    p.set_defaults(func=cmd_evidence_probe)

    p = sub.add_parser("txsearch-probe", help="Measure Transaction Search lag for created transactions")
    p.add_argument("--interval", type=int, default=600, help="seconds between polls")
    p.add_argument("--hours", type=float, default=6.0)
    p.add_argument("--lookback-hours", type=float, default=48.0)
    p.add_argument("--max-errors", type=int, default=3, help="abort after this many consecutive non-auth errors")
    p.add_argument(
        "--auth-grace-hours", type=float, default=4.0, help="tolerate 401/403 this long (permission activation)"
    )
    p.set_defaults(func=cmd_txsearch_probe)

    p = sub.add_parser("db-coldstart", help="Time Postgres connect + query (run after the DB has idled)")
    p.add_argument("--repeat", type=int, default=2, help="1st attempt = cold, later ones = warm")
    p.add_argument("--min-idle-minutes", type=float, default=10.0, help="refuse if this script used the DB sooner")
    p.set_defaults(func=cmd_db_coldstart)

    p = sub.add_parser("http-coldstart", help="Time GETs to a deployed service after idle (Render spin-down)")
    p.add_argument("--url", required=True, help="e.g. https://<service>.onrender.com/health")
    p.add_argument("--repeat", type=int, default=2, help="1st attempt = cold, later ones = warm")
    p.add_argument("--min-idle-minutes", type=float, default=20.0, help="refuse if this script hit it sooner")
    p.add_argument("--timeout", type=float, default=120.0, help="seconds to wait for a sleeping service")
    p.set_defaults(func=cmd_http_coldstart)

    sub.add_parser("report", help="Summarise everything logged so far").set_defaults(func=cmd_report)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        settings = None if args.func in (cmd_report, cmd_db_coldstart, cmd_http_coldstart) else load_settings()
        args.func(settings, args)
    except ConfigError as exc:
        print(f"CONFIG ERROR: {exc}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("\nstopped")
        return 130
    return 0


if __name__ == "__main__":
    sys.exit(main())
