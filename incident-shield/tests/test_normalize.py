"""Normalisation against REAL sandbox webhook payloads (tests/fixtures)."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from decimal import Decimal
from pathlib import Path

import pytest

from app.normalize import NormalizationError, decide_transition, normalize_event, parse_order_identity

FIXTURES = Path(__file__).parent / "fixtures"
EVENTS = json.loads((FIXTURES / "sandbox_webhook_events.json").read_text(encoding="utf-8"))
ORDERS = json.loads((FIXTURES / "sandbox_orders.json").read_text(encoding="utf-8"))


def by_resource(resource_id: str) -> dict:
    return next(e for e in EVENTS if (e["resource"].get("id") or e["resource"].get("transaction_id")) == resource_id)


def test_usd_card_capture() -> None:
    txn = normalize_event(by_resource("6JB34600M49183205"))
    assert txn is not None
    assert (txn.kind, txn.direction, txn.status) == ("capture", "in", "COMPLETED")
    assert txn.amount == Decimal("0.79") and txn.currency == "USD" and txn.amount_usd == Decimal("0.79")
    assert txn.order_id == "8NH233524F587213D"
    assert txn.custom_id == "spike-run-1"
    assert txn.occurred_at == datetime(2026, 11, 8, 7, 49, 40, tzinfo=timezone.utc)
    assert txn.counterparty_key is None  # capture events carry no payer data


@pytest.mark.parametrize(
    ("resource_id", "currency", "amount", "usd"),
    [("6F2349135S128104C", "EUR", "136.43", "144.37"), ("2JE92927X0915151N", "GBP", "62.68", "79.22")],
)
def test_foreign_currency_keeps_original_and_uses_paypal_usd_value(resource_id, currency, amount, usd) -> None:
    txn = normalize_event(by_resource(resource_id))
    assert txn.currency == currency
    assert txn.amount == Decimal(amount)
    assert txn.amount_usd == Decimal(usd)


def test_payout_item_is_outgoing_with_known_recipient() -> None:
    txn = normalize_event(by_resource("4T656028Y5133581B"))
    assert (txn.kind, txn.direction, txn.status) == ("payout", "out", "SUCCESS")
    assert txn.amount == Decimal("50.00") and txn.amount_usd == Decimal("50.00")
    assert txn.counterparty_key == "payout:sb-nwjji53751152@personal.example.com"
    assert txn.identity_strength == "strong"


@pytest.mark.parametrize(
    "event_type", ["CHECKOUT.ORDER.APPROVED", "PAYMENT.PAYOUTSBATCH.PROCESSING", "PAYMENT.PAYOUTSBATCH.SUCCESS"]
)
def test_non_money_events_are_ignored(event_type: str) -> None:
    event = next(e for e in EVENTS if e["event_type"] == event_type)
    assert normalize_event(event) is None


def test_every_fixture_normalizes_without_error() -> None:
    results = [normalize_event(e) for e in EVENTS]
    assert sum(r is not None for r in results) == 9  # 8 captures + 1 payout item


@pytest.mark.parametrize(
    "mutate",
    [
        lambda r: r.pop("amount"),
        lambda r: r.__setitem__("amount", {"currency_code": "USD", "value": "abc"}),
        lambda r: r.__setitem__("amount", {"currency_code": "US", "value": "1.00"}),
        lambda r: r.pop("id"),
    ],
)
def test_malformed_capture_raises(mutate) -> None:
    event = json.loads(json.dumps(by_resource("6JB34600M49183205")))
    mutate(event["resource"])
    with pytest.raises(NormalizationError):
        normalize_event(event)


def test_card_identity_is_weak_and_name_is_untrusted() -> None:
    identity = parse_order_identity(ORDERS["8NH233524F587213D"])
    assert identity.key == "card:test sender echo:VISA:1881"
    assert identity.strength == "weak"
    assert identity.untrusted_text == {"payer_name": "Test Sender Echo"}


def test_wallet_identity_uses_stable_account_id() -> None:
    identity = parse_order_identity(ORDERS["2TN7251323160421J"])
    assert identity.key == "paypal:63HPNVEKUH8WE"
    assert identity.strength == "strong"
    assert identity.label == "John Doe"


def test_card_name_normalisation_matches_same_person() -> None:
    a = parse_order_identity({"payment_source": {"card": {"name": "Test  Sender ALPHA", "last_digits": "1881"}}})
    b = parse_order_identity({"payment_source": {"card": {"name": "test sender alpha", "last_digits": "1881"}}})
    assert a.key == b.key


def test_order_without_payment_source_has_no_identity() -> None:
    assert parse_order_identity({}) is None


T1 = datetime(2026, 11, 8, 8, 0, tzinfo=timezone.utc)
T2 = datetime(2026, 11, 8, 8, 5, tzinfo=timezone.utc)


@pytest.mark.parametrize(
    ("old", "old_at", "new", "new_at", "apply", "flag"),
    [
        ("PENDING", T1, "COMPLETED", T2, True, None),  # normal progression
        ("COMPLETED", T2, "PENDING", T1, False, "unexpected_transition:COMPLETED->PENDING"),  # stale event
        ("COMPLETED", T1, "REFUNDED", T2, True, None),
        ("REVERSED", T1, "COMPLETED", T2, True, "allowed_downgrade:REVERSED->COMPLETED"),  # chargeback won
        ("REFUNDED", T1, "COMPLETED", T2, False, "unexpected_transition:REFUNDED->COMPLETED"),
        ("COMPLETED", T1, "COMPLETED", T2, False, None),  # duplicate
        ("COMPLETED", T2, "SUCCESS", T1, False, None),  # same rank, older event never overwrites
        ("COMPLETED", T1, "SUCCESS", T2, True, None),  # same rank, newer event wins
    ],
)
def test_state_transitions(old, old_at, new, new_at, apply, flag) -> None:
    assert decide_transition(old, old_at, new, new_at) == (apply, flag)
