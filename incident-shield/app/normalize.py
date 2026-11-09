"""Turn PayPal webhook events into normalised money movements. Pure functions, no I/O.

Shapes are taken from real sandbox deliveries (tests/fixtures). Capture events carry no payer
information; the payer is identified separately from the order (see parse_order_identity).
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation
from typing import Any

CAPTURE_EVENTS = frozenset(
    {"PAYMENT.CAPTURE.COMPLETED", "PAYMENT.CAPTURE.PENDING", "PAYMENT.CAPTURE.DENIED", "PAYMENT.CAPTURE.DECLINED"}
)
PAYOUT_ITEM_PREFIX = "PAYMENT.PAYOUTS-ITEM."

# Higher rank = later in the lifecycle. A transaction normally only moves to an equal or higher rank.
STATUS_RANK = {
    "PENDING": 10,
    "ONHOLD": 10,
    "UNCLAIMED": 15,
    "COMPLETED": 20,
    "SUCCESS": 20,
    "DENIED": 30,
    "DECLINED": 30,
    "FAILED": 30,
    "BLOCKED": 30,
    "PARTIALLY_REFUNDED": 40,
    "REFUNDED": 50,
    "RETURNED": 50,
    "REVERSED": 60,
}
# Legitimate moves to a LOWER rank, e.g. a chargeback decided in the merchant's favour.
# Inferred from PayPal's documented states, not from a published transition table.
ALLOWED_DOWNGRADES = frozenset({("REVERSED", "COMPLETED")})


@dataclass(frozen=True)
class NormalizedTxn:
    paypal_id: str
    kind: str  # capture | payout
    direction: str  # in | out
    amount: Decimal
    currency: str
    amount_usd: Decimal | None
    status: str
    occurred_at: datetime
    order_id: str | None = None
    custom_id: str | None = None
    counterparty_key: str | None = None
    counterparty_label: str | None = None
    identity_strength: str = "unknown"
    untrusted_text: dict[str, str] = field(default_factory=dict)


@dataclass(frozen=True)
class Identity:
    key: str
    label: str
    strength: str  # strong | weak
    untrusted_text: dict[str, str]


class NormalizationError(ValueError):
    """The event is a supported type but its payload is malformed."""


def parse_time(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def _money(obj: Any, value_key: str = "value", currency_key: str = "currency_code") -> tuple[Decimal, str]:
    if not isinstance(obj, dict):
        raise NormalizationError("missing amount")
    try:
        amount = Decimal(str(obj[value_key]))
    except (KeyError, InvalidOperation) as exc:
        raise NormalizationError(f"bad amount: {obj!r}") from exc
    cur = str(obj.get(currency_key, "")).upper()
    if len(cur) != 3:
        raise NormalizationError(f"bad currency: {obj!r}")
    return amount, cur


def _capture(event: dict[str, Any]) -> NormalizedTxn:
    res = event.get("resource") or {}
    paypal_id = res.get("id")
    if not paypal_id:
        raise NormalizationError("capture without id")
    amount, currency = _money(res.get("amount"))
    amount_usd: Decimal | None = amount if currency == "USD" else None
    receivable = (res.get("seller_receivable_breakdown") or {}).get("receivable_amount")
    if amount_usd is None and isinstance(receivable, dict) and receivable.get("currency_code") == "USD":
        amount_usd, _ = _money(receivable)
    occurred = parse_time(res.get("create_time")) or parse_time(event.get("create_time"))
    if occurred is None:
        raise NormalizationError("capture without time")
    order_id = ((res.get("supplementary_data") or {}).get("related_ids") or {}).get("order_id")
    return NormalizedTxn(
        paypal_id=paypal_id,
        kind="capture",
        direction="in",
        amount=amount,
        currency=currency,
        amount_usd=amount_usd,
        status=str(res.get("status", "UNKNOWN")).upper(),
        occurred_at=occurred,
        order_id=order_id,
        custom_id=res.get("custom_id"),
    )


def _payout_item(event: dict[str, Any]) -> NormalizedTxn | None:
    res = event.get("resource") or {}
    item = res.get("payout_item") or {}
    # Failed items may have no transaction_id; fall back to the payout item id.
    paypal_id = res.get("transaction_id") or res.get("payout_item_id")
    if not paypal_id:
        raise NormalizationError("payout item without id")
    amount, currency = _money(item.get("amount"), currency_key="currency")
    occurred = parse_time(res.get("time_processed")) or parse_time(event.get("create_time"))
    if occurred is None:
        raise NormalizationError("payout item without time")
    receiver = str(item.get("receiver") or "")
    return NormalizedTxn(
        paypal_id=paypal_id,
        kind="payout",
        direction="out",
        amount=amount,
        currency=currency,
        amount_usd=amount if currency == "USD" else None,
        status=str(res.get("transaction_status", "UNKNOWN")).upper(),
        occurred_at=occurred,
        counterparty_key=f"payout:{receiver.lower()}" if receiver else None,
        counterparty_label=receiver or None,
        # The merchant chose this recipient, so the identity is reliable.
        identity_strength="strong" if receiver else "unknown",
    )


def normalize_event(event: dict[str, Any]) -> NormalizedTxn | None:
    """Return a money movement, or None for event types that don't represent one."""
    event_type = str(event.get("event_type", ""))
    if event_type in CAPTURE_EVENTS:
        return _capture(event)
    if event_type.startswith(PAYOUT_ITEM_PREFIX):
        return _payout_item(event)
    return None


def _norm_name(name: str) -> str:
    return re.sub(r"\s+", " ", name).strip().casefold()


def parse_order_identity(order: dict[str, Any]) -> Identity | None:
    """Identify the payer from a GET /v2/checkout/orders/{id} response.

    PayPal wallet: account_id is stable across payments (strong).
    Card guest: sandbox issues a NEW payer account id on every card payment, so the
    best available identity is name + brand + last 4 digits (weak).
    """
    source = order.get("payment_source") or {}
    wallet = source.get("paypal")
    if isinstance(wallet, dict) and wallet.get("account_id"):
        name = wallet.get("name") or {}
        full = " ".join(p for p in (name.get("given_name"), name.get("surname")) if p)
        return Identity(
            key=f"paypal:{wallet['account_id']}",
            label=full or "PayPal account",
            strength="strong",
            untrusted_text={"payer_name": full} if full else {},
        )
    card = source.get("card")
    if isinstance(card, dict) and (card.get("name") or card.get("last_digits")):
        name = str(card.get("name") or "")
        brand = str(card.get("brand") or "card").upper()
        last4 = str(card.get("last_digits") or "????")
        return Identity(
            key=f"card:{_norm_name(name)}:{brand}:{last4}",
            label=f"{name or 'Card holder'} ({brand} ...{last4})",
            strength="weak",
            untrusted_text={"payer_name": name} if name else {},
        )
    return None


def decide_transition(
    old_status: str, old_event_at: datetime | None, new_status: str, new_event_at: datetime | None
) -> tuple[bool, str | None]:
    """Should a new event's status replace the stored one? Returns (apply, flag)."""
    old_rank = STATUS_RANK.get(old_status, 0)
    new_rank = STATUS_RANK.get(new_status, 0)
    if new_status == old_status:
        return False, None
    if (old_status, new_status) in ALLOWED_DOWNGRADES:
        return True, f"allowed_downgrade:{old_status}->{new_status}"
    if new_rank > old_rank:
        return True, None
    if new_rank == old_rank:
        # Same stage, different status: newest event wins; stale events never overwrite.
        newer = old_event_at is None or (new_event_at is not None and new_event_at > old_event_at)
        return newer, None
    return False, f"unexpected_transition:{old_status}->{new_status}"
