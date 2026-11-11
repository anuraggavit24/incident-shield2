"""Database tables.

Money is Numeric(18, 2) and handled as Decimal everywhere. Times are timezone-aware UTC.
"""

from __future__ import annotations

from datetime import datetime
from decimal import Decimal
from typing import Any

from sqlalchemy import JSON, Boolean, DateTime, ForeignKey, Integer, Numeric, String, Text, false, func
from sqlalchemy.orm import Mapped, mapped_column

from .db import Base

Money = Numeric(18, 2)


class WebhookEvent(Base):
    """A signature-verified PayPal webhook delivery. Unverified requests are never stored here."""

    __tablename__ = "webhook_events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    event_id: Mapped[str] = mapped_column(String(128), unique=True)
    event_type: Mapped[str] = mapped_column(String(128), index=True)
    resource_id: Mapped[str | None] = mapped_column(String(128))
    event_created_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    received_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    payload: Mapped[dict[str, Any]] = mapped_column(JSON)
    # pending -> processed | ignored | failed (failed is retried until attempts run out)
    status: Mapped[str] = mapped_column(String(16), default="pending", index=True)
    attempts: Mapped[int] = mapped_column(Integer, default=0)
    last_error: Mapped[str | None] = mapped_column(Text)
    processed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class Transaction(Base):
    """One money movement, normalised from webhooks (and later Transaction Search)."""

    __tablename__ = "transactions"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    paypal_id: Mapped[str] = mapped_column(String(64), unique=True)
    kind: Mapped[str] = mapped_column(String(16))  # capture | payout
    direction: Mapped[str] = mapped_column(String(3))  # in | out
    amount: Mapped[Decimal] = mapped_column(Money)
    currency: Mapped[str] = mapped_column(String(3))
    amount_usd: Mapped[Decimal | None] = mapped_column(Money)
    status: Mapped[str] = mapped_column(String(32))
    status_rank: Mapped[int] = mapped_column(Integer)
    occurred_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    last_event_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    order_id: Mapped[str | None] = mapped_column(String(64))
    custom_id: Mapped[str | None] = mapped_column(String(127))
    counterparty_key: Mapped[str | None] = mapped_column(String(160), index=True)
    counterparty_label: Mapped[str | None] = mapped_column(String(200))
    identity_strength: Mapped[str] = mapped_column(String(8), default="unknown")  # strong | weak | unknown
    # Attacker-controllable text (payer-typed names, notes). Never interpreted, only displayed or
    # passed to the AI layer as delimited data.
    untrusted_text: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    source: Mapped[str] = mapped_column(String(16))  # webhook | txsearch
    flags: Mapped[list[Any]] = mapped_column(JSON, default=list)


class Incident(Base):
    __tablename__ = "incidents"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    kind: Mapped[str] = mapped_column(String(48))
    severity: Mapped[str] = mapped_column(String(8))  # low | medium | high
    status: Mapped[str] = mapped_column(String(24), default="detected")
    opened_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    # e.g. "mule:<64-hex>" (the earliest probe's key when the incident was first opened)
    dedupe_key: Mapped[str] = mapped_column(String(128), unique=True)


class RuleHit(Base):
    __tablename__ = "rule_hits"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    rule_id: Mapped[str] = mapped_column(String(32), index=True)
    rule_version: Mapped[int] = mapped_column(Integer)
    severity: Mapped[str] = mapped_column(String(8))
    window_start: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    window_end: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    values: Mapped[dict[str, Any]] = mapped_column(JSON)
    transaction_ids: Mapped[list[str]] = mapped_column(JSON)
    dedupe_key: Mapped[str] = mapped_column(String(64), unique=True)
    incident_id: Mapped[int | None] = mapped_column(ForeignKey("incidents.id"), index=True)
    # Set when a later hit of the same rule covers all of this hit's transactions.
    superseded_by: Mapped[int | None] = mapped_column(ForeignKey("rule_hits.id"))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class IncidentEvent(Base):
    """Append-only audit trail for an incident."""

    __tablename__ = "incident_events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    incident_id: Mapped[int] = mapped_column(ForeignKey("incidents.id"), index=True)
    at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    actor: Mapped[str] = mapped_column(String(16))  # system | owner
    action: Mapped[str] = mapped_column(String(48))
    details: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)


class CopilotCall(Base):
    """Every Copilot answer: the cache (same question + same evidence = same answer, no new AI call)
    and the persistent daily AI budget (it survives restarts)."""

    __tablename__ = "copilot_calls"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    cache_key: Mapped[str] = mapped_column(String(64), index=True)
    incident_id: Mapped[int] = mapped_column(ForeignKey("incidents.id"), index=True)
    scope: Mapped[str] = mapped_column(String(16))  # owner | judge | warmup
    # Only stable outcomes are served from cache; failures are kept for the budget and the audit.
    cacheable: Mapped[bool] = mapped_column(Boolean, default=False, server_default=false())
    source: Mapped[str] = mapped_column(String(16))  # ai | template | refused
    intent: Mapped[str] = mapped_column(String(32))
    response: Mapped[dict[str, Any]] = mapped_column(JSON)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), index=True)
