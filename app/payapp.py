"""The payment app: a PayPal-like checkout whose money moves through the PayPal sandbox.

What is real and what is simulated:
- REAL (PayPal sandbox): the payer's order, approval, capture, and any refund to the payer.
- SIMULATED: crediting the payee is a ledger entry in this app, and signals only a telecom, issuer or
  consortium could see are switched on by the demo user (and labelled as simulated in the record).

Every attempt is scored by the risk engine BEFORE any money moves, the decision is sealed, and the band
decides: allow, confirm the payee (step-up), delay (suspected coached scam), hold for review, or block.
AI never moves money: a human reviewer approves refunds and releases.
"""

from __future__ import annotations

import hashlib
import logging
import re
import secrets
import threading
import time
from collections import deque
from datetime import datetime, timedelta, timezone
from decimal import ROUND_HALF_UP, Decimal, InvalidOperation
from typing import Any, Literal

import httpx
from fastapi import APIRouter, Depends, Header, HTTPException, Query, Request
from pydantic import BaseModel, Field
from sqlalchemy import func, select, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from . import db
from .auth import require_owner
from .config import get_settings
from .models import AppComplaint, AppPayment, AppUser, PaymentEvent
from .paypal_client import PayPalClient, PayPalError
from .risk import service
from .risk.brief import write_brief
from .risk.claims import extract_claims, queue_priority
from .risk.complaint import consistency
from .risk.engine import decide
from .risk.evidence import build_evidence, fingerprint_hash, sanitize_simulated
from .risk.learning import gap_report, rescore_payers, scam_library
from .risk.reference_ai import read_reference
from .risk.snapshot import SnapshotError

log = logging.getLogger("incident_shield.payapp")
router = APIRouter()

HANDLE = re.compile(r"^[a-z0-9_]{3,24}$")
DEVICE_ID = re.compile(r"^[A-Za-z0-9-]{16,64}$")
MIN_AMOUNT, MAX_AMOUNT = Decimal("0.50"), Decimal("1000.00")
PAYPAL_DOWN = (PayPalError, httpx.HTTPError)  # a refusal from PayPal, or PayPal unreachable
ATTEMPTS_PER_HOUR = 60
COMPLAINTS_PER_DAY = 5


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


clock = utcnow  # tests replace this


class SlidingLimit:
    def __init__(self, per_minute: int) -> None:
        self.per_minute, self._hits, self._lock = per_minute, deque(), threading.Lock()

    def allow(self) -> bool:
        now = time.monotonic()
        with self._lock:
            while self._hits and now - self._hits[0] > 60:
                self._hits.popleft()
            if len(self._hits) >= self.per_minute:
                return False
            self._hits.append(now)
            return True


signup_limit = SlidingLimit(30)
reference_ai_limit = SlidingLimit(12)  # AI reads of payment references per minute (free-tier budget)
SIGNUPS_PER_ADDRESS_PER_MINUTE = 4
_signup_by_address: dict[str, SlidingLimit] = {}


# --------------------------------------------------------------------------- request models


class SignupBody(BaseModel):
    handle: str = Field(min_length=3, max_length=24)
    display_name: str = Field(min_length=1, max_length=80)


class FingerprintBody(BaseModel):
    ua: str = Field(default="", max_length=300)
    platform: str = Field(default="", max_length=60)
    tz: str = Field(default="", max_length=60)
    lang: str = Field(default="", max_length=30)
    screen: str = Field(default="", max_length=30)


class BehaviourBody(BaseModel):
    typing_cps: float | None = Field(default=None, ge=0, le=200)
    paste_used: bool = False
    seconds_on_page: float | None = Field(default=None, ge=0, le=86400)
    blur_count: int = Field(default=0, ge=0, le=1000)
    pause_count: int = Field(default=0, ge=0, le=1000)


class PaymentBody(BaseModel):
    payee_handle: str = Field(min_length=3, max_length=24)
    payee_name: str = Field(min_length=1, max_length=80, description="The payee's name as the payer typed it")
    amount: str = Field(min_length=1, max_length=12)
    reference: str = Field(default="", max_length=140)
    device_id: str
    fingerprint: FingerprintBody = FingerprintBody()
    behaviour: BehaviourBody = BehaviourBody()
    simulated: dict[str, Any] = Field(default_factory=dict, description="Demo mode only")


class ConfirmBody(BaseModel):
    typed_handle: str = Field(min_length=3, max_length=24)


class CredentialsBody(BaseModel):
    device_id: str


class ComplaintBody(BaseModel):
    claim: Literal["unauthorised", "scam"]
    text: str = Field(default="", max_length=1000)


class ApproveBody(BaseModel):
    confirm_amount: str = Field(description="Type the payment amount to confirm the refund")


# --------------------------------------------------------------------------- helpers


def _ring_or_503() -> None:
    if service.keyring() is None:
        raise HTTPException(status_code=503, detail="risk keys are not configured on this server")


def _paypal(request: Request) -> PayPalClient:
    return request.app.state.paypal


def parse_amount(raw: str) -> Decimal:
    try:
        value = Decimal(raw.strip())
    except InvalidOperation:
        raise HTTPException(status_code=422, detail="amount must be a number") from None
    if not value.is_finite() or value != value.quantize(Decimal("0.01"), rounding=ROUND_HALF_UP):
        raise HTTPException(status_code=422, detail="amount must have at most 2 decimals")
    if not MIN_AMOUNT <= value <= MAX_AMOUNT:
        raise HTTPException(status_code=422, detail=f"amount must be between {MIN_AMOUNT} and {MAX_AMOUNT}")
    return value


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def client_ip(request: Request) -> str:
    settings = get_settings()
    if settings.trust_proxy:
        forwarded = request.headers.get("x-forwarded-for", "")
        if forwarded:
            # First entry = the browser as the platform's edge reported it. A client can prepend its own
            # value, so this is a heuristic input, not proof (README: limits).
            return forwarded.split(",")[0].strip()[:64]
    return request.client.host if request.client else "unknown"


def ip_digest(ip: str) -> str:
    return hashlib.sha256(f"incident-shield-ip|{ip}".encode()).hexdigest()


def current_payer(authorization: str | None = Header(default=None)) -> int:
    """The payer's user id from `Authorization: Bearer <token>`. Raw tokens are never stored."""
    token = (authorization or "").removeprefix("Bearer ").strip()
    if not token:
        raise HTTPException(status_code=401, detail="missing token")
    with db.session_scope() as session:
        user_id = session.scalar(select(AppUser.id).where(AppUser.token_hash == hash_token(token)))
    if user_id is None:
        raise HTTPException(status_code=401, detail="invalid token")
    return user_id


def add_event(
    session: Session, payment_id: int, actor: str, action: str, details: dict[str, Any] | None = None
) -> None:
    session.add(PaymentEvent(payment_id=payment_id, actor=actor, action=action, details=details or {}))


def _decision_summary(decision: dict[str, Any], simulated: list[str]) -> dict[str, Any]:
    return {
        "score": decision["score"],
        "band": decision["band"],
        "action": decision["action"],
        "typology": decision["typology"],
        "reason_codes": decision["reason_codes"],
        "floors_triggered": [f["name"] for f in decision["floors_triggered"]],
        "signals_fired": [f["name"] for f in decision["signals_fired"]],
        "missing_data": decision["missing_data"],
        "invalid_data": decision["invalid_data"],
        "simulated_fields": simulated,
    }


MESSAGES = {
    "allow": "Payment approved. Continue to PayPal to pay.",
    "step_up": "Please confirm who you are paying: type the payee's handle.",
    "warn_and_delay": (
        "This payment looks like it may be part of a scam. It is delayed. Be wary of anyone who asked you to pay "
        "urgently, to move money to a safe account, or to stay on the phone."
    ),
    "hold_review": "This payment is on hold while our team reviews it. No money has moved.",
    "block": "This payment was blocked. No money has moved.",
}


def _payment_out(session: Session, p: AppPayment, with_events: bool = False) -> dict[str, Any]:
    payee = session.get(AppUser, p.payee_id)
    out: dict[str, Any] = {
        "id": p.id,
        "status": p.status,
        "amount": f"{p.amount:.2f}",
        "currency": p.currency,
        "payee": payee.handle if payee else None,
        "reference": p.reference,
        "created_at": p.created_at.isoformat(),
        "captured_at": p.captured_at.isoformat() if p.captured_at else None,
        "refunded_at": p.refunded_at.isoformat() if p.refunded_at else None,
        "release_at": p.release_at.isoformat() if p.release_at else None,
    }
    if with_events:
        events = session.scalars(select(PaymentEvent).where(PaymentEvent.payment_id == p.id).order_by(PaymentEvent.id))
        out["timeline"] = [
            {"at": e.at.isoformat(), "actor": e.actor, "action": e.action, "details": e.details} for e in events
        ]
    return out


def _start_order(request: Request, payment_id: int) -> dict[str, Any]:
    """Create the PayPal sandbox order for a payment that is cleared to pay. Idempotent per payment."""
    settings = get_settings()
    with db.session_scope() as session:
        p = session.get(AppPayment, payment_id)
        if p is None or p.status not in ("scored", "awaiting_approval"):
            raise HTTPException(status_code=409, detail="payment is not ready to pay")
        amount, currency = f"{p.amount:.2f}", p.currency
        existing = p.paypal_order_id
    base = settings.public_base_url
    try:
        order = _paypal(request).create_order(
            amount,
            currency,
            custom_id=str(payment_id),
            return_url=f"{base}/app?pay={payment_id}",
            cancel_url=f"{base}/app?cancel={payment_id}",
            request_id=f"order-{payment_id}",
        )
    except PAYPAL_DOWN as exc:
        # The payment stays cleared-to-pay; the payer can retry (same idempotency key, so never two orders).
        with db.session_scope() as session:
            add_event(session, payment_id, "system", "paypal_order_failed", {"error": str(exc)[:200]})
        raise HTTPException(status_code=502, detail="PayPal could not create the order; try again") from None
    with db.session_scope() as session:
        p = session.get(AppPayment, payment_id)
        assert p is not None
        p.paypal_order_id, p.status = order["id"], "awaiting_approval"
        add_event(session, payment_id, "paypal", "order_created", {"order_id": order["id"], "reused": bool(existing)})
    return {"order_id": order["id"], "approve_url": order["approve_url"]}


# --------------------------------------------------------------------------- payer endpoints


@router.post("/app/signup")
def signup(body: SignupBody, request: Request) -> dict[str, Any]:
    """Create a demo account. The token is shown ONCE and only its hash is stored."""
    address = ip_digest(client_ip(request))
    if len(_signup_by_address) > 5000:
        _signup_by_address.clear()
    mine = _signup_by_address.setdefault(address, SlidingLimit(SIGNUPS_PER_ADDRESS_PER_MINUTE))
    if not mine.allow() or not signup_limit.allow():
        raise HTTPException(status_code=429, detail="too many sign-ups, try again in a minute")
    handle = body.handle.strip().lower()
    if not HANDLE.fullmatch(handle):
        raise HTTPException(status_code=422, detail="handle: 3-24 characters, a-z, 0-9 and _")
    token = secrets.token_urlsafe(32)
    try:
        with db.session_scope() as session:
            if (session.scalar(select(func.count(AppUser.id))) or 0) >= get_settings().max_users:
                raise HTTPException(status_code=503, detail="the demo is full")
            session.add(AppUser(handle=handle, display_name=body.display_name.strip(), token_hash=hash_token(token)))
    except IntegrityError:
        raise HTTPException(status_code=409, detail="that handle is taken") from None
    return {"handle": handle, "token": token}


@router.get("/app/me")
def me(user_id: int = Depends(current_payer)) -> dict[str, Any]:
    with db.session_scope() as session:
        user = session.get(AppUser, user_id)
        assert user is not None
        payments = session.scalars(
            select(AppPayment).where(AppPayment.payer_id == user_id).order_by(AppPayment.id.desc()).limit(20)
        ).all()
        return {
            "handle": user.handle,
            "display_name": user.display_name,
            "demo_mode": get_settings().simulation_enabled,
            "payments": [_payment_out(session, p) for p in payments],
        }


@router.post("/app/me/credentials")
def change_credentials(body: CredentialsBody, user_id: int = Depends(current_payer)) -> dict[str, str]:
    """Demo of a password/email change. It is recorded because attackers often change credentials first."""
    if not DEVICE_ID.fullmatch(body.device_id):
        raise HTTPException(status_code=422, detail="bad device id")
    with db.session_scope() as session:
        user = session.get(AppUser, user_id)
        assert user is not None
        user.credentials_changed_at, user.credentials_changed_device = clock(), body.device_id
    return {"status": "recorded"}


@router.post("/app/demo/history")
def demo_history(body: CredentialsBody, request: Request, user_id: int = Depends(current_payer)) -> dict[str, Any]:
    """Demo mode only: give the caller an established account, so the takeover and scam scenarios can be
    shown in one sitting. Backdates the account 120 days and adds four past $20 payments to @demo_shop from
    this device and network, plus a brand-new payee @demo_stranger. Rows are marked `seeded`; no PayPal
    call is made for them, so they can't be refunded."""
    if not get_settings().simulation_enabled:
        raise HTTPException(status_code=404, detail="not available")
    if not DEVICE_ID.fullmatch(body.device_id):
        raise HTTPException(status_code=422, detail="bad device id")
    now = clock()
    ip_hash = ip_digest(client_ip(request))
    with db.session_scope() as session:
        session.execute(text("SELECT pg_advisory_xact_lock(:k)"), {"k": service.CHAIN_LOCK + 1})
        user = session.get(AppUser, user_id)
        assert user is not None
        if session.scalar(select(AppPayment.id).where(AppPayment.payer_id == user_id).limit(1)):
            raise HTTPException(status_code=409, detail="this account already has payments")
        payees = {}
        for handle, name, age in (("demo_shop", "Demo Shop", 400), ("demo_stranger", "Demo Stranger", 0)):
            payee = session.scalar(select(AppUser).where(AppUser.handle == handle))
            if payee is None:
                payee = AppUser(
                    handle=handle,
                    display_name=name,
                    token_hash=hash_token(secrets.token_urlsafe(32)),  # nobody holds this token
                    created_at=now - timedelta(days=age),
                    seeded=True,
                )
                session.add(payee)
                session.flush()
            payees[handle] = payee
        user.created_at = now - timedelta(days=120)
        for i in range(4):
            at = now - timedelta(days=100 - i * 20)
            session.add(
                AppPayment(
                    payer_id=user_id,
                    payee_id=payees["demo_shop"].id,
                    amount=Decimal("20.00"),
                    status="captured",
                    device_id=body.device_id,
                    ip_hash=ip_hash,
                    created_at=at,
                    captured_at=at,
                    seeded=True,
                )
            )
    return {"status": "ready", "regular_payee": "demo_shop", "new_payee": "demo_stranger"}


@router.post("/app/payments")
def create_payment(body: PaymentBody, request: Request, user_id: int = Depends(current_payer)) -> dict[str, Any]:
    """Score the attempt, seal the decision, then act on the band. No money moves unless it is cleared."""
    _ring_or_503()
    settings = get_settings()
    amount = parse_amount(body.amount)
    if not DEVICE_ID.fullmatch(body.device_id):
        raise HTTPException(status_code=422, detail="bad device id")
    handle = body.payee_handle.strip().lower()
    now = clock()
    ip_hash = ip_digest(client_ip(request))
    simulated = sanitize_simulated(body.simulated) if settings.simulation_enabled else {}
    # AI job 1: read the reference for scam language the keyword list misses. Network call, so it runs
    # before the database transaction. It can only add a signal.
    fast_llm = getattr(request.app.state, "llm_fast", None)
    ref_read = read_reference(fast_llm, body.reference, allow_call=fast_llm is None or reference_ai_limit.allow())
    with db.session_scope() as session:
        payer = session.get(AppUser, user_id)
        payee = session.scalar(select(AppUser).where(AppUser.handle == handle))
        assert payer is not None
        if payee is None:
            raise HTTPException(status_code=404, detail="no such payee")
        if payee.id == payer.id:
            raise HTTPException(status_code=422, detail="you can't pay yourself")
        recent = session.scalar(
            select(func.count(AppPayment.id)).where(
                AppPayment.payer_id == payer.id, AppPayment.created_at >= now - timedelta(hours=1)
            )
        )
        if (recent or 0) >= ATTEMPTS_PER_HOUR:
            raise HTTPException(status_code=429, detail="too many payment attempts this hour")

        fp = body.fingerprint.model_dump()
        evidence = build_evidence(
            session,
            payer,
            payee,
            amount=amount,
            reference=body.reference,
            payee_name_typed=body.payee_name,
            device_id=body.device_id,
            ip_hash=ip_hash,
            fp=fp,
            behaviour=body.behaviour.model_dump(),
            simulated=simulated,
            now=now,
            high_value_usd=settings.high_value_usd,
        )
        evidence["ai_reference_read"] = {"status": ref_read["status"], **ref_read["values"]}
        if ref_read["flagged"]:
            evidence["reference_flagged_by_ai"] = True
        decision = decide(evidence)
        action = decision["action"]
        status = {
            "allow": "scored",
            "step_up": "awaiting_confirmation",
            "warn_and_delay": "delayed",
            "hold_review": "held",
            "block": "blocked",
        }[action]
        client = {**body.behaviour.model_dump(), "fp_hash": fingerprint_hash(fp)}
        payment = AppPayment(
            payer_id=payer.id,
            payee_id=payee.id,
            amount=amount,
            currency="USD",
            reference=body.reference.strip(),
            status=status,
            device_id=body.device_id,
            ip_hash=ip_hash,
            client=client,
            release_at=now + timedelta(minutes=settings.step_up_delay_minutes) if action == "warn_and_delay" else None,
            created_at=now,
        )
        session.add(payment)
        session.flush()
        evidence["txn_id"] = payment.id
        sealed = service.seal_decision(session, payment.id, decision, evidence, now)
        add_event(
            session,
            payment.id,
            "system",
            "scored",
            {"score": decision["score"], "band": decision["band"], "action": action, "decision_id": sealed.id},
        )
        payment_id = payment.id
        summary = _decision_summary(decision, evidence.get("simulated_fields", []))
        summary["ai_reference_read"] = evidence["ai_reference_read"]
        release_at = payment.release_at

    response: dict[str, Any] = {
        "payment_id": payment_id,
        "status": status,
        "action": action,
        "message": MESSAGES[action],
        "release_at": release_at.isoformat() if release_at else None,
    }
    if settings.simulation_enabled:  # a real service wouldn't show attackers the score
        response["decision"] = summary
    if action == "allow":
        response.update(_start_order(request, payment_id))
        response["status"] = "awaiting_approval"
    return response


@router.post("/app/payments/{payment_id}/confirm")
def confirm_payment(
    payment_id: int, body: ConfirmBody, request: Request, user_id: int = Depends(current_payer)
) -> dict[str, Any]:
    """Step-up: type the payee's handle (confirmation of payee). For a delayed payment, only after the delay."""
    with db.session_scope() as session:
        p = session.get(AppPayment, payment_id)
        if p is None or p.payer_id != user_id:
            raise HTTPException(status_code=404, detail="payment not found")
        if p.status not in ("awaiting_confirmation", "delayed"):
            raise HTTPException(status_code=409, detail="this payment doesn't need confirming")
        payee = session.get(AppUser, p.payee_id)
        assert payee is not None
        if body.typed_handle.strip().lower() != payee.handle:
            add_event(session, p.id, "payer", "confirmation_failed")
            session.commit()
            raise HTTPException(status_code=422, detail="that is not the payee's handle")
        now = clock()
        if p.status == "delayed" and p.release_at and now < p.release_at:
            wait = int((p.release_at - now).total_seconds()) + 1
            raise HTTPException(status_code=409, detail=f"this payment is delayed for another {wait} seconds")
        p.status = "scored"
        add_event(session, p.id, "payer", "confirmed_payee")
    result = _start_order(request, payment_id)
    return {"status": "awaiting_approval", **result}


@router.post("/app/payments/{payment_id}/capture")
def capture_payment(payment_id: int, request: Request, user_id: int = Depends(current_payer)) -> dict[str, Any]:
    """After the payer approves at PayPal: re-check the order is ours and unchanged, then capture it."""
    with db.session_scope() as session:
        p = session.get(AppPayment, payment_id)
        if p is None or p.payer_id != user_id:
            raise HTTPException(status_code=404, detail="payment not found")
        if p.status == "captured":
            return {"status": "captured", "already": True}
        if p.status != "awaiting_approval" or not p.paypal_order_id:
            raise HTTPException(status_code=409, detail="payment is not waiting for approval")
        order_id, expected = p.paypal_order_id, f"{p.amount:.2f}"
    paypal = _paypal(request)
    try:
        order = paypal.get_order(order_id)
    except PAYPAL_DOWN:
        raise HTTPException(status_code=502, detail="could not read the order from PayPal") from None
    unit = (order.get("purchase_units") or [{}])[0]
    amount = unit.get("amount") or {}
    if str(unit.get("custom_id")) != str(payment_id) or amount.get("value") != expected:
        raise HTTPException(status_code=409, detail="the PayPal order doesn't match this payment")
    if order.get("status") != "APPROVED":
        raise HTTPException(status_code=409, detail="not approved at PayPal yet")
    try:
        captured = paypal.capture_order(order_id, request_id=f"capture-{payment_id}")
    except PAYPAL_DOWN as exc:
        with db.session_scope() as session:
            add_event(session, payment_id, "paypal", "capture_failed", {"error": str(exc)[:200]})
        raise HTTPException(status_code=502, detail="PayPal could not capture the payment") from None
    with db.session_scope() as session:
        p = session.get(AppPayment, payment_id)
        assert p is not None
        if captured["status"] != "COMPLETED" or captured["amount"] != expected:
            p.status = "failed"
            add_event(session, payment_id, "paypal", "capture_not_completed", {"status": captured["status"]})
            raise_after = True
        else:
            p.status, p.paypal_capture_id, p.captured_at = "captured", captured["capture_id"], clock()
            add_event(session, payment_id, "paypal", "captured", {"capture_id": captured["capture_id"]})
            add_event(session, payment_id, "system", "payee_credited_in_ledger", {"simulated": True})
            raise_after = False
    if raise_after:
        raise HTTPException(status_code=502, detail="the capture did not complete")
    return {"status": "captured", "capture_id": captured["capture_id"], "payee_credit": "ledger entry (simulated)"}


@router.get("/app/payments/{payment_id}/approve-link")
def approve_link(payment_id: int, request: Request, user_id: int = Depends(current_payer)) -> dict[str, str]:
    """The PayPal approval link for a payment waiting for approval, read back from PayPal."""
    with db.session_scope() as session:
        p = session.get(AppPayment, payment_id)
        if p is None or p.payer_id != user_id:
            raise HTTPException(status_code=404, detail="payment not found")
        retry = p.status == "scored"  # cleared to pay, but PayPal failed when the order was created
        if not retry and (p.status != "awaiting_approval" or not p.paypal_order_id):
            raise HTTPException(status_code=409, detail="payment is not waiting for approval")
        order_id = p.paypal_order_id
    if retry:
        return {"approve_url": _start_order(request, payment_id)["approve_url"]}
    try:
        order = _paypal(request).get_order(order_id)
    except PAYPAL_DOWN:
        raise HTTPException(status_code=502, detail="could not read the order from PayPal") from None
    links = {link.get("rel"): link.get("href") for link in order.get("links", []) if isinstance(link, dict)}
    href = str(links.get("payer-action") or links.get("approve") or "")
    if not href.startswith("https://"):
        raise HTTPException(status_code=409, detail="PayPal has no approval link for this order any more")
    return {"approve_url": href}


@router.post("/app/payments/{payment_id}/cancel")
def cancel_payment(payment_id: int, user_id: int = Depends(current_payer)) -> dict[str, str]:
    with db.session_scope() as session:
        p = session.get(AppPayment, payment_id)
        if p is None or p.payer_id != user_id:
            raise HTTPException(status_code=404, detail="payment not found")
        if p.status not in ("awaiting_approval", "awaiting_confirmation", "delayed"):
            raise HTTPException(status_code=409, detail="this payment can't be cancelled now")
        p.status = "cancelled"
        add_event(session, p.id, "payer", "cancelled")
    return {"status": "cancelled"}


@router.get("/app/payments/{payment_id}")
def get_payment(payment_id: int, user_id: int = Depends(current_payer)) -> dict[str, Any]:
    with db.session_scope() as session:
        p = session.get(AppPayment, payment_id)
        if p is None or p.payer_id != user_id:
            raise HTTPException(status_code=404, detail="payment not found")
        out = _payment_out(session, p, with_events=True)
        complaint = session.scalar(select(AppComplaint).where(AppComplaint.payment_id == p.id))
        out["complaint"] = (
            {"id": complaint.id, "status": complaint.status, "claim": complaint.claim} if complaint else None
        )
        return out


@router.post("/app/payments/{payment_id}/complaint")
def file_complaint(
    payment_id: int, body: ComplaintBody, request: Request, user_id: int = Depends(current_payer)
) -> dict[str, Any]:
    """The payer says a captured payment was unauthorised or a scam. The AI reads the text into yes/no claims,
    code compares everything with the sealed snapshot from the moment of payment, and a human decides."""
    _ring_or_503()
    now = clock()
    with db.session_scope() as session:
        p = session.get(AppPayment, payment_id)
        if p is None or p.payer_id != user_id:
            raise HTTPException(status_code=404, detail="payment not found")
        if p.status != "captured":
            raise HTTPException(status_code=409, detail="only a completed payment can be disputed")
        if session.scalar(select(AppComplaint.id).where(AppComplaint.payment_id == p.id)):
            raise HTTPException(status_code=409, detail="this payment already has a complaint")
        today = session.scalar(
            select(func.count(AppComplaint.id)).where(
                AppComplaint.payer_id == user_id, AppComplaint.created_at >= now - timedelta(days=1)
            )
        )
        if (today or 0) >= COMPLAINTS_PER_DAY:
            raise HTTPException(status_code=429, detail="too many complaints today")
        row = service.decision_for(session, p.id)
        if row is None:
            raise HTTPException(status_code=409, detail="no recorded decision for this payment")
        try:
            snapshot = service.open_decision(row)
        except SnapshotError:
            raise HTTPException(status_code=500, detail="the stored decision could not be read") from None
        payer_total = session.scalar(
            select(func.count(AppPayment.id)).where(AppPayment.payer_id == user_id, AppPayment.status == "captured")
        )
        past = list(session.scalars(select(AppComplaint).where(AppComplaint.payer_id == user_id)))
        rejected = sum(1 for c in past if c.status == "refund_declined")
        text = body.text.strip()
    claims = extract_claims(request.app.state.llm, text)  # network call, outside the transaction
    values = claims["values"]
    result = consistency(
        {
            "claim": body.claim,
            "denies_account_changes": values.get("denies_account_changes") or None,
            "complainant_dispute_rate": len(past) / max(1, payer_total or 0),
            "complainant_rejected_disputes": rejected,
        },
        snapshot,
    )
    status = {
        "fast_track_refund": "fast_tracked",
        "standard_review": "in_review",
        "manual_review_possible_first_party_abuse": "manual_review",
    }[result["outcome"]]
    # AI job 3: the AI's reading can move the case up the reviewer's queue (never down, never decide).
    priority = queue_priority(result["consistency_score"], result["outcome"], values)
    with db.session_scope() as session:
        complaint = AppComplaint(
            payment_id=payment_id,
            payer_id=user_id,
            claim=body.claim,
            text=text,
            claims={**values, "_status": claims["status"], "_prompt": "claims-v2", "_priority": priority},
            result=result,
            status=status,
            created_at=now,
        )
        session.add(complaint)
        session.flush()
        add_event(
            session,
            payment_id,
            "payer",
            "complaint_filed",
            {
                "claim": body.claim,
                "consistency": result["consistency_score"],
                "outcome": result["outcome"],
                "queue_priority": priority["priority"],
                "ai_priority_bonus": priority["ai_bonus"],
            },
        )
        complaint_id = complaint.id
    return {
        "complaint_id": complaint_id,
        "status": status,
        "message": (
            "Thanks. Your case has been prioritised for a reviewer."
            if status == "fast_tracked"
            else "Thanks. A reviewer will look at your case."
        ),
    }


# --------------------------------------------------------------------------- reviewer (owner key)


def _case(session: Session, p: AppPayment) -> dict[str, Any]:
    out = _payment_out(session, p, with_events=True)
    payer = session.get(AppUser, p.payer_id)
    out["payer"] = payer.handle if payer else None
    row = service.decision_for(session, p.id)
    if row is not None:
        try:
            snap = service.open_decision(row)
            out["decision"] = {**_decision_summary(snap["decision"], snap["evidence"].get("simulated_fields", []))}
            out["decision"]["reductions"] = [r["name"] for r in snap["decision"]["reductions_applied"]]
            out["decision"]["sealed_at"] = snap["sealed_at"]
            out["decision"]["evidence_note"] = (
                "Device, network and behaviour evidence was reported by the payer's browser and can be "
                "staged. Treat a high consistency score as a reason to look first, not as proof."
            )
        except SnapshotError:
            out["decision"] = {"error": "could not open (wrong key or altered record)"}
    complaint = session.scalar(select(AppComplaint).where(AppComplaint.payment_id == p.id))
    if complaint:
        out["complaint"] = {
            "id": complaint.id,
            "status": complaint.status,
            "claim": complaint.claim,
            "text": complaint.text,  # untrusted: show as text only
            "ai_read_claims": {k: v for k, v in complaint.claims.items() if not k.startswith("_")},
            "ai_status": complaint.claims.get("_status"),
            "queue_priority": complaint.claims.get("_priority"),
            "consistency": complaint.result,
            "filed_at": complaint.created_at.isoformat(),
        }
        if p.refunded_at:
            out["complaint"]["time_to_return_seconds"] = int((p.refunded_at - complaint.created_at).total_seconds())
    return out


@router.get("/review/queue", dependencies=[Depends(require_owner)])
def review_queue() -> dict[str, Any]:
    with db.session_scope() as session:
        held = session.scalars(select(AppPayment).where(AppPayment.status == "held").order_by(AppPayment.id)).all()
        open_complaints = session.scalars(
            select(AppComplaint)
            .where(AppComplaint.status.in_(("fast_tracked", "in_review", "manual_review")))
            .order_by(AppComplaint.id)
        ).all()
        recent = session.scalars(select(AppPayment).order_by(AppPayment.id.desc()).limit(25)).all()

        def rank(c: AppComplaint) -> tuple[int, int]:
            pr = (c.claims.get("_priority") or {}).get("priority", c.result.get("consistency_score", 0))
            return (-int(pr), c.id)  # highest priority first, then oldest

        return {
            "held_payments": [_payment_out(session, p) for p in held],
            "open_complaints": [
                {
                    "complaint_id": c.id,
                    "payment_id": c.payment_id,
                    "status": c.status,
                    "claim": c.claim,
                    "consistency_score": c.result.get("consistency_score"),
                    "queue_priority": (c.claims.get("_priority") or {}).get("priority"),
                    "ai_priority_bonus": (c.claims.get("_priority") or {}).get("ai_bonus", 0),
                    "ai_priority_reasons": (c.claims.get("_priority") or {}).get("ai_reasons", []),
                    "filed_at": c.created_at.isoformat(),
                }
                for c in sorted(open_complaints, key=rank)
            ],
            "recent_payments": [_payment_out(session, p) for p in recent],
        }


@router.get("/review/payments/{payment_id}", dependencies=[Depends(require_owner)])
def review_case(payment_id: int) -> dict[str, Any]:
    _ring_or_503()
    with db.session_scope() as session:
        p = session.get(AppPayment, payment_id)
        if p is None:
            raise HTTPException(status_code=404, detail="payment not found")
        return _case(session, p)


@router.post("/review/payments/{payment_id}/brief", dependencies=[Depends(require_owner)])
def review_brief(payment_id: int, request: Request) -> dict[str, Any]:
    """AI job 2: a short brief written from code-built facts and checked by code. A brief with a number that
    isn't in the facts, or wording that decides the case, is replaced by a plain template."""
    _ring_or_503()
    with db.session_scope() as session:
        p = session.get(AppPayment, payment_id)
        if p is None:
            raise HTTPException(status_code=404, detail="payment not found")
        case = _case(session, p)
    return write_brief(request.app.state.llm, case)


@router.post("/review/payments/{payment_id}/release", dependencies=[Depends(require_owner)])
def release_held(payment_id: int, request: Request) -> dict[str, Any]:
    """A reviewer clears a held payment. The payer still has to approve it at PayPal."""
    with db.session_scope() as session:
        p = session.get(AppPayment, payment_id)
        if p is None:
            raise HTTPException(status_code=404, detail="payment not found")
        if p.status != "held":
            raise HTTPException(status_code=409, detail="payment is not held")
        p.status = "scored"
        add_event(session, p.id, "reviewer", "released")
    result = _start_order(request, payment_id)
    return {"status": "awaiting_approval", "order_id": result["order_id"]}


@router.post("/review/payments/{payment_id}/decline", dependencies=[Depends(require_owner)])
def decline_held(payment_id: int) -> dict[str, str]:
    with db.session_scope() as session:
        p = session.get(AppPayment, payment_id)
        if p is None:
            raise HTTPException(status_code=404, detail="payment not found")
        if p.status != "held":
            raise HTTPException(status_code=409, detail="payment is not held")
        p.status = "declined"
        add_event(session, p.id, "reviewer", "declined")
    return {"status": "declined"}


@router.post("/review/complaints/{complaint_id}/approve", dependencies=[Depends(require_owner)])
def approve_refund(complaint_id: int, body: ApproveBody, request: Request) -> dict[str, Any]:
    """A reviewer approves the refund. The amount must be typed to confirm. The money goes back to the
    original payer through PayPal's refund API (the only place PayPal returns it to)."""
    with db.session_scope() as session:
        c = session.get(AppComplaint, complaint_id)
        if c is None:
            raise HTTPException(status_code=404, detail="complaint not found")
        p = session.get(AppPayment, c.payment_id)
        assert p is not None
        if c.status not in ("fast_tracked", "in_review", "manual_review", "refund_approved"):
            raise HTTPException(status_code=409, detail="this complaint is closed")
        if p.status not in ("captured", "refunded") or not p.paypal_capture_id:
            raise HTTPException(status_code=409, detail="there is no captured payment to refund")
        amount, currency, capture_id, payment_id = f"{p.amount:.2f}", p.currency, p.paypal_capture_id, p.id
        if body.confirm_amount.strip() != amount:
            raise HTTPException(status_code=422, detail="the typed amount doesn't match the payment")
        c.status = "refund_approved"  # confirmed fraud from here on, even if the PayPal call needs a retry
        add_event(session, payment_id, "reviewer", "refund_approved", {"complaint_id": complaint_id})
    try:
        refund = _paypal(request).refund_capture(
            capture_id, amount, currency, "Refund approved by Incident Shield reviewer", f"refund-{complaint_id}"
        )
    except PAYPAL_DOWN as exc:
        with db.session_scope() as session:
            add_event(session, payment_id, "paypal", "refund_failed", {"error": str(exc)[:200]})
        raise HTTPException(status_code=502, detail="PayPal could not refund; approve again to retry") from None
    now = clock()
    with db.session_scope() as session:
        c = session.get(AppComplaint, complaint_id)
        p = session.get(AppPayment, payment_id)
        assert c is not None and p is not None
        c.status, c.decided_at = "refunded", now
        p.status, p.paypal_refund_id, p.refunded_at = "refunded", refund["id"], now
        add_event(session, payment_id, "paypal", "refunded", {"refund_id": refund["id"], "status": refund["status"]})
        seconds = int((now - c.created_at).total_seconds())
    return {"status": "refunded", "refund_id": refund["id"], "seconds_from_complaint_to_refund": seconds}


@router.post("/review/complaints/{complaint_id}/decline", dependencies=[Depends(require_owner)])
def decline_refund(complaint_id: int) -> dict[str, str]:
    with db.session_scope() as session:
        c = session.get(AppComplaint, complaint_id)
        if c is None:
            raise HTTPException(status_code=404, detail="complaint not found")
        if c.status not in ("fast_tracked", "in_review", "manual_review"):
            raise HTTPException(status_code=409, detail="this complaint is closed")
        c.status, c.decided_at = "refund_declined", clock()
        add_event(session, c.payment_id, "reviewer", "refund_declined", {"complaint_id": complaint_id})
    return {"status": "refund_declined"}


# --------------------------------------------------------------------------- risk records (owner key)


class VerifyBody(BaseModel):
    checkpoint: dict[str, Any] | None = None


@router.get("/risk/checkpoint", dependencies=[Depends(require_owner)])
def risk_checkpoint() -> dict[str, Any]:
    """Save this somewhere the database can't reach. It is what detects records removed from the end."""
    _ring_or_503()
    with db.session_scope() as session:
        return service.checkpoint(session)


@router.post("/risk/verify", dependencies=[Depends(require_owner)])
def risk_verify(body: VerifyBody) -> dict[str, Any]:
    _ring_or_503()
    with db.session_scope() as session:
        return service.verify(session, body.checkpoint)


def _opened_snapshots(session: Session) -> list[dict[str, Any]]:
    out = []
    for row in service.all_rows(session):
        try:
            out.append(service.open_decision(row))
        except SnapshotError:
            continue
    return out


@router.post("/risk/rescore/{recipient_handle}", dependencies=[Depends(require_owner)])
def risk_rescore(recipient_handle: str) -> dict[str, Any]:
    """A recipient was confirmed as fraud: rescore everyone who paid them, and list likely victims."""
    _ring_or_503()
    with db.session_scope() as session:
        alerts = rescore_payers(_opened_snapshots(session), recipient_handle.lower())
    return {"recipient": recipient_handle.lower(), "likely_victims_to_alert": alerts}


@router.get("/risk/gap/{payment_id}", dependencies=[Depends(require_owner)])
def risk_gap(payment_id: int, typology: str = Query(max_length=40)) -> dict[str, Any]:
    """How a confirmed-fraud payment got through: what fired, what was missing, what nearly fired."""
    _ring_or_503()
    with db.session_scope() as session:
        row = service.decision_for(session, payment_id)
        if row is None:
            raise HTTPException(status_code=404, detail="no decision for that payment")
        return gap_report(service.open_decision(row), typology)


@router.get("/risk/scam-library", dependencies=[Depends(require_owner)])
def risk_scam_library() -> dict[str, Any]:
    """Confirmed cases grouped by type. A case is confirmed when a reviewer approved the refund; a payment
    whose complaint was declined counts as a false alarm for the engine."""
    _ring_or_503()
    cases: list[dict[str, Any]] = []
    with db.session_scope() as session:
        for c in session.scalars(select(AppComplaint).where(AppComplaint.status.in_(("refunded", "refund_declined")))):
            row = service.decision_for(session, c.payment_id)
            if row is None:
                continue
            snap = service.open_decision(row)
            if c.status == "refunded":
                typology = snap["decision"]["typology"] or ("authorised_scam" if c.claim == "scam" else "takeover")
                cases.append({"snapshot": snap, "outcome": "fraud", "typology": typology})
            else:
                cases.append({"snapshot": snap, "outcome": "legitimate", "typology": None})
    return scam_library(cases)
