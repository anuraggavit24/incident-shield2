"""Sealing and reading decisions in the database. Keys come from the environment, never from the database."""

from __future__ import annotations

import os
from datetime import datetime
from typing import Any

from sqlalchemy import select, text
from sqlalchemy.orm import Session

from ..models import RiskDecision
from .snapshot import GENESIS_HASH, SnapshotError, load_keyring, make_checkpoint, open_snapshot, seal, verify_chain

CHAIN_LOCK = 7340011  # one transaction at a time may extend the chain, so it can't fork

_ring: dict[str, Any] | None = None
_ring_checked = False


def keyring() -> dict[str, Any] | None:
    """The configured keys, or None when RISK_* variables are missing (the payment app then answers 503)."""
    global _ring, _ring_checked
    if not _ring_checked:
        try:
            _ring = load_keyring(os.environ)
        except SnapshotError:
            _ring = None
        _ring_checked = True
    return _ring


def reset_keyring_cache() -> None:  # for tests
    global _ring, _ring_checked
    _ring, _ring_checked = None, False


def _record(row: RiskDecision) -> dict[str, str]:
    return {
        "key_id": row.key_id,
        "prev_hash": row.prev_hash,
        "nonce": row.nonce,
        "ciphertext": row.ciphertext,
        "record_hash": row.record_hash,
        "signature": row.signature,
    }


def seal_decision(
    session: Session, payment_id: int, decision: dict[str, Any], evidence: dict[str, Any], now: datetime
) -> RiskDecision:
    """Append one sealed decision to the chain. Must run in the transaction that also stores the payment."""
    ring = keyring()
    if ring is None:
        raise SnapshotError("risk keys are not configured")
    active = ring["active"]
    session.execute(text("SELECT pg_advisory_xact_lock(:k)"), {"k": CHAIN_LOCK})
    last = session.scalar(select(RiskDecision).order_by(RiskDecision.id.desc()).limit(1))
    prev = last.record_hash if last else GENESIS_HASH
    sealed = seal(decision, evidence, prev, ring["enc"][active], ring["sign"][active], now, key_id=active)
    row = RiskDecision(payment_id=payment_id, **sealed)
    session.add(row)
    session.flush()
    return row


def open_decision(row: RiskDecision) -> dict[str, Any]:
    ring = keyring()
    if ring is None:
        raise SnapshotError("risk keys are not configured")
    snap = open_snapshot(_record(row), ring["enc"])
    # The payment id is inside the encrypted, signed evidence. If the row now points at another payment,
    # someone moved it: refuse to treat it as that payment's decision.
    if snap["evidence"].get("txn_id") != row.payment_id:
        raise SnapshotError("this decision was sealed for a different payment")
    return snap


def decision_for(session: Session, payment_id: int) -> RiskDecision | None:
    return session.scalar(select(RiskDecision).where(RiskDecision.payment_id == payment_id))


def all_rows(session: Session) -> list[RiskDecision]:
    return list(session.scalars(select(RiskDecision).order_by(RiskDecision.id)))


def checkpoint(session: Session) -> dict[str, Any]:
    """A signed (count, head hash) the owner should store OUTSIDE the database."""
    ring = keyring()
    if ring is None:
        raise SnapshotError("risk keys are not configured")
    active = ring["active"]
    return make_checkpoint([_record(r) for r in all_rows(session)], ring["sign"][active], key_id=active)


def verify(session: Session, saved_checkpoint: dict[str, Any] | None) -> dict[str, Any]:
    ring = keyring()
    if ring is None:
        raise SnapshotError("risk keys are not configured")
    rows = all_rows(session)
    records = [_record(r) for r in rows]
    ok, bad = verify_chain(records, ring["sign"], saved_checkpoint)
    if ok:  # the chain is intact; now check each record still belongs to the payment it was sealed for
        for index, row in enumerate(rows):
            try:
                open_decision(row)
            except SnapshotError:
                return {
                    "ok": False,
                    "records": len(records),
                    "first_bad_index": index,
                    "checkpoint_used": saved_checkpoint is not None,
                    "note": "a record is attached to a different payment than it was sealed for, or can't be opened",
                }
    return {
        "ok": ok,
        "records": len(records),
        "first_bad_index": bad,
        "checkpoint_used": saved_checkpoint is not None,
        "note": (
            "records cut off the end of the chain can only be detected with a saved checkpoint"
            if saved_checkpoint is None
            else "checked against the saved checkpoint"
        ),
    }
