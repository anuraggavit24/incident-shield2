"""A tamper-evident record of reviewer and owner actions, and of who opened which case.

Each row is chained to the one before (SHA-256 over the previous hash and this row's content) and signed
(HMAC-SHA256 with the active signing key). verify() recomputes every link. Like the decision chain, a chain
alone can't show rows cut off the END; the count is included in /risk/checkpoint for that.
Whoever controls the app host holds the signing key and could rewrite the whole chain: see THREAT_MODEL.md.
"""

from __future__ import annotations

import hashlib
import hmac
import json
from datetime import datetime
from typing import Any

from sqlalchemy import func, select, text
from sqlalchemy.orm import Session

from .models import AuditLog
from .risk import service
from .risk.snapshot import GENESIS_HASH, SnapshotError

AUDIT_LOCK = service.CHAIN_LOCK + 2


def _body(at: str, actor: str, action: str, subject: str, details: dict[str, Any]) -> bytes:
    payload = {"at": at, "actor": actor, "action": action, "subject": subject, "details": details}
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str).encode()


def record(session: Session, actor: str, action: str, subject: str, details: dict[str, Any], now: datetime) -> None:
    """Append one row. Runs in the caller's transaction, so the action and its record commit together."""
    ring = service.keyring()
    if ring is None:
        raise SnapshotError("risk keys are not configured")
    details = json.loads(json.dumps(details, default=str))  # exactly what will be stored and re-read
    session.execute(text("SELECT pg_advisory_xact_lock(:k)"), {"k": AUDIT_LOCK})
    last = session.scalar(select(AuditLog).order_by(AuditLog.id.desc()).limit(1))
    prev = last.record_hash if last else GENESIS_HASH
    at = now.isoformat()
    record_hash = hashlib.sha256(prev.encode() + _body(at, actor, action, subject, details)).hexdigest()
    active = ring["active"]
    session.add(
        AuditLog(
            at=at,
            actor=actor,
            action=action,
            subject=subject,
            details=details,
            key_id=active,
            prev_hash=prev,
            record_hash=record_hash,
            signature=hmac.new(ring["sign"][active], record_hash.encode(), hashlib.sha256).hexdigest(),
        )
    )
    session.flush()


def verify(session: Session, expected_count: int | None = None) -> dict[str, Any]:
    ring = service.keyring()
    if ring is None:
        raise SnapshotError("risk keys are not configured")
    prev, count = GENESIS_HASH, 0
    for row in session.scalars(select(AuditLog).order_by(AuditLog.id)):
        key = ring["sign"].get(row.key_id)
        expected = hashlib.sha256(
            row.prev_hash.encode() + _body(row.at, row.actor, row.action, row.subject, row.details)
        ).hexdigest()
        good = (
            key is not None
            and row.prev_hash == prev
            and row.record_hash == expected
            and hmac.compare_digest(hmac.new(key, row.record_hash.encode(), hashlib.sha256).hexdigest(), row.signature)
        )
        if not good:
            return {"ok": False, "records": count, "first_bad_index": count}
        prev, count = row.record_hash, count + 1
    if expected_count is not None and count < expected_count:
        return {"ok": False, "records": count, "first_bad_index": count, "note": "fewer rows than the checkpoint"}
    return {"ok": True, "records": count, "first_bad_index": None}


def count(session: Session) -> int:
    return session.scalar(select(func.count(AuditLog.id))) or 0
