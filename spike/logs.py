"""JSON-lines logging for spike evidence. Secrets and card data are redacted."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import Any

from .config import LOG_DIR

SENSITIVE_KEYS = frozenset(
    {"authorization", "access_token", "client_secret", "number", "security_code", "cvv", "expiry"}
)


def utcnow() -> datetime:
    return datetime.now(UTC)


def iso(dt: datetime) -> str:
    return dt.isoformat()


def redact(obj: Any) -> Any:
    if isinstance(obj, dict):
        return {k: ("[REDACTED]" if str(k).lower() in SENSITIVE_KEYS else redact(v)) for k, v in obj.items()}
    if isinstance(obj, list):
        return [redact(item) for item in obj]
    return obj


def append_jsonl(name: str, record: dict[str, Any]) -> None:
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    line = json.dumps({"logged_at": iso(utcnow()), **redact(record)}, default=str, ensure_ascii=False)
    with (LOG_DIR / f"{name}.jsonl").open("a", encoding="utf-8") as fh:
        fh.write(line + "\n")


def read_jsonl(name: str) -> list[dict[str, Any]]:
    path = LOG_DIR / f"{name}.jsonl"
    if not path.exists():
        return []
    records: list[dict[str, Any]] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            records.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return records


def parse_paypal_time(value: str | None) -> datetime | None:
    """Parse PayPal timestamps such as 2026-11-07T06:30:00Z or 2026-11-07T06:30:00.123Z."""
    if not value:
        return None
    try:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=UTC)
