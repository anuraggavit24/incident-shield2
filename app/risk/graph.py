"""The payments graph: accounts, devices and networks, and how they connect.

Nodes are accounts, device ids and network (IP-hash) ids. Edges are "paid" (account to account, completed
payments) and "used" (account to device or network, any attempt). Built from this app's own ledger with
read-only queries; nothing here writes.

Two uses:
- fraud_distances(): how many steps each account is from a confirmed-fraud account, where a step is a
  completed payment OR a shared device. This feeds the engine's recipient-linked-to-fraud signal, so a fresh
  mule account run from the same device as a confirmed one is caught before anyone has paid it.
- neighbourhood(): what a reviewer sees for one account: who it paid, who paid it, which devices and networks
  it shares with whom, and the findings below.

Fan-out and device-ring size are also scored by the engine (signals RC8 and RC9), not only shown.

Limits: device ids and networks are reported by the browser, so a careful attacker can avoid sharing them;
shared networks alone (a household, an office, a campus) are shown but never count as a fraud link. A shared
device does link accounts, which catches rings and also catches households: the owner can mark a device as
legitimately shared (shared_devices) and it then links nobody.
"""

from __future__ import annotations

import threading
from collections import defaultdict, deque
from datetime import datetime, timedelta
from typing import Any

from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from ..models import AppComplaint, AppPayment, AppUser, SharedDevice

COMPLETED = "captured"
CONFIRMED_FRAUD = ("refund_approved", "refunded")
WINDOW_DAYS = 30  # payments older than this are not in the graph
DEVICE_LINK_DAYS = 14  # a shared device links accounts only if each used it this recently
FAN_IN_SENDERS = 5  # distinct payers in 7 days
FAN_OUT_PAYEES = 4  # distinct payees paid within an hour of receiving money
RING_SIZE = 3  # accounts tied together by shared devices


def confirmed_fraud_accounts(session: Session) -> set[int]:
    """Accounts that received a payment a reviewer confirmed as fraud (refund approved), unless the owner has
    since cleared the flag (complaints filed before the clearing no longer count)."""
    rows = session.execute(
        select(AppPayment.payee_id)
        .join(AppComplaint, AppComplaint.payment_id == AppPayment.id)
        .join(AppUser, AppUser.id == AppPayment.payee_id)
        .where(
            AppComplaint.status.in_(CONFIRMED_FRAUD),
            or_(AppUser.fraud_cleared_at.is_(None), AppComplaint.created_at > AppUser.fraud_cleared_at),
        )
    ).all()
    return {r[0] for r in rows}


_cache: dict[str, Any] = {"key": None, "value": None}
_cache_lock = threading.Lock()


def _snapshot(
    session: Session, now: datetime
) -> tuple[list[Any], dict[int, set[int]], dict[str, set[int]], dict[str, set[int]]]:
    """(rows, account links, accounts per device, accounts per network) for the window.

    Rebuilt only when the ledger changed: the cache key is a cheap aggregate (row count, newest id, number
    completed, allowlist size, the day). One process only; a second worker would keep its own copy."""
    since = now - timedelta(days=WINDOW_DAYS)
    key = (
        *session.execute(
            select(
                func.count(AppPayment.id),
                func.max(AppPayment.id),
                func.count(AppPayment.captured_at),
            ).where(AppPayment.created_at >= since, AppPayment.seeded.is_(False))
        ).one(),
        session.scalar(select(func.count(SharedDevice.device_id))),
        now.date().isoformat(),
    )
    with _cache_lock:
        if _cache["key"] == key:
            return _cache["value"]
    rows = list(
        session.execute(
            select(
                AppPayment.payer_id,
                AppPayment.payee_id,
                AppPayment.device_id,
                AppPayment.ip_hash,
                AppPayment.status,
                AppPayment.amount,
                AppPayment.created_at,
            ).where(AppPayment.created_at >= since, AppPayment.seeded.is_(False))
        ).all()
    )
    allowed = set(session.scalars(select(SharedDevice.device_id)))
    device_since = now - timedelta(days=DEVICE_LINK_DAYS)
    paid: dict[int, set[int]] = defaultdict(set)
    by_device: dict[str, set[int]] = defaultdict(set)
    by_ip: dict[str, set[int]] = defaultdict(set)
    for payer, payee, device, ip, status, _, at in rows:
        if status == COMPLETED:
            paid[payer].add(payee)
            paid[payee].add(payer)
        # Old device use counts for nothing: a link needs both accounts on the device recently. Devices the
        # owner marked as legitimately shared (household, office) never link anyone.
        if device and device not in allowed and at >= device_since:
            by_device[device].add(payer)
        if ip:
            by_ip[ip].add(payer)
    for accounts in by_device.values():  # a shared device links every account that used it
        for a in accounts:
            paid[a] |= accounts - {a}
    value = (rows, paid, by_device, by_ip)
    with _cache_lock:
        _cache["key"], _cache["value"] = key, value
    return value


def _ring(account_id: int, by_device: dict[str, set[int]]) -> set[int]:
    """Every account reachable from this one through shared devices only."""
    ring, queue = {account_id}, deque([account_id])
    while queue:
        node = queue.popleft()
        for accounts in by_device.values():
            if node in accounts:
                for other in accounts - ring:
                    ring.add(other)
                    queue.append(other)
    return ring


def _fan_out(account_id: int, rows: list[Any]) -> int:
    """Distinct accounts paid within an hour of this account receiving money."""
    received = sorted(at for _, payee, _, _, s, _, at in rows if payee == account_id and s == COMPLETED)
    return len(
        {
            payee
            for payer, payee, _, _, s, _, at in rows
            if payer == account_id
            and s == COMPLETED
            and any(timedelta(0) <= at - r <= timedelta(hours=1) for r in received)
        }
    )


def account_features(session: Session, account_id: int, now: datetime) -> dict[str, int]:
    """Graph features of one account for the engine: fan-out after receipt, and device-ring size."""
    rows, _, by_device, _ = _snapshot(session, now)
    return {"fan_out_1h": _fan_out(account_id, rows), "device_ring_size": len(_ring(account_id, by_device))}


def fraud_distance(session: Session, account_id: int, fraud: set[int], now: datetime, limit: int = 2) -> int | None:
    """Steps from this account to the nearest confirmed-fraud account (0 = it is one), or None beyond `limit`."""
    if account_id in fraud:
        return 0
    if not fraud:
        return None
    _, links, _, _ = _snapshot(session, now)
    seen, queue = {account_id}, deque([(account_id, 0)])
    while queue:
        node, dist = queue.popleft()
        if dist == limit:
            continue
        for nxt in links[node]:
            if nxt in fraud:
                return dist + 1
            if nxt not in seen:
                seen.add(nxt)
                queue.append((nxt, dist + 1))
    return None


def neighbourhood(session: Session, handle: str, now: datetime) -> dict[str, Any] | None:
    user = session.scalar(select(AppUser).where(AppUser.handle == handle))
    if user is None:
        return None
    rows, _, by_device, by_ip = _snapshot(session, now)
    fraud = confirmed_fraud_accounts(session)
    names = dict(session.execute(select(AppUser.id, AppUser.handle)).all())
    me = user.id
    week = now - timedelta(days=7)

    paid_to: dict[int, list[float]] = defaultdict(list)
    paid_by: dict[int, list[float]] = defaultdict(list)
    for payer, payee, _, _, status, amount, _ in rows:
        if status != COMPLETED:
            continue
        if payer == me:
            paid_to[payee].append(float(amount))
        if payee == me:
            paid_by[payer].append(float(amount))

    my_devices = {d for d, accounts in by_device.items() if me in accounts}
    my_ips = {i for i, accounts in by_ip.items() if me in accounts}
    shared_devices = [
        {"device": d[:8], "accounts": sorted(names[a] for a in by_device[d])}
        for d in sorted(my_devices)
        if len(by_device[d]) > 1
    ]
    shared_networks = [
        {"network": i[:8], "accounts": sorted(names[a] for a in by_ip[i])} for i in sorted(my_ips) if len(by_ip[i]) > 1
    ]
    ring = _ring(me, by_device)
    senders_7d = {p for p, payee, _, _, s, _, at in rows if payee == me and s == COMPLETED and at >= week}
    fan_out = _fan_out(me, rows)

    findings: list[dict[str, Any]] = []
    if me in fraud:
        findings.append({"finding": "confirmed_fraud_account", "detail": "a reviewer approved a refund against it"})
    distance = fraud_distance(session, me, fraud, now)
    if distance not in (None, 0):
        findings.append(
            {"finding": "linked_to_confirmed_fraud", "detail": f"{distance} step(s) away by payment or shared device"}
        )
    if len(senders_7d) >= FAN_IN_SENDERS:
        findings.append({"finding": "fan_in", "detail": f"{len(senders_7d)} different payers in 7 days"})
    if fan_out >= FAN_OUT_PAYEES:
        findings.append(
            {
                "finding": "fan_out",
                "detail": f"paid {fan_out} accounts within an hour of receiving money",
                "scored_as": "RC8",
            }
        )
    if len(ring) >= RING_SIZE:
        findings.append(
            {
                "finding": "device_ring",
                "detail": f"{len(ring)} accounts tied together by shared devices",
                "accounts": sorted(names[a] for a in ring),
                "includes_confirmed_fraud": bool(ring & fraud),
                "scored_as": "RC9",
            }
        )
    return {
        "account": handle,
        "window_days": WINDOW_DAYS,
        "device_link_days": DEVICE_LINK_DAYS,
        "paid_to": [
            {"account": names[a], "payments": len(v), "total": round(sum(v), 2)} for a, v in sorted(paid_to.items())
        ],
        "paid_by": [
            {"account": names[a], "payments": len(v), "total": round(sum(v), 2)} for a, v in sorted(paid_by.items())
        ],
        "devices_used": len(my_devices),
        "shared_devices": shared_devices,
        "shared_networks": shared_networks,
        "shared_networks_note": "a shared network alone is common (home, office) and is not counted as a fraud link",
        "findings": findings,
        "evidence_note": "device and network ids are reported by the browser and can be avoided or forged",
    }
