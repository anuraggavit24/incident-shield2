"""Sealed decision snapshots: what the engine knew and decided at the moment of a transaction.

Each record is encrypted (AES-256-GCM), chained to the previous record's hash, and signed
(HMAC-SHA256 with a separate key). Nothing readable is stored: score, signals and evidence are all
inside the ciphertext. Changing, removing or reordering any record breaks verify_chain().
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
from datetime import datetime
from typing import Any

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

GENESIS_HASH = "0" * 64


class SnapshotError(Exception):
    pass


def _check_key(key: bytes, name: str) -> None:
    if len(key) != 32:
        raise SnapshotError(f"{name} must be 32 bytes (AES-256 / HMAC-SHA256)")


def seal(
    decision: dict[str, Any],
    evidence: dict[str, Any],
    prev_hash: str,
    enc_key: bytes,
    sign_key: bytes,
    sealed_at: datetime,
    key_id: str = "k1",
) -> dict[str, str]:
    """Encrypt and chain one decision. Returns the row to store; every value is hex or an id."""
    _check_key(enc_key, "encryption key")
    _check_key(sign_key, "signing key")
    body = json.dumps(
        {"decision": decision, "evidence": evidence, "sealed_at": sealed_at.isoformat()}, sort_keys=True, default=str
    ).encode()
    nonce = os.urandom(12)
    # prev_hash is authenticated with the ciphertext, so a record can't be moved to another position.
    ciphertext = AESGCM(enc_key).encrypt(nonce, body, prev_hash.encode())
    record_hash = hashlib.sha256(prev_hash.encode() + nonce + ciphertext).hexdigest()
    signature = hmac.new(sign_key, record_hash.encode(), hashlib.sha256).hexdigest()
    return {
        "key_id": key_id,
        "prev_hash": prev_hash,
        "nonce": nonce.hex(),
        "ciphertext": ciphertext.hex(),
        "record_hash": record_hash,
        "signature": signature,
    }


def open_snapshot(record: dict[str, str], enc_key: bytes) -> dict[str, Any]:
    try:
        body = AESGCM(enc_key).decrypt(
            bytes.fromhex(record["nonce"]), bytes.fromhex(record["ciphertext"]), record["prev_hash"].encode()
        )
    except (InvalidTag, ValueError) as exc:
        raise SnapshotError("snapshot could not be decrypted: wrong key or altered record") from exc
    return json.loads(body)


def verify_chain(records: list[dict[str, str]], sign_key: bytes) -> tuple[bool, int | None]:
    """Check hashes, links and signatures in order. Returns (ok, index of the first bad record)."""
    prev = GENESIS_HASH
    for index, r in enumerate(records):
        try:
            expected = hashlib.sha256(
                r["prev_hash"].encode() + bytes.fromhex(r["nonce"]) + bytes.fromhex(r["ciphertext"])
            ).hexdigest()
        except ValueError:
            return False, index
        signature = hmac.new(sign_key, r["record_hash"].encode(), hashlib.sha256).hexdigest()
        if r["prev_hash"] != prev or r["record_hash"] != expected or not hmac.compare_digest(signature, r["signature"]):
            return False, index
        prev = r["record_hash"]
    return True, None
