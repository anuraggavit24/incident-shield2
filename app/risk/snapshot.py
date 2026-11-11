"""Sealed decision snapshots: what the engine knew and decided at the moment of a transaction.

Each record is encrypted (AES-256-GCM), chained to the previous record's hash, and signed
(HMAC-SHA256 with a separate key). Nothing readable is stored: score, signals and evidence are all
inside the ciphertext.

verify_chain() detects an edited, reordered or removed record, including a removed first or middle record.
A chain on its own can NOT detect records cut off the END: what is left is still a valid chain. To catch that,
keep a signed checkpoint (make_checkpoint) somewhere an attacker with database access can't also edit, and
pass it to verify_chain(). A checkpoint also can't prove the chain wasn't rolled back to an older checkpoint
together with its records; store the latest one outside the database to narrow that.

Keys: seal() records which key id it used; open_snapshot() and verify_chain() accept a single key or a
{key_id: key} mapping, so old records stay readable after a new key becomes active (load_keyring()).
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
from collections.abc import Mapping
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


Keys = bytes | Mapping[str, bytes]


def _pick(keys: Keys, key_id: str | None) -> bytes:
    if isinstance(keys, Mapping):
        if key_id not in keys:
            raise SnapshotError(f"no key with id {key_id!r}")
        return keys[key_id]
    return keys


def load_keyring(environ: Mapping[str, str]) -> dict[str, Any]:
    """Read keys from environment variables, never from the database.

    RISK_ENC_KEY_<ID> and RISK_SIGN_KEY_<ID> are 64 hex characters (32 bytes) each; RISK_ACTIVE_KEY_ID names
    the id used to seal new records. Returns {"enc": {...}, "sign": {...}, "active": id}."""
    enc: dict[str, bytes] = {}
    sign: dict[str, bytes] = {}
    for name, value in environ.items():
        for prefix, target in (("RISK_ENC_KEY_", enc), ("RISK_SIGN_KEY_", sign)):
            if name.startswith(prefix):
                try:
                    key = bytes.fromhex(value.strip())
                except ValueError as exc:
                    raise SnapshotError(f"{name} is not hex") from exc
                _check_key(key, name)
                target[name[len(prefix) :].lower()] = key
    active = environ.get("RISK_ACTIVE_KEY_ID", "").strip().lower()
    if not active or active not in enc or active not in sign:
        raise SnapshotError("RISK_ACTIVE_KEY_ID must name an id that has both an encryption and a signing key")
    return {"enc": enc, "sign": sign, "active": active}


def open_snapshot(record: dict[str, str], enc_key: Keys) -> dict[str, Any]:
    key = _pick(enc_key, record.get("key_id"))
    try:
        body = AESGCM(key).decrypt(
            bytes.fromhex(record["nonce"]), bytes.fromhex(record["ciphertext"]), record["prev_hash"].encode()
        )
    except (InvalidTag, ValueError) as exc:
        raise SnapshotError("snapshot could not be decrypted: wrong key or altered record") from exc
    return json.loads(body)


def _checkpoint_signature(sign_key: bytes, count: int, head_hash: str) -> str:
    return hmac.new(sign_key, f"checkpoint:{count}:{head_hash}".encode(), hashlib.sha256).hexdigest()


def make_checkpoint(records: list[dict[str, str]], sign_key: bytes, key_id: str = "k1") -> dict[str, Any]:
    """A signed (count, head hash) to store outside the database. Detects records cut off the end."""
    _check_key(sign_key, "signing key")
    head = records[-1]["record_hash"] if records else GENESIS_HASH
    return {
        "key_id": key_id,
        "count": len(records),
        "head_hash": head,
        "signature": _checkpoint_signature(sign_key, len(records), head),
    }


def verify_chain(
    records: list[dict[str, str]], sign_key: Keys, checkpoint: dict[str, Any] | None = None
) -> tuple[bool, int | None]:
    """Check hashes, links and signatures in order. Returns (ok, index of the first bad record).

    With a checkpoint it also fails if the chain is shorter than the checkpoint or doesn't contain the
    checkpointed head (records removed from the end, or replaced). Records added after the checkpoint are fine."""
    prev = GENESIS_HASH
    for index, r in enumerate(records):
        try:
            key = _pick(sign_key, r.get("key_id"))
            expected = hashlib.sha256(
                r["prev_hash"].encode() + bytes.fromhex(r["nonce"]) + bytes.fromhex(r["ciphertext"])
            ).hexdigest()
        except (ValueError, KeyError, SnapshotError):
            return False, index
        signature = hmac.new(key, r["record_hash"].encode(), hashlib.sha256).hexdigest()
        if r["prev_hash"] != prev or r["record_hash"] != expected or not hmac.compare_digest(signature, r["signature"]):
            return False, index
        prev = r["record_hash"]
    if checkpoint is not None:
        try:
            count, head = int(checkpoint["count"]), str(checkpoint["head_hash"])
            key = _pick(sign_key, checkpoint.get("key_id"))
            good = hmac.compare_digest(_checkpoint_signature(key, count, head), str(checkpoint["signature"]))
        except (ValueError, KeyError, TypeError, SnapshotError):
            return False, len(records)
        if not good or len(records) < count:
            return False, min(len(records), max(count, 0))
        chain_head = records[count - 1]["record_hash"] if count else GENESIS_HASH
        if chain_head != head:
            return False, max(count - 1, 0)
    return True, None
