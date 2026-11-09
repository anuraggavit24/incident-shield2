"""The policy snapshot: short PayPal help-page excerpts captured once, each with its source URL
and SHA-256. Nothing is fetched at runtime, and the AI never writes or chooses policy text:
the sections shown for each answer are fixed in code (copilot.INTENTS)."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

SNAPSHOT_PATH = Path(__file__).with_name("policy_snapshot.json")


class PolicySnapshotError(RuntimeError):
    pass


@dataclass(frozen=True)
class PolicySection:
    id: str
    title: str
    text: str
    source_url: str
    source: str  # paypal_help_center | paypal_business_resource_center | incident_shield_observation
    sha256: str

    def as_dict(self, captured_at: str) -> dict[str, str]:
        return {
            "id": self.id,
            "title": self.title,
            "text": self.text,
            "source_url": self.source_url,
            "source": self.source,
            "captured_at": captured_at,
            "sha256": self.sha256,
            "integrity_note": "The hash shows this text hasn't been edited since capture. It doesn't prove the "
            "text came from PayPal: check source_url.",
        }


@dataclass(frozen=True)
class PolicySnapshot:
    captured_at: str
    sections: dict[str, PolicySection]

    def get(self, section_id: str) -> PolicySection:
        return self.sections[section_id]


def load_snapshot(path: Path = SNAPSHOT_PATH) -> PolicySnapshot:
    data = json.loads(path.read_text(encoding="utf-8"))
    sections = {}
    for raw in data["sections"]:
        section = PolicySection(**{k: raw[k] for k in ("id", "title", "text", "source_url", "source", "sha256")})
        if hashlib.sha256(section.text.encode("utf-8")).hexdigest() != section.sha256:
            raise PolicySnapshotError(f"policy section {section.id} was edited without updating its sha256")
        sections[section.id] = section
    return PolicySnapshot(captured_at=data["captured_at"], sections=sections)


@lru_cache(maxsize=1)
def snapshot() -> PolicySnapshot:
    return load_snapshot()
