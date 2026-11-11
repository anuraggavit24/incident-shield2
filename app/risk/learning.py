"""Learning from outcomes: retroactive rescoring, how confirmed fraud got through, and the scam library."""

from __future__ import annotations

from collections import Counter
from typing import Any

from .engine import decide, near_misses

HOLD_AT = 60


def rescore_payers(snapshots: list[dict[str, Any]], recipient: str) -> list[dict[str, Any]]:
    """A recipient was confirmed fraudulent. Rescore every stored payment to them with that fact
    added, and return the ones that now reach the hold band: likely victims to alert before they
    complain. `snapshots` are opened snapshots whose evidence carries `recipient` and `txn_id`."""
    alerts = []
    for snap in snapshots:
        evidence = dict(snap["evidence"])
        if evidence.get("recipient") != recipient:
            continue
        old = snap["decision"]["score"]
        evidence["recipient_prior_complaints"] = max(1, evidence.get("recipient_prior_complaints") or 0)
        evidence["on_negative_list"] = True
        new = decide(evidence)
        if new["score"] >= HOLD_AT and new["score"] > old:
            alerts.append(
                {
                    "txn_id": evidence.get("txn_id"),
                    "sender": evidence.get("sender"),
                    "score_at_the_time": old,
                    "score_now": new["score"],
                    "band_now": new["band"],
                }
            )
    return sorted(alerts, key=lambda a: -a["score_now"])


def gap_report(snapshot: dict[str, Any], confirmed_typology: str) -> dict[str, Any]:
    """For confirmed fraud the engine did not hold: what it saw, what it lacked, what nearly fired."""
    decision = snapshot["decision"]
    return {
        "confirmed_typology": confirmed_typology,
        "engine_typology": decision["typology"],
        "typology_matched": decision["typology"] == confirmed_typology,
        "score": decision["score"],
        "band": decision["band"],
        "let_through": decision["score"] < HOLD_AT,
        "signals_fired": [f["name"] for f in decision["signals_fired"]],
        "missing_data": decision["missing_data"],
        **near_misses(snapshot["evidence"]),
    }


def scam_library(cases: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    """Group reviewed cases by confirmed typology. `cases`: {"snapshot": opened snapshot,
    "outcome": "fraud" | "legitimate", "typology": confirmed typology or None}."""
    library: dict[str, dict[str, Any]] = {}
    for typology in sorted({c["typology"] for c in cases if c["outcome"] == "fraud" and c["typology"]}):
        group = [c for c in cases if c["outcome"] == "fraud" and c["typology"] == typology]
        reports = [gap_report(c["snapshot"], typology) for c in group]
        signals = Counter(s for r in reports for s in r["signals_fired"])
        gaps = Counter(m["signal"] for r in reports if r["let_through"] for m in r["signals_just_under_threshold"])
        missing = Counter(m for r in reports if r["let_through"] for m in r["missing_data"])
        library[typology] = {
            "cases": len(group),
            "held_or_blocked": sum(not r["let_through"] for r in reports),
            "let_through": sum(r["let_through"] for r in reports),
            "average_score": round(sum(r["score"] for r in reports) / len(reports), 1),
            "most_common_signals": signals.most_common(5),
            "thresholds_most_often_just_missed": gaps.most_common(5),
            "data_most_often_missing_when_missed": missing.most_common(5),
        }
    legit = [c for c in cases if c["outcome"] == "legitimate"]
    library["_false_alarms"] = {
        "cases": len(legit),
        "held_or_blocked": sum(c["snapshot"]["decision"]["score"] >= HOLD_AT for c in legit),
    }
    return library
