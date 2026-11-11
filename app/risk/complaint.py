"""Complaint-consistency score (0-100): does a complaint match what was recorded at the time?

The complaint is compared with the sealed snapshot, never with current data, because the snapshot
was taken before anyone had a reason to misreport. High consistency supports a fast refund. Low
consistency never rejects a complaint by itself: it sends the case to a human reviewer.
"""

from __future__ import annotations

from typing import Any

START = 50
FAST_TRACK_AT = 70
REVIEW_BELOW = 40


def consistency(complaint: dict[str, Any], snapshot: dict[str, Any]) -> dict[str, Any]:
    """`complaint`: claim ("unauthorised" or "scam"), denies_account_changes (optional bool),
    complainant_dispute_rate and complainant_rejected_disputes (optional).
    `snapshot`: an opened snapshot, {"decision": ..., "evidence": ...}."""
    e = {k: v for k, v in snapshot["evidence"].items() if v is not None}
    decision = snapshot["decision"]
    fired = {f["name"] for f in decision["signals_fired"]}
    claim = complaint.get("claim")
    if claim not in ("unauthorised", "scam"):
        raise ValueError("claim must be 'unauthorised' or 'scam'")
    checks: list[dict[str, Any]] = []
    missing: list[str] = []

    def check(name: str, field: str, effects: list[tuple[Any, int, str]]) -> None:
        """effects: (predicate over the recorded value, points, what it means). First match applies."""
        if field not in e:
            missing.append(field)
            return
        for predicate, points, meaning in effects:
            if predicate(e[field]):
                checks.append({"check": name, "recorded": {field: e[field]}, "points": points, "meaning": meaning})
                return

    def note(name: str, recorded: Any, points: int, meaning: str) -> None:
        checks.append({"check": name, "recorded": recorded, "points": points, "meaning": meaning})

    if claim == "unauthorised":
        check(
            "device",
            "new_device",
            [
                (lambda v: v is True, 20, "payment came from a device never seen on this account"),
                (lambda v: v is False, -25, "payment came from the complainant's known device"),
            ],
        )
        check(
            "network",
            "network_seen_days",
            [
                (lambda v: v >= 30, -15, "payment came from a network used for 30+ days"),
                (lambda v: v == 0, 10, "payment came from a network never seen before"),
            ],
        )
        if fired & {"N3_IMPOSSIBLE_TRAVEL", "N1_ANONYMISING_NETWORK", "N4_IP_FAR_FROM_USUAL"}:
            note(
                "location",
                sorted(fired & {"N3_IMPOSSIBLE_TRAVEL", "N1_ANONYMISING_NETWORK", "N4_IP_FAR_FROM_USUAL"}),
                10,
                "location or network was unusual at the time",
            )
        if complaint.get("denies_account_changes"):
            check(
                "account changes",
                "credential_change_from_known_device",
                [
                    (lambda v: v is True, -20, "the denied account change came from the complainant's own device"),
                    (lambda v: v is False, 15, "the denied account change came from an unknown device"),
                ],
            )
        if decision.get("typology") == "takeover":
            note("typology at the time", "takeover", 10, "the engine classified this as takeover when it happened")
    else:  # authorised scam: the victim's own device is expected, so it isn't held against them
        for signal, meaning in (
            ("D4_ACTIVE_CALL", "a phone call was active during the payment"),
            ("B2_COACHING_SIGNS", "entry looked dictated or coached"),
            ("C3_SCAM_REFERENCE", "the payment reference contained scam wording"),
        ):
            if signal in fired:
                note("scam indicator", signal, 10, meaning)
        check("payee", "new_payee", [(lambda v: v is True, 10, "the payee was added for this payment")])
        if decision["category_points"]["recipient"]["counted"] > 0:
            note(
                "recipient risk",
                decision["category_points"]["recipient"]["counted"],
                15,
                "the recipient showed mule indicators at the time",
            )
        if decision.get("typology") == "authorised_scam":
            note("typology at the time", "authorised_scam", 10, "the engine classified this as a scam when it happened")

    check(
        "history with recipient",
        "recipient_prior_payments",
        [
            (lambda v: v >= 3, -20, "the complainant had paid this recipient 3+ times before"),
            (lambda v: v == 0, 10, "the complainant had never paid this recipient before"),
        ],
    )
    if decision["score"] >= 60:
        note("score at the time", decision["score"], 10, "the transaction was already scored as high risk")
    # Complainant history is capped at -20 in total, so a genuine repeat victim isn't buried by it.
    history = 0
    if (complaint.get("complainant_rejected_disputes") or 0) >= 2:
        history -= 10
    if (complaint.get("complainant_dispute_rate") or 0) > 0.1:
        history -= 10
    if history:
        note(
            "complainant history",
            {
                "rejected_disputes": complaint.get("complainant_rejected_disputes"),
                "dispute_rate": complaint.get("complainant_dispute_rate"),
            },
            history,
            "the complainant's past disputes lower confidence",
        )

    score = max(0, min(100, START + sum(c["points"] for c in checks)))
    if score >= FAST_TRACK_AT:
        outcome = "fast_track_refund"
    elif score >= REVIEW_BELOW:
        outcome = "standard_review"
    else:
        outcome = "manual_review_possible_first_party_abuse"
    return {
        "consistency_score": score,
        "outcome": outcome,
        "claim": claim,
        "checks": checks,
        "missing_data": sorted(set(missing)),
        "compared_with": "sealed snapshot, not current data",
    }
