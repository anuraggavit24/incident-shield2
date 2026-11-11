"""Score one transaction 0-100 from named evidence. Pure: no database, no network, no clock.

Rules (rule set RULESET_VERSION):
- Each signal has a tier with fixed points (LOW 3, MED 7, HIGH 12). Points are summed per category
  and capped per category, then the total is capped at 100.
- Trust reductions are subtracted. Combination floors set a minimum the score can't go below.
- Evidence that is absent is never guessed: the signal scores 0 and the field is listed in missing_data.
- Evidence of the wrong type (a string where a number is needed) never crashes the scorer: the signal
  scores 0 and the field is listed in invalid_data. Callers must validate input before it gets here;
  because withheld or garbled evidence lowers a score, wiring this in without validation is unsafe.
- `source` says where a signal's evidence comes from: "app" (our payment app sees it), "ledger" (our
  own transaction records and PayPal webhooks) or "external" (telecom, breach, consortium or issuer
  data the demo can only simulate).
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any

RULESET_VERSION = "2026.11-1"
TIER_POINTS = {"LOW": 3, "MED": 7, "HIGH": 12}
CATEGORY_CAPS = {
    "velocity": 20,
    "device": 20,
    "network": 10,
    "identity": 15,
    "funding": 15,
    "recipient": 25,
    "behaviour": 10,
    "context": 10,
    "external": 10,
}
SCAM_MARKERS = ("safe account", "investment", "tax", "release fee")
BANDS = ((80, "block"), (60, "hold_review"), (30, "step_up"), (0, "allow"))
NEAR_MISS_SHARE = 0.7  # a numeric signal at 70%+ of its threshold counts as a near miss

Evidence = Mapping[str, Any]
Test = Callable[[Evidence], bool]
_BAD_VALUE = (TypeError, ValueError, ArithmeticError, AttributeError)


def _holds(test: Callable[..., bool], invalid: set[str], names: tuple[str, ...], *args: Any) -> bool:
    """Run one test; evidence of the wrong type counts as not fired and is recorded in `invalid`."""
    try:
        return bool(test(*args))
    except _BAD_VALUE:
        invalid.update(names)
        return False


@dataclass(frozen=True)
class Signal:
    id: str
    category: str
    tier: str
    needs: tuple[str, ...]
    test: Test
    source: str = "app"
    near: tuple[str, float] | None = None  # (field, threshold) for "field > threshold" signals

    @property
    def points(self) -> int:
        return TIER_POINTS[self.tier]


def _flag(sid: str, cat: str, tier: str, field: str, source: str = "app") -> Signal:
    return Signal(sid, cat, tier, (field,), lambda e: e[field] is True, source)


def _over(sid: str, cat: str, tier: str, field: str, threshold: float, source: str = "app") -> Signal:
    return Signal(sid, cat, tier, (field,), lambda e: e[field] > threshold, source, (field, threshold))


def _has_scam_marker(e: Evidence) -> bool:
    text = str(e["payment_reference"]).lower()
    return any(marker in text for marker in SCAM_MARKERS)


SIGNALS: tuple[Signal, ...] = (
    # 1. Velocity and aggregation
    _over("V1_AMOUNT_ZSCORE", "velocity", "HIGH", "amount_zscore_90d", 3, "ledger"),
    _over("V2_HOURLY_SPEND_SPIKE", "velocity", "HIGH", "spend_1h_vs_daily_avg_ratio", 5, "ledger"),
    _over("V3_NEW_RECIPIENTS_24H", "velocity", "MED", "new_recipients_24h", 3, "ledger"),
    _over("V4_ACCOUNTS_ON_DEVICE_OR_IP", "velocity", "HIGH", "accounts_on_device_or_ip_7d", 3),
    _flag("V5_DECLINED_THEN_RETRIED", "velocity", "MED", "declined_retry_altered_amount", "ledger"),
    _over("V6_STRUCTURING", "velocity", "MED", "amounts_just_under_threshold_24h", 2, "ledger"),
    # 2. Device intelligence
    _flag("D1_DEVICE_TIED_TO_FRAUD", "device", "HIGH", "device_linked_to_fraud"),
    _flag("D2_COMPROMISED_DEVICE", "device", "HIGH", "device_compromised", "external"),
    _flag("D3_REMOTE_ACCESS_OR_OVERLAY", "device", "HIGH", "remote_access_or_overlay", "external"),
    _flag("D4_ACTIVE_CALL", "device", "MED", "active_call", "external"),
    Signal(
        "D5_RECENT_SIM_SWAP",
        "device",
        "HIGH",
        ("sim_swap_days_ago",),
        lambda e: e["sim_swap_days_ago"] <= 7,
        "external",
    ),
    _flag("D6_FINGERPRINT_INCONSISTENT", "device", "MED", "fingerprint_inconsistent"),
    _flag("D7_FRESH_DEVICE_OLD_ACCOUNT", "device", "MED", "fresh_device_on_old_account"),
    # 3. Network
    _flag("N1_ANONYMISING_NETWORK", "network", "MED", "anonymising_asn", "external"),
    _flag("N2_IP_SHARED_WITH_FRAUD", "network", "HIGH", "ip_shared_with_fraud_accounts"),
    _flag("N3_IMPOSSIBLE_TRAVEL", "network", "HIGH", "impossible_travel"),
    _flag("N4_IP_FAR_FROM_USUAL", "network", "LOW", "ip_far_from_usual"),
    # 4. Identity and account state
    Signal(
        "I1_CREDENTIAL_CHANGE_THEN_PAYOUT",
        "identity",
        "HIGH",
        ("credential_change_hours_ago", "is_high_value"),
        lambda e: e["credential_change_hours_ago"] <= 72 and e["is_high_value"] is True,
    ),
    Signal(
        "I2_BREACHED_CREDENTIALS_NEW_DEVICE",
        "identity",
        "HIGH",
        ("credentials_in_breach", "new_device"),
        lambda e: e["credentials_in_breach"] is True and e["new_device"] is True,
        "external",
    ),
    _flag("I3_WEAK_CONTACT_DETAILS", "identity", "MED", "weak_contact_details"),
    Signal("I4_DORMANT_REACTIVATED", "identity", "MED", ("dormant_days",), lambda e: e["dormant_days"] >= 90),
    _flag("I5_LOW_VERIFICATION_FOR_AMOUNT", "identity", "MED", "verification_low_for_amount"),
    # 5. Funding instrument
    _flag("F1_CARD_TESTING", "funding", "HIGH", "card_testing_pattern", "ledger"),
    Signal(
        "F2_NEW_INSTRUMENT_HIGH_VALUE",
        "funding",
        "MED",
        ("instrument_age_minutes", "is_high_value"),
        lambda e: e["instrument_age_minutes"] <= 60 and e["is_high_value"] is True,
    ),
    _flag("F3_ISSUER_COUNTRY_MISMATCH", "funding", "MED", "issuer_country_mismatch", "external"),
    _flag("F4_CARD_CHECK_FAILED", "funding", "MED", "card_check_failed", "external"),
    _over("F5_MANY_INSTRUMENTS_ADDED", "funding", "HIGH", "instruments_added_24h", 3),
    _flag("F6_INSTRUMENT_PRIOR_CHARGEBACK", "funding", "HIGH", "instrument_prior_chargeback", "ledger"),
    # 6. Recipient and mule indicators
    _over("RC1_PASS_THROUGH", "recipient", "HIGH", "recipient_passthrough_ratio_30m", 0.8, "ledger"),
    Signal(
        "RC2_FAN_IN_YOUNG_ACCOUNT",
        "recipient",
        "HIGH",
        ("recipient_senders_7d", "recipient_account_age_days"),
        lambda e: e["recipient_senders_7d"] >= 5 and e["recipient_account_age_days"] < 60,
        "ledger",
    ),
    Signal(
        "RC3_LINKED_TO_FRAUD",
        "recipient",
        "HIGH",
        ("recipient_hops_to_fraud",),
        lambda e: e["recipient_hops_to_fraud"] <= 2,
    ),
    Signal(
        "RC4_RECIPIENT_PRIOR_COMPLAINTS",
        "recipient",
        "HIGH",
        ("recipient_prior_complaints",),
        lambda e: e["recipient_prior_complaints"] >= 1,
        "ledger",
    ),
    _flag("RC5_PAYEE_NAME_MISMATCH", "recipient", "MED", "payee_name_mismatch"),
    _flag("RC6_HIGH_RISK_CASH_OUT", "recipient", "MED", "recipient_high_risk_cashout", "ledger"),
    _over("RC7_INBOUND_ABOVE_PROFILE", "recipient", "MED", "recipient_inbound_vs_profile_ratio", 5, "ledger"),
    # 7. Behavioural biometrics (deviation flags only; raw keystrokes are never stored)
    _flag("B1_TYPING_DEVIATION", "behaviour", "MED", "typing_deviation"),
    _flag("B2_COACHING_SIGNS", "behaviour", "MED", "coaching_signs"),
    _flag("B3_SCRIPTED_INPUT", "behaviour", "MED", "scripted_input"),
    _flag("B4_STRAIGHT_TO_MAX_TRANSFER", "behaviour", "MED", "direct_to_new_payee_max_amount"),
    # 8. Transaction context
    _flag("C1_AMOUNT_EXTREME_VS_PEERS", "context", "MED", "amount_extreme_vs_peers", "ledger"),
    _flag("C2_HIGH_RISK_CORRIDOR", "context", "LOW", "high_risk_corridor"),
    Signal("C3_SCAM_REFERENCE", "context", "MED", ("payment_reference",), _has_scam_marker),
    _flag("C4_PERSONAL_PAYMENT_FOR_PURCHASE", "context", "LOW", "personal_payment_for_purchase"),
    # 9. External and consortium data
    _flag("E1_ON_NEGATIVE_LIST", "external", "HIGH", "on_negative_list", "external"),
    _flag("E2_NETWORK_RISK_SCORE_HIGH", "external", "MED", "network_risk_score_high", "external"),
)

# Trust reductions: (id, points, fields needed, test)
REDUCTIONS: tuple[tuple[str, int, tuple[str, ...], Test], ...] = (
    (
        "T1_ESTABLISHED_RECIPIENT",
        10,
        ("recipient_prior_payments", "recipient_relationship_days", "recipient_disputes_by_sender"),
        lambda e: (
            e["recipient_prior_payments"] >= 3
            and e["recipient_relationship_days"] >= 60
            and e["recipient_disputes_by_sender"] == 0
        ),
    ),
    (
        "T2_KNOWN_DEVICE_AND_NETWORK",
        8,
        ("device_seen_days", "network_seen_days"),
        lambda e: e["device_seen_days"] >= 30 and e["network_seen_days"] >= 30,
    ),
    ("T3_STRONG_AUTHENTICATION", 8, ("strong_auth",), lambda e: e["strong_auth"] is True),
    ("T4_RECURRING_PATTERN", 6, ("matches_recurring_pattern",), lambda e: e["matches_recurring_pattern"] is True),
    (
        "T5_LONG_TENURE_NO_DISPUTES",
        4,
        ("account_tenure_days", "account_disputes"),
        lambda e: e["account_tenure_days"] > 730 and e["account_disputes"] == 0,
    ),
)

Component = tuple[str, tuple[str, ...], Callable[[Evidence, set[str]], bool]]


def _fired(signal_id: str) -> Callable[[Evidence, set[str]], bool]:
    return lambda e, fired: signal_id in fired


# Combination floors: (id, typology, minimum score, components that must ALL hold)
FLOORS: tuple[tuple[str, str, int, tuple[Component, ...]], ...] = (
    (
        "ACCOUNT_TAKEOVER",
        "takeover",
        85,
        (
            (
                "credential change in last 72h",
                ("credential_change_hours_ago",),
                lambda e, f: e["credential_change_hours_ago"] <= 72,
            ),
            ("new device", ("new_device",), lambda e, f: e["new_device"] is True),
            ("new payee", ("new_payee",), lambda e, f: e["new_payee"] is True),
            ("amount above 3x norm", ("amount_vs_norm_ratio",), lambda e, f: e["amount_vs_norm_ratio"] > 3),
        ),
    ),
    (
        "MULE_ACCOUNT",
        "mule_activity",
        80,
        (
            (
                "recipient under 60 days",
                ("recipient_account_age_days",),
                lambda e, f: e["recipient_account_age_days"] < 60,
            ),
            ("fan-in", (), _fired("RC2_FAN_IN_YOUNG_ACCOUNT")),
            ("pass-through", (), _fired("RC1_PASS_THROUGH")),
        ),
    ),
    (
        "CARD_TESTING",
        "card_testing",
        80,
        (
            ("micro-authorisations", (), _fired("F1_CARD_TESTING")),
            ("new instrument", ("instrument_age_minutes",), lambda e, f: e["instrument_age_minutes"] <= 60),
            ("velocity", (), lambda e, f: any(s.startswith("V") for s in f)),
        ),
    ),
    (
        "AUTHORISED_SCAM",
        "authorised_scam",
        70,
        (
            ("known device", ("new_device",), lambda e, f: e["new_device"] is False),
            ("active call or coaching", (), lambda e, f: bool({"D4_ACTIVE_CALL", "B2_COACHING_SIGNS"} & f)),
            ("new payee", ("new_payee",), lambda e, f: e["new_payee"] is True),
            ("scam reference markers", (), _fired("C3_SCAM_REFERENCE")),
        ),
    ),
    (
        "DEVICE_FARM",
        "mule_activity",
        75,
        (
            (
                "5+ accounts on one device in 7d",
                ("accounts_on_device_7d",),
                lambda e, f: e["accounts_on_device_7d"] >= 5,
            ),
        ),
    ),
)

CATEGORY_TYPOLOGY = {
    "device": "takeover",
    "network": "takeover",
    "identity": "takeover",
    "recipient": "mule_activity",
    "funding": "card_testing",
    "behaviour": "authorised_scam",
    "context": "authorised_scam",
}


def band_for(score: int) -> str:
    return next(name for minimum, name in BANDS if score >= minimum)


def _at_least_share(value: Any, threshold: float) -> bool:
    return bool(value >= threshold * NEAR_MISS_SHARE)


def _floor_state(e: Evidence, fired: set[str], invalid: set[str] | None = None) -> list[dict[str, Any]]:
    invalid = invalid if invalid is not None else set()
    states = []
    for floor_id, typology, minimum, components in FLOORS:
        held, lacking = [], []
        for name, needs, test in components:
            ok = all(n in e for n in needs) and _holds(test, invalid, needs, e, fired)
            (held if ok else lacking).append(name)
        states.append({"id": floor_id, "typology": typology, "floor": minimum, "held": held, "lacking": lacking})
    return states


def decide(evidence: Evidence) -> dict[str, Any]:
    """Score one transaction. Values that are None count as missing."""
    e = {k: v for k, v in evidence.items() if v is not None}
    fired: list[dict[str, Any]] = []
    missing: set[str] = set()
    invalid: set[str] = set()
    for s in SIGNALS:
        lacking = [n for n in s.needs if n not in e]
        if lacking:
            missing.update(lacking)
        elif _holds(s.test, invalid, s.needs, e):
            fired.append(
                {
                    "name": s.id,
                    "category": s.category,
                    "tier": s.tier,
                    "points": s.points,
                    "raw_value": {n: e[n] for n in s.needs},
                    "source": s.source,
                }
            )
    fired_ids = {f["name"] for f in fired}

    categories = {}
    for category, cap in CATEGORY_CAPS.items():
        raw = sum(f["points"] for f in fired if f["category"] == category)
        categories[category] = {"raw": raw, "cap": cap, "counted": min(raw, cap)}
    subtotal = min(100, sum(c["counted"] for c in categories.values()))

    reductions = []
    for rid, points, needs, test in REDUCTIONS:
        lacking = [n for n in needs if n not in e]
        if lacking:
            missing.update(lacking)
        elif _holds(test, invalid, needs, e):
            reductions.append({"name": rid, "points": -points, "raw_value": {n: e[n] for n in needs}})

    floor_states = _floor_state(e, fired_ids, invalid)
    floors = [
        {"name": s["id"], "floor": s["floor"], "typology": s["typology"]} for s in floor_states if not s["lacking"]
    ]
    for _, _, _, components in FLOORS:
        for _, needs, _ in components:
            missing.update(n for n in needs if n not in e)
    floor = max((f["floor"] for f in floors), default=0)
    score = max(subtotal + sum(r["points"] for r in reductions), floor, 0)

    if floors:
        typology = max(floors, key=lambda f: f["floor"])["typology"]
    elif score >= 30 and fired:
        top = max((c for c in categories if c in CATEGORY_TYPOLOGY), key=lambda c: categories[c]["counted"])
        typology = CATEGORY_TYPOLOGY[top] if categories[top]["counted"] > 0 else "unclassified"
    else:
        typology = None

    band = band_for(score)
    # A coached victim passes extra authentication themselves, so step-up doesn't protect them.
    action = "warn_and_delay" if band == "step_up" and typology == "authorised_scam" else band
    top_signals = sorted(fired, key=lambda f: -f["points"])
    reason_codes = ([f["name"] for f in floors] + [f["name"] for f in top_signals])[:3]
    return {
        "ruleset_version": RULESET_VERSION,
        "score": score,
        "band": band,
        "action": action,
        "typology": typology,
        "signals_fired": fired,
        "category_points": categories,
        "floors_triggered": floors,
        "reductions_applied": reductions,
        "missing_data": sorted(missing),
        "invalid_data": sorted(invalid),
        "reason_codes": reason_codes,
    }


def near_misses(evidence: Evidence) -> dict[str, list[dict[str, Any]]]:
    """What almost fired: numeric signals close to their threshold, and floors one component short.
    Run on confirmed fraud the engine let through, to see how it got past."""
    e = {k: v for k, v in evidence.items() if v is not None}
    fired = {f["name"] for f in decide(e)["signals_fired"]}
    signals = []
    for s in SIGNALS:
        if s.near is None or s.id in fired or s.near[0] not in e:
            continue
        field, threshold = s.near
        if _holds(_at_least_share, set(), (field,), e[field], threshold):
            signals.append({"signal": s.id, "field": field, "value": e[field], "threshold": threshold})
    floors = [
        {"floor": s["id"], "one_short": s["lacking"][0], "held": s["held"]}
        for s in _floor_state(e, fired)
        if len(s["lacking"]) == 1 and s["held"]
    ]
    return {"signals_just_under_threshold": signals, "floors_one_component_short": floors}
