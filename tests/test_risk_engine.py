"""The fraud-risk decision engine: scoring, sealed snapshots, complaint consistency, learning. No database."""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from app.risk.complaint import consistency
from app.risk.engine import CATEGORY_CAPS, SIGNALS, decide, near_misses
from app.risk.learning import gap_report, rescore_payers, scam_library
from app.risk.snapshot import (
    GENESIS_HASH,
    SnapshotError,
    load_keyring,
    make_checkpoint,
    open_snapshot,
    seal,
    verify_chain,
)

ENC, SIGN = b"e" * 32, b"s" * 32
NOW = datetime(2026, 11, 11, 12, 0, tzinfo=timezone.utc)

TAKEOVER = {
    "credential_change_hours_ago": 2,
    "new_device": True,
    "new_payee": True,
    "amount_vs_norm_ratio": 6,
    "is_high_value": True,
    "network_seen_days": 0,
    "recipient_prior_payments": 0,
    "credential_change_from_known_device": False,
}
SCAM = {
    "new_device": False,
    "active_call": True,
    "new_payee": True,
    "payment_reference": "transfer to safe account",
    "recipient_prior_payments": 0,
}
MULE = {"recipient_account_age_days": 12, "recipient_senders_7d": 9, "recipient_passthrough_ratio_30m": 0.95}


def names(decision) -> set[str]:
    return {f["name"] for f in decision["signals_fired"]}


def test_nothing_known_scores_zero_and_lists_what_is_missing() -> None:
    d = decide({})
    assert d["score"] == 0 and d["band"] == "allow" and d["typology"] is None
    assert d["signals_fired"] == [] and "new_device" in d["missing_data"] and "amount_zscore_90d" in d["missing_data"]


def test_none_values_count_as_missing_not_as_false() -> None:
    d = decide({"device_linked_to_fraud": None})
    assert "device_linked_to_fraud" in d["missing_data"] and d["score"] == 0


def test_signal_ids_are_unique_and_every_category_has_a_cap() -> None:
    ids = [s.id for s in SIGNALS]
    assert len(ids) == len(set(ids)) == 45
    assert {s.category for s in SIGNALS} == set(CATEGORY_CAPS)


def test_category_cap_limits_a_pile_of_signals() -> None:
    d = decide({"device_linked_to_fraud": True, "device_compromised": True, "remote_access_or_overlay": True})
    assert d["category_points"]["device"] == {"raw": 36, "cap": 20, "counted": 20}
    assert d["score"] == 20


def test_total_is_capped_at_100() -> None:
    everything = {
        "amount_zscore_90d": 9, "spend_1h_vs_daily_avg_ratio": 9, "device_linked_to_fraud": True,
        "device_compromised": True, "ip_shared_with_fraud_accounts": True, "impossible_travel": True,
        "credential_change_hours_ago": 1, "is_high_value": True, "credentials_in_breach": True, "new_device": True,
        "card_testing_pattern": True, "instruments_added_24h": 9, "recipient_passthrough_ratio_30m": 1.0,
        "recipient_prior_complaints": 3, "recipient_hops_to_fraud": 1, "typing_deviation": True,
        "coaching_signs": True, "amount_extreme_vs_peers": True, "payment_reference": "tax release fee",
        "on_negative_list": True,
    }  # fmt: skip
    assert decide(everything)["score"] == 100


def test_takeover_floor_sets_85_even_when_the_sum_is_lower() -> None:
    d = decide(TAKEOVER)
    assert d["score"] == 85 and d["band"] == "block" and d["typology"] == "takeover"
    assert d["floors_triggered"][0]["name"] == "ACCOUNT_TAKEOVER" and d["reason_codes"][0] == "ACCOUNT_TAKEOVER"


def test_reductions_subtract_but_never_go_below_a_floor() -> None:
    trusted = {"strong_auth": True, "account_tenure_days": 1000, "account_disputes": 0}
    d = decide({**TAKEOVER, **trusted})
    assert {r["name"] for r in d["reductions_applied"]} == {"T3_STRONG_AUTHENTICATION", "T5_LONG_TENURE_NO_DISPUTES"}
    assert d["score"] == 85
    plain = decide({"amount_zscore_90d": 4, **trusted})
    assert plain["score"] == 0  # 12 - 12, and never negative


def test_established_recipient_lowers_the_score() -> None:
    base = {"amount_zscore_90d": 4, "spend_1h_vs_daily_avg_ratio": 6}
    known = {"recipient_prior_payments": 5, "recipient_relationship_days": 90, "recipient_disputes_by_sender": 0}
    assert decide(base)["score"] == 20 and decide({**base, **known})["score"] == 10


def test_mule_floor_and_device_farm_floor() -> None:
    d = decide(MULE)
    assert d["score"] == 80 and d["typology"] == "mule_activity"
    assert decide({"accounts_on_device_7d": 5})["score"] == 75


def test_card_testing_floor_needs_all_three_parts() -> None:
    parts = {"card_testing_pattern": True, "instrument_age_minutes": 10, "new_recipients_24h": 5}
    assert decide(parts)["score"] == 80
    without_velocity = {k: v for k, v in parts.items() if k != "new_recipients_24h"}
    assert decide(without_velocity)["floors_triggered"] == []


def test_authorised_scam_is_held_and_step_up_becomes_warn_and_delay() -> None:
    d = decide(SCAM)
    assert d["score"] == 70 and d["band"] == "hold_review" and d["typology"] == "authorised_scam"
    mild = decide({"coaching_signs": True, "typing_deviation": True, "payment_reference": "investment",
                   "high_risk_corridor": True, "amount_extreme_vs_peers": True, "active_call": True,
                   "ip_far_from_usual": True})  # fmt: skip
    assert mild["band"] == "step_up" and mild["typology"] == "authorised_scam" and mild["action"] == "warn_and_delay"


@pytest.mark.parametrize(("score_inputs", "band"), [
    ({}, "allow"),
    ({"amount_zscore_90d": 4, "spend_1h_vs_daily_avg_ratio": 6, "device_linked_to_fraud": True}, "step_up"),
    ({"amount_zscore_90d": 4, "spend_1h_vs_daily_avg_ratio": 6, "device_linked_to_fraud": True,
      "device_compromised": True, "recipient_prior_complaints": 1, "recipient_hops_to_fraud": 1}, "hold_review"),
])  # fmt: skip
def test_bands(score_inputs, band) -> None:
    assert decide(score_inputs)["band"] == band


def test_near_misses_show_how_a_case_slipped_under() -> None:
    evidence = {**MULE, "recipient_passthrough_ratio_30m": 0.79}
    assert decide(evidence)["floors_triggered"] == []
    report = near_misses(evidence)
    assert report["signals_just_under_threshold"] == [
        {"signal": "RC1_PASS_THROUGH", "field": "recipient_passthrough_ratio_30m", "value": 0.79, "threshold": 0.8}
    ]
    assert report["floors_one_component_short"][0] == {
        "floor": "MULE_ACCOUNT", "one_short": "pass-through", "held": ["recipient under 60 days", "fan-in"]
    }  # fmt: skip


# ---- sealed snapshots


def chain(evidences) -> list[dict]:
    records, prev = [], GENESIS_HASH
    for ev in evidences:
        record = seal(decide(ev), ev, prev, ENC, SIGN, NOW)
        records.append(record)
        prev = record["record_hash"]
    return records


def test_snapshot_round_trip_and_nothing_readable_is_stored() -> None:
    record = chain([TAKEOVER])[0]
    stored = " ".join(record.values())
    assert "takeover" not in stored and "score" not in stored and "new_device" not in stored
    opened = open_snapshot(record, ENC)
    assert opened["decision"]["score"] == 85 and opened["evidence"]["new_device"] is True
    assert opened["sealed_at"] == NOW.isoformat()


def test_chain_verifies_and_detects_edits_removals_and_reordering() -> None:
    records = chain([TAKEOVER, SCAM, MULE])
    assert verify_chain(records, SIGN) == (True, None)
    edited = [dict(r) for r in records]
    edited[1]["ciphertext"] = edited[1]["ciphertext"][:-2] + ("00" if edited[1]["ciphertext"][-2:] != "00" else "01")
    assert verify_chain(edited, SIGN) == (False, 1)
    assert verify_chain([records[0], records[2]], SIGN) == (False, 1)
    assert verify_chain([records[1], records[0], records[2]], SIGN) == (False, 0)
    assert verify_chain(records, b"x" * 32) == (False, 0)


def test_wrong_key_or_altered_record_cannot_be_opened() -> None:
    record = chain([TAKEOVER])[0]
    with pytest.raises(SnapshotError):
        open_snapshot(record, b"x" * 32)
    moved = {**record, "prev_hash": "1" * 64}
    with pytest.raises(SnapshotError):
        open_snapshot(moved, ENC)
    with pytest.raises(SnapshotError):
        seal({}, {}, GENESIS_HASH, b"short", SIGN, NOW)


def test_chain_alone_cannot_see_removed_tail_but_a_checkpoint_does() -> None:
    records = chain([TAKEOVER, SCAM, MULE, TAKEOVER, SCAM])
    checkpoint = make_checkpoint(records, SIGN)
    # without a checkpoint a truncated chain still verifies: this is the known limit
    assert verify_chain(records[:3], SIGN) == (True, None)
    assert verify_chain([], SIGN) == (True, None)
    # with the checkpoint, cutting the end (or emptying the chain) is caught
    assert verify_chain(records, SIGN, checkpoint) == (True, None)
    assert verify_chain(records[:3], SIGN, checkpoint) == (False, 3)
    assert verify_chain([], SIGN, checkpoint) == (False, 0)
    # records appended after the checkpoint are fine
    longer = chain([TAKEOVER, SCAM, MULE, TAKEOVER, SCAM, MULE])
    assert verify_chain(longer, SIGN, make_checkpoint(longer[:5], SIGN)) == (True, None)
    # a different valid chain of the same length (records replaced) does not contain the checkpointed head
    replaced = chain([SCAM, MULE, TAKEOVER, SCAM, MULE])
    assert verify_chain(replaced, SIGN) == (True, None)
    assert verify_chain(replaced, SIGN, checkpoint) == (False, 4)
    # a forged or edited checkpoint is rejected
    assert verify_chain(records, SIGN, {**checkpoint, "count": 2})[0] is False
    assert verify_chain(records, b"x" * 32, checkpoint)[0] is False
    assert verify_chain([], SIGN, make_checkpoint([], SIGN)) == (True, None)


def test_old_records_stay_readable_after_the_key_is_rotated() -> None:
    old = seal(decide(TAKEOVER), TAKEOVER, GENESIS_HASH, ENC, SIGN, NOW, key_id="k1")
    new_enc, new_sign = b"E" * 32, b"S" * 32
    new = seal(decide(SCAM), SCAM, old["record_hash"], new_enc, new_sign, NOW, key_id="k2")
    enc_ring, sign_ring = {"k1": ENC, "k2": new_enc}, {"k1": SIGN, "k2": new_sign}
    assert verify_chain([old, new], sign_ring) == (True, None)
    assert open_snapshot(old, enc_ring)["decision"]["score"] == 85
    assert open_snapshot(new, enc_ring)["decision"]["typology"] == "authorised_scam"
    assert verify_chain([old, new], {"k1": SIGN}) == (False, 1)  # unknown key id
    with pytest.raises(SnapshotError):
        open_snapshot(new, {"k1": ENC})


def test_keyring_loads_from_environment_and_rejects_bad_keys() -> None:
    env = {
        "RISK_ENC_KEY_K1": "11" * 32,
        "RISK_SIGN_KEY_K1": "22" * 32,
        "RISK_ENC_KEY_K2": "33" * 32,
        "RISK_SIGN_KEY_K2": "44" * 32,
        "RISK_ACTIVE_KEY_ID": "K2",
    }
    ring = load_keyring(env)
    assert ring["active"] == "k2" and set(ring["enc"]) == {"k1", "k2"} and ring["sign"]["k1"] == b"\x22" * 32
    with pytest.raises(SnapshotError):
        load_keyring({**env, "RISK_ACTIVE_KEY_ID": "k9"})
    with pytest.raises(SnapshotError):
        load_keyring({**env, "RISK_ENC_KEY_K1": "abcd"})
    with pytest.raises(SnapshotError):
        load_keyring({**env, "RISK_SIGN_KEY_K1": "zz" * 32})


# ---- malformed evidence


def test_wrong_type_evidence_never_crashes_and_is_reported() -> None:
    bad = {"sim_swap_days_ago": "3", "amount_zscore_90d": "huge", "dormant_days": None, "new_device": "yes"}
    result = decide(bad)
    assert result["score"] == 0 and "sim_swap_days_ago" in result["invalid_data"]
    assert "amount_zscore_90d" in result["invalid_data"]
    assert near_misses(bad)["signals_just_under_threshold"] == []
    # valid evidence in the same record still scores
    mixed = decide({**TAKEOVER, "amount_zscore_90d": "huge"})
    assert mixed["score"] == 85 and mixed["invalid_data"] == ["amount_zscore_90d"]
    assert decide(TAKEOVER)["invalid_data"] == []


def test_engine_rule_ids_do_not_clash_with_the_incident_rules() -> None:
    import re
    from pathlib import Path

    incident_rules = set(re.findall(r'rule_id="([A-Z0-9_]+)"', Path("app/rules.py").read_text()))
    assert "R2_PASS_THROUGH" in incident_rules  # guards the regex itself
    assert not incident_rules & {s.id for s in SIGNALS}


# ---- complaint consistency


def snap(evidence) -> dict:
    return {"decision": decide(evidence), "evidence": evidence}


def test_real_takeover_complaint_is_fast_tracked() -> None:
    result = consistency({"claim": "unauthorised", "denies_account_changes": True}, snap(TAKEOVER))
    assert result["consistency_score"] == 100 and result["outcome"] == "fast_track_refund"
    assert result["compared_with"].startswith("sealed snapshot")


def test_not_me_claim_from_the_usual_device_goes_to_manual_review_not_rejection() -> None:
    own = {"new_device": False, "network_seen_days": 200, "recipient_prior_payments": 6,
           "credential_change_from_known_device": True}  # fmt: skip
    result = consistency({"claim": "unauthorised", "denies_account_changes": True,
                          "complainant_rejected_disputes": 3, "complainant_dispute_rate": 0.4}, snap(own))  # fmt: skip
    assert result["consistency_score"] == 0
    assert result["outcome"] == "manual_review_possible_first_party_abuse"


def test_scam_complaint_does_not_penalise_the_victims_own_device() -> None:
    result = consistency({"claim": "scam"}, snap(SCAM))
    assert result["outcome"] == "fast_track_refund"
    assert all(c["check"] != "device" for c in result["checks"])


def test_complaint_with_no_recorded_evidence_stays_in_standard_review() -> None:
    result = consistency({"claim": "unauthorised"}, snap({}))
    assert result["consistency_score"] == 50 and result["outcome"] == "standard_review"
    assert "new_device" in result["missing_data"]
    with pytest.raises(ValueError):
        consistency({"claim": "other"}, snap({}))


# ---- learning


def test_confirmed_fraud_recipient_rescoring_finds_likely_victims() -> None:
    quiet = {"txn_id": "T1", "sender": "alice", "recipient": "mule-1", "amount_zscore_90d": 4, "new_payee": True,
             "recipient_hops_to_fraud": 2, "payment_reference": "investment", "amount_extreme_vs_peers": True,
             "typing_deviation": True}  # fmt: skip
    other = {"txn_id": "T2", "sender": "bob", "recipient": "shop-9", "amount_zscore_90d": 4}
    snaps = [snap(quiet), snap(other)]
    assert snaps[0]["decision"]["band"] == "step_up"
    alerts = rescore_payers(snaps, "mule-1")
    assert [a["txn_id"] for a in alerts] == ["T1"]
    assert alerts[0]["score_now"] >= 60 > alerts[0]["score_at_the_time"]


def test_gap_report_and_scam_library_group_what_got_through() -> None:
    slipped = {**MULE, "recipient_passthrough_ratio_30m": 0.79}
    report = gap_report(snap(slipped), "mule_activity")
    assert report["let_through"] and report["signals_just_under_threshold"][0]["signal"] == "RC1_PASS_THROUGH"
    library = scam_library([
        {"snapshot": snap(slipped), "outcome": "fraud", "typology": "mule_activity"},
        {"snapshot": snap(MULE), "outcome": "fraud", "typology": "mule_activity"},
        {"snapshot": snap(TAKEOVER), "outcome": "fraud", "typology": "takeover"},
        {"snapshot": snap(SCAM), "outcome": "legitimate", "typology": None},
    ])  # fmt: skip
    mule = library["mule_activity"]
    assert (mule["cases"], mule["held_or_blocked"], mule["let_through"]) == (2, 1, 1)
    assert mule["thresholds_most_often_just_missed"] == [("RC1_PASS_THROUGH", 1)]
    assert library["takeover"]["cases"] == 1 and library["_false_alarms"] == {"cases": 1, "held_or_blocked": 1}
