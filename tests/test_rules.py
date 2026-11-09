"""Guard rules: attack scenarios AND normal activity that must not alert."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from decimal import Decimal

from app.rules import RuleTxn, detect_mule_sequence, evaluate

T0 = datetime(2026, 11, 8, 10, 0, tzinfo=timezone.utc)


def tx(pid, minutes, direction="in", usd="50.00", currency="USD", sender=None, status="COMPLETED", strength="weak"):
    return RuleTxn(
        paypal_id=pid,
        direction=direction,
        amount_usd=Decimal(usd) if usd is not None else None,
        currency=currency,
        counterparty_key=sender,
        identity_strength=strength,
        occurred_at=T0 + timedelta(minutes=minutes),
        status=status,
    )


def rule_ids(hits):
    return sorted(h.rule_id for h in hits)


def attack(prefix="a"):
    return [
        tx(f"{prefix}probe", 0, usd="0.79", sender="card:echo"),
        tx(f"{prefix}b1", 5, usd="60.00", sender="card:alpha"),
        tx(f"{prefix}b2", 6, usd="144.37", currency="EUR", sender="card:bravo"),
        tx(f"{prefix}b3", 7, usd="79.22", currency="GBP", sender="card:charlie"),
        tx(f"{prefix}out", 9, direction="out", usd="250.00", sender="payout:exchange", strength="strong"),
    ]


def test_normal_activity_from_repeat_buyers_raises_nothing() -> None:
    known = {"paypal:buyer1", "paypal:buyer2", "paypal:buyer3"}
    recent = [tx(f"n{i}", i * 3, sender=f"paypal:buyer{i % 3 + 1}", strength="strong") for i in range(6)]
    assert evaluate(T0 + timedelta(minutes=20), recent, known, prior_count=40) == []


def test_normal_withdrawal_without_new_senders_is_not_pass_through() -> None:
    known = {"paypal:buyer1"}
    recent = [
        tx("n1", 0, sender="paypal:buyer1", strength="strong"),
        tx("w1", 5, direction="out", usd="500.00", sender="payout:mybank", strength="strong"),
    ]
    assert evaluate(T0 + timedelta(minutes=6), recent, known, prior_count=40) == []


def test_full_mule_pattern_is_detected_as_a_sequence() -> None:
    recent = attack()
    as_of = T0 + timedelta(minutes=9)
    hits = evaluate(as_of, recent, known=set(), prior_count=40)
    # The probe alone is evaluated as of its own time in the live system; collect hits as events arrive.
    all_hits = []
    for t in recent:
        all_hits += evaluate(t.occurred_at, [r for r in recent if r.occurred_at <= t.occurred_at], set(), 40)
    assert {"R1_BURST_NEW_SENDERS", "R2_PASS_THROUGH", "R3_PROBE_PAYMENT", "R4_CURRENCY_MIX"} <= set(rule_ids(hits))
    match = detect_mule_sequence(all_hits)
    assert match is not None
    assert match.probe.transaction_ids == ("aprobe",)
    assert match.burst.window_end <= match.passthrough.window_end


def test_burst_severity_drops_when_history_is_insufficient() -> None:
    hits = evaluate(T0 + timedelta(minutes=8), attack()[:4], known=set(), prior_count=1)
    r1 = next(h for h in hits if h.rule_id == "R1_BURST_NEW_SENDERS")
    assert r1.severity == "low"
    assert r1.values["history"] == "insufficient"


def test_burst_needs_three_distinct_new_senders() -> None:
    recent = [tx("x1", 0, sender="card:a"), tx("x2", 1, sender="card:a"), tx("x3", 2, sender="card:b")]
    hits = evaluate(T0 + timedelta(minutes=3), recent, known=set(), prior_count=40)
    assert "R1_BURST_NEW_SENDERS" not in rule_ids(hits)


def test_unknown_identity_counts_as_new_so_missing_data_cannot_hide_a_burst() -> None:
    recent = [tx(f"u{i}", i, sender=None) for i in range(3)]
    hits = evaluate(T0 + timedelta(minutes=3), recent, known=set(), prior_count=40)
    assert "R1_BURST_NEW_SENDERS" in rule_ids(hits)


def test_probe_from_known_sender_is_not_flagged() -> None:
    recent = [tx("p", 0, usd="0.50", sender="paypal:buyer1", strength="strong")]
    assert evaluate(T0 + timedelta(minutes=1), recent, known={"paypal:buyer1"}, prior_count=40) == []


def test_probe_boundary_one_dollar_is_not_a_probe() -> None:
    recent = [tx("p", 0, usd="1.00", sender="card:z")]
    assert "R3_PROBE_PAYMENT" not in rule_ids(evaluate(T0 + timedelta(minutes=1), recent, set(), 40))


def test_currency_mix_counts_original_currencies_only() -> None:
    recent = [tx("c1", 0, currency="USD"), tx("c2", 1, currency="USD"), tx("c3", 2, currency="EUR")]
    assert "R4_CURRENCY_MIX" not in rule_ids(evaluate(T0 + timedelta(minutes=3), recent, set(), 40))


def test_pending_and_failed_transactions_are_not_counted() -> None:
    recent = [tx(f"f{i}", i, sender=f"card:{i}", status="DECLINED") for i in range(5)]
    assert evaluate(T0 + timedelta(minutes=5), recent, set(), 40) == []


def test_events_outside_the_window_are_ignored() -> None:
    recent = [tx(f"old{i}", -90 + i, sender=f"card:{i}") for i in range(5)]
    assert evaluate(T0, recent, set(), 40) == []


def test_sequence_requires_order_and_time_gap() -> None:
    late = attack("l")
    # Money out 3 hours after the burst: not the same pattern.
    late[-1] = tx("lout", 200, direction="out", usd="250.00", sender="payout:x", strength="strong")
    hits = []
    for t in late:
        hits += evaluate(t.occurred_at, [r for r in late if r.occurred_at <= t.occurred_at], set(), 40)
    assert detect_mule_sequence(hits) is None


def test_hits_are_deterministic_and_deduplicable() -> None:
    a = evaluate(T0 + timedelta(minutes=9), attack(), set(), 40)
    b = evaluate(T0 + timedelta(minutes=9), attack(), set(), 40)
    assert [h.dedupe_key for h in a] == [h.dedupe_key for h in b]
