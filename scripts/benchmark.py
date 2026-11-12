"""Measure the risk engine on labelled, SIMULATED payments. Run: python scripts/benchmark.py

What this is: a fixed-seed generator of legitimate and fraudulent payments, built only from evidence the
payment app can really produce (plus the seven demo-simulated signals at partial availability), scored by
the same decide() the app uses. It reports how often fraud is slowed or stopped and how often legitimate
payments are, per scenario, including "evasive" fraud that stays just under each threshold.

What this is NOT: a measure of real-world accuracy. The scenarios were written by the people who wrote the
rules, so the full-pattern rows mostly confirm the rules do what they say. The useful rows are the evasive
ones and the awkward legitimate ones: they show where the engine fails. Real rates need labelled production
data, which a sandbox project doesn't have.
"""

from __future__ import annotations

import random
import sys
from collections import Counter
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.risk.engine import RULESET_VERSION, decide  # noqa: E402

SEED = 20261112
NEVER = 1_000_000  # "no credential change on record"


def base(r: random.Random) -> dict[str, Any]:
    """An established customer paying someone they have paid before, from their usual device."""
    tenure = r.randint(90, 1500)
    return {
        "account_tenure_days": tenure,
        "account_disputes": 0,
        "dormant_days": r.randint(0, 20),
        "is_high_value": False,
        "recipient_prior_payments": r.randint(3, 30),
        "new_payee": False,
        "recipient_relationship_days": r.randint(60, 700),
        "recipient_disputes_by_sender": 0,
        "matches_recurring_pattern": r.random() < 0.4,
        "payee_name_mismatch": False,
        "new_device": False,
        "device_seen_days": r.randint(30, 600),
        "network_seen_days": r.randint(30, 600),
        "fresh_device_on_old_account": False,
        "fingerprint_inconsistent": False,
        "credential_change_hours_ago": NEVER,
        "amount_zscore_90d": round(r.uniform(-1, 1.5), 2),
        "amount_vs_norm_ratio": round(r.uniform(0.5, 1.6), 2),
        "new_recipients_24h": 0,
        "spend_1h_vs_daily_avg_ratio": round(r.uniform(0.2, 2.5), 2),
        "amounts_just_under_threshold_24h": 0,
        "card_testing_pattern": False,
        "declined_retry_altered_amount": False,
        "accounts_on_device_or_ip_7d": r.choice([1, 1, 1, 2]),
        "accounts_on_device_7d": 1,
        "device_linked_to_fraud": False,
        "ip_shared_with_fraud_accounts": False,
        "recipient_account_age_days": r.randint(120, 2000),
        "recipient_senders_7d": r.randint(1, 4),
        "recipient_passthrough_ratio_30m": round(r.uniform(0, 0.3), 2),
        "recipient_prior_complaints": 0,
        "recipient_hops_to_fraud": 99,
        "on_negative_list": False,
        "payment_reference": r.choice(["rent", "lunch", "thanks", "invoice 2231", "birthday", "", "tickets"]),
        "scripted_input": False,
        "coaching_signs": r.random() < 0.03,  # people do get interrupted while paying
        "typing_deviation": r.random() < 0.05,
        "direct_to_new_payee_max_amount": False,
        "recipient_fan_out_1h": r.choice([0, 0, 0, 1]),
        "recipient_device_ring_size": 1,
    }


def to_new_payee(e: dict[str, Any], r: random.Random) -> dict[str, Any]:
    e.update(
        new_payee=True,
        recipient_prior_payments=0,
        recipient_relationship_days=0,
        matches_recurring_pattern=False,
        new_recipients_24h=1,
        payee_name_mismatch=r.random() < 0.1,
    )
    return e


def on_new_device(e: dict[str, Any]) -> dict[str, Any]:
    e.update(new_device=True, device_seen_days=0, network_seen_days=0, fresh_device_on_old_account=True)
    return e


# ---------------------------------------------------------------- legitimate scenarios


def legit_repeat(r):
    return base(r)


def legit_new_payee_small(r):
    return to_new_payee(base(r), r)


def legit_big_one_off(r):  # a deposit or a used car: new payee, far above the usual amount
    e = to_new_payee(base(r), r)
    e.update(
        amount_zscore_90d=round(r.uniform(3.2, 8), 2),
        amount_vs_norm_ratio=round(r.uniform(3.5, 12), 2),
        is_high_value=True,
        direct_to_new_payee_max_amount=True,
        spend_1h_vs_daily_avg_ratio=r.uniform(4, 12),
    )
    return e


def legit_new_phone(r):
    return on_new_device(base(r))


def legit_new_phone_new_payee(r):  # new phone, password reset while setting it up, then pays someone new
    e = on_new_device(to_new_payee(base(r), r))
    e.update(credential_change_hours_ago=r.randint(1, 60), amount_vs_norm_ratio=round(r.uniform(0.6, 4.5), 2))
    return e


def legit_vpn(r):
    e = base(r)
    e.update(anonymising_asn=True, network_seen_days=0)
    return e


def legit_pays_busy_new_seller(r):  # a new but honest marketplace seller: many buyers, young account
    e = to_new_payee(base(r), r)
    e.update(
        recipient_account_age_days=r.randint(5, 55),
        recipient_senders_7d=r.randint(5, 25),
        recipient_passthrough_ratio_30m=round(r.uniform(0, 0.6), 2),
    )
    return e


def legit_scammy_reference(r):  # innocent wording that contains a marker word
    e = to_new_payee(base(r), r)
    e["payment_reference"] = r.choice(
        ["council tax share", "investment club dues", "taxi and tax", "kids investment acct"]
    )
    return e


def legit_shared_household(r):  # family or flatmates on one network and tablet
    e = base(r)
    e.update(accounts_on_device_or_ip_7d=r.randint(3, 5), accounts_on_device_7d=r.randint(2, 4))
    return e


# ---------------------------------------------------------------- fraud scenarios


def fraud_takeover(r):
    e = on_new_device(to_new_payee(base(r), r))
    e.update(
        credential_change_hours_ago=r.randint(0, 48),
        amount_vs_norm_ratio=round(r.uniform(3.5, 15), 2),
        amount_zscore_90d=round(r.uniform(3.2, 9), 2),
        is_high_value=True,
        direct_to_new_payee_max_amount=True,
    )
    if r.random() < 0.3:
        e["credentials_in_breach"] = True
    return e


def fraud_takeover_patient(r):  # evasive: waits out the 72 hours and keeps the amount under 3x
    e = on_new_device(to_new_payee(base(r), r))
    e.update(
        credential_change_hours_ago=r.randint(73, 200),
        amount_vs_norm_ratio=round(r.uniform(2.0, 2.9), 2),
        amount_zscore_90d=round(r.uniform(1.5, 2.9), 2),
    )
    return e


def fraud_takeover_session_hijack(r):  # evasive: acts from the victim's own device, changes nothing
    e = to_new_payee(base(r), r)
    e.update(
        amount_vs_norm_ratio=round(r.uniform(3.5, 10), 2),
        amount_zscore_90d=round(r.uniform(3.2, 8), 2),
        is_high_value=True,
        direct_to_new_payee_max_amount=True,
    )
    if r.random() < 0.5:
        e["remote_access_or_overlay"] = True  # only seen when that signal happens to be available
    return e


def fraud_scam_coached(r):
    e = to_new_payee(base(r), r)
    e.update(
        payment_reference=r.choice(["move to safe account", "release fee", "investment deposit", "tax payment"]),
        coaching_signs=r.random() < 0.7,
        direct_to_new_payee_max_amount=r.random() < 0.7,
        amount_vs_norm_ratio=round(r.uniform(2, 10), 2),
    )
    if r.random() < 0.6:
        e["active_call"] = True
    return e


def fraud_scam_bland(r):  # evasive: victim told to write an ordinary reference and stay off the phone signal
    e = to_new_payee(base(r), r)
    e.update(
        payment_reference=r.choice(["family help", "gift", "loan repayment", "holiday"]),
        coaching_signs=r.random() < 0.3,
        direct_to_new_payee_max_amount=r.random() < 0.6,
        amount_vs_norm_ratio=round(r.uniform(2, 8), 2),
    )
    return e


def fraud_mule_recipient(r):
    e = to_new_payee(base(r), r)
    e.update(
        recipient_account_age_days=r.randint(1, 50),
        recipient_senders_7d=r.randint(5, 30),
        recipient_passthrough_ratio_30m=round(r.uniform(0.82, 1.0), 2),
    )
    return e


def fraud_mule_careful(r):  # evasive: keeps 21%+ and spreads senders
    e = to_new_payee(base(r), r)
    e.update(
        recipient_account_age_days=r.randint(1, 50),
        recipient_senders_7d=r.randint(2, 4),
        recipient_passthrough_ratio_30m=round(r.uniform(0.6, 0.79), 2),
    )
    return e


def fraud_known_bad_recipient(r):  # the payee already has a confirmed complaint
    e = to_new_payee(base(r), r)
    e.update(recipient_prior_complaints=r.randint(1, 4), recipient_hops_to_fraud=0, on_negative_list=True)
    return e


def fraud_card_testing(r):  # the app has no card data, so the card-testing floor can never complete
    e = to_new_payee(base(r), r)
    e.update(
        card_testing_pattern=True,
        new_recipients_24h=r.randint(1, 5),
        account_tenure_days=r.randint(0, 5),
        device_seen_days=0,
        network_seen_days=0,
        new_device=False,
        dormant_days=0,
    )
    return e


def fraud_device_farm(r):
    e = to_new_payee(base(r), r)
    e.update(
        accounts_on_device_7d=r.randint(5, 12),
        accounts_on_device_or_ip_7d=r.randint(5, 12),
        account_tenure_days=r.randint(0, 10),
    )
    return e


# ---------------------------------------------------------------- held-out scenarios
#
# RETIRED held-out set (v1). It was scored once against ruleset 2026.11-2 (9.4% of its fraud slowed). The
# rules then changed (graph signals RC8 and RC9, ruleset 2026.11-3), so by the rule further down these
# scenarios moved into the tuning set and a new held-out set (v2) was written.


def held_fraud_takeover_small_amounts(r):  # attacker drains in ordinary-sized payments
    e = on_new_device(to_new_payee(base(r), r))
    e.update(
        credential_change_hours_ago=r.randint(1, 24),
        amount_vs_norm_ratio=round(r.uniform(0.8, 1.8), 2),
        new_recipients_24h=r.randint(1, 2),
    )
    return e


def held_fraud_scam_from_new_phone(r):  # victim coached on a phone they bought last week
    e = on_new_device(to_new_payee(base(r), r))
    e.update(
        payment_reference=r.choice(["move to safe account", "investment deposit"]),
        coaching_signs=True,
        amount_vs_norm_ratio=round(r.uniform(2, 8), 2),
        direct_to_new_payee_max_amount=True,
    )
    if r.random() < 0.6:
        e["active_call"] = True
    return e


def held_fraud_mule_aged_account(r):  # a bought or dormant account, well past 60 days old
    e = to_new_payee(base(r), r)
    e.update(
        recipient_account_age_days=r.randint(90, 900),
        recipient_senders_7d=r.randint(6, 30),
        recipient_passthrough_ratio_30m=round(r.uniform(0.85, 1.0), 2),
    )
    return e


def held_fraud_ring_member(r):  # fresh account one step from a confirmed fraud account, 3 accounts on the device
    e = to_new_payee(base(r), r)
    e.update(
        recipient_hops_to_fraud=1,
        recipient_account_age_days=r.randint(0, 20),
        accounts_on_device_7d=3,
        accounts_on_device_or_ip_7d=3,
    )
    return e


def held_legit_first_rent(r):  # brand-new account, no history at all, large first payment
    e = to_new_payee(base(r), r)
    for key in (
        "amount_zscore_90d",
        "amount_vs_norm_ratio",
        "spend_1h_vs_daily_avg_ratio",
        "dormant_days",
        "new_device",
        "device_seen_days",
        "network_seen_days",
        "fresh_device_on_old_account",
        "fingerprint_inconsistent",
        "direct_to_new_payee_max_amount",
        "typing_deviation",
    ):
        e.pop(key, None)
    e.update(account_tenure_days=r.randint(0, 5), is_high_value=True, payment_reference="deposit and first month")
    return e


def held_legit_traveller(r):  # usual device, unfamiliar network, usual payee
    e = base(r)
    e.update(network_seen_days=0, anonymising_asn=r.random() < 0.3)
    return e


def held_legit_charity_appeal(r):  # an old, well-known payee with dozens of new donors this week
    e = to_new_payee(base(r), r)
    e.update(
        recipient_senders_7d=r.randint(20, 80),
        recipient_account_age_days=r.randint(400, 3000),
        recipient_passthrough_ratio_30m=round(r.uniform(0, 0.9), 2),
    )
    return e


def held_legit_reset_then_big_payment(r):  # forgot password, reset it on the usual device, paid a builder
    e = to_new_payee(base(r), r)
    e.update(
        credential_change_hours_ago=r.randint(0, 24),
        amount_vs_norm_ratio=round(r.uniform(3.5, 9), 2),
        amount_zscore_90d=round(r.uniform(3.2, 7), 2),
        is_high_value=True,
        direct_to_new_payee_max_amount=True,
    )
    return e


RETIRED_LEGIT = [
    (held_legit_first_rent, 40),
    (held_legit_traveller, 40),
    (held_legit_charity_appeal, 40),
    (held_legit_reset_then_big_payment, 40),
]
RETIRED_FRAUD = [
    (held_fraud_takeover_small_amounts, 40),
    (held_fraud_scam_from_new_phone, 40),
    (held_fraud_mule_aged_account, 40),
    (held_fraud_ring_member, 40),
]

# ---------------------------------------------------------------- held-out set v2
#
# Written on 2026-11-12 AFTER ruleset 2026.11-3 and scored once. Rule for this section: never change a rule,
# threshold, floor or model because of a number in the held-out table. If anything is changed for any reason,
# these scenarios move to the tuning set and new ones are written. In real use the held-out set would be
# payments from a LATER time period than anything used for tuning or training; simulated data can only
# imitate that by being written afterwards.


def v2_fraud_sim_swap_takeover(r):  # SIM swapped, attacker on a new device, no credential change needed
    e = on_new_device(to_new_payee(base(r), r))
    e.update(amount_vs_norm_ratio=round(r.uniform(1.5, 2.9), 2))
    if r.random() < 0.5:  # the telecom signal is only sometimes available
        e["sim_swap_days_ago"] = r.randint(0, 5)
    return e


def v2_fraud_romance_repeat_payee(r):  # the "partner" has been paid twice before, so not a new payee
    e = base(r)
    e.update(
        recipient_prior_payments=2,
        recipient_relationship_days=r.randint(10, 40),
        matches_recurring_pattern=False,
        payment_reference=r.choice(["for your flight", "hospital bill", "customs for the parcel"]),
        amount_vs_norm_ratio=round(r.uniform(2, 6), 2),
        coaching_signs=r.random() < 0.5,
    )
    return e


def v2_fraud_layering_mule(r):  # an old account that forwards money to several accounts within the hour
    e = to_new_payee(base(r), r)
    e.update(
        recipient_account_age_days=r.randint(200, 900),
        recipient_fan_out_1h=r.randint(3, 8),
        recipient_passthrough_ratio_30m=round(r.uniform(0.5, 0.79), 2),
        recipient_senders_7d=r.randint(3, 9),
    )
    return e


def v2_fraud_fresh_ring_account(r):  # one of several new accounts run from the same device
    e = to_new_payee(base(r), r)
    e.update(recipient_account_age_days=r.randint(0, 6), recipient_device_ring_size=r.randint(2, 5))
    return e


def v2_legit_colleague_on_office_pc(r):  # payee uses a shared office computer with three colleagues
    e = to_new_payee(base(r), r)
    e.update(recipient_device_ring_size=4, accounts_on_device_or_ip_7d=r.randint(2, 4))
    return e


def v2_legit_shop_paying_suppliers(r):  # a busy shop that pays several suppliers soon after takings arrive
    e = base(r)
    e.update(
        recipient_fan_out_1h=r.randint(4, 7),
        recipient_senders_7d=r.randint(10, 60),
        recipient_account_age_days=r.randint(300, 2500),
    )
    return e


def v2_legit_gift_while_on_a_call(r):  # sending a birthday gift to someone new while chatting on the phone
    e = to_new_payee(base(r), r)
    e.update(payment_reference="happy birthday", active_call=True)
    return e


def v2_legit_student_new_phone_rent(r):  # new phone, first rent to a new landlord, far above usual spending
    e = on_new_device(to_new_payee(base(r), r))
    e.update(
        amount_vs_norm_ratio=round(r.uniform(4, 15), 2),
        amount_zscore_90d=round(r.uniform(3.2, 9), 2),
        is_high_value=True,
        direct_to_new_payee_max_amount=True,
        payment_reference="rent",
    )
    return e


HELD_LEGIT = [
    (v2_legit_colleague_on_office_pc, 40),
    (v2_legit_shop_paying_suppliers, 40),
    (v2_legit_gift_while_on_a_call, 40),
    (v2_legit_student_new_phone_rent, 40),
]
HELD_FRAUD = [
    (v2_fraud_sim_swap_takeover, 40),
    (v2_fraud_romance_repeat_payee, 40),
    (v2_fraud_layering_mule, 40),
    (v2_fraud_fresh_ring_account, 40),
]

LEGIT = [
    (legit_repeat, 560),
    (legit_new_payee_small, 160),
    (legit_big_one_off, 50),
    (legit_new_phone, 60),
    (legit_new_phone_new_payee, 40),
    (legit_vpn, 40),
    (legit_pays_busy_new_seller, 40),
    (legit_scammy_reference, 25),
    (legit_shared_household, 25),
    *RETIRED_LEGIT,
]
FRAUD = [
    (fraud_takeover, 40),
    (fraud_takeover_patient, 25),
    (fraud_takeover_session_hijack, 25),
    (fraud_scam_coached, 40),
    (fraud_scam_bland, 30),
    (fraud_mule_recipient, 30),
    (fraud_mule_careful, 25),
    (fraud_known_bad_recipient, 20),
    (fraud_card_testing, 20),
    (fraud_device_farm, 20),
    *RETIRED_FRAUD,
]
SLOWED = {"step_up", "warn_and_delay", "hold_review", "block"}  # anything except a straight allow
STOPPED = {"hold_review", "block"}  # no money moves without a reviewer


FRAUD_SHARE = 0.005  # share of payments that are fraud in the "realistic mix" figures (an assumption)
REVIEW_COST_USD = 4  # assumed cost of one human review, for the cost-per-case line


def _amount(r: random.Random, label: str) -> float:
    """Simulated payment size. Fraud is drawn larger, and with a long tail, as it is in practice."""
    if label == "legit":
        return round(r.choice([8, 15, 25, 40, 60, 90, 150, 400]) * r.uniform(0.7, 1.3), 2)
    return round(r.choice([40, 90, 150, 300, 600, 900, 2500, 5000]) * r.uniform(0.7, 1.3), 2)


def _score(r: random.Random, legit: list, fraud: list, model: dict | None = None) -> dict[str, Any]:
    from app.risk import model as shadow

    rows, t = [], {"legit": Counter(), "fraud": Counter()}
    for label, scenarios in (("legit", legit), ("fraud", fraud)):
        for make, n in scenarios:
            slowed = stopped = m_slowed = either = 0
            for _ in range(n):
                decision = decide(make(r))
                amount = _amount(r, label)
                is_slowed, is_stopped = decision["action"] in SLOWED, decision["action"] in STOPPED
                m_hit = bool(model) and shadow.predict(model, shadow.features_of(decision)) >= 0.5
                slowed += is_slowed
                stopped += is_stopped
                m_slowed += m_hit
                either += is_slowed or m_hit
                t[label].update(
                    n=1,
                    slowed=is_slowed,
                    stopped=is_stopped,
                    model=m_hit,
                    either=is_slowed or m_hit,
                    money=amount,
                    money_slowed=amount if is_slowed else 0,
                )
            rows.append((label, make.__name__, n, slowed, stopped, m_slowed, either))
    lt, ft = t["legit"], t["fraud"]
    review_load = 1000 * ((1 - FRAUD_SHARE) * lt["stopped"] / lt["n"] + FRAUD_SHARE * ft["stopped"] / ft["n"])
    frauds_stopped_per_1000 = 1000 * FRAUD_SHARE * ft["stopped"] / ft["n"]
    return {
        "rows": rows,
        "legit": lt,
        "fraud": ft,
        "detection_any": ft["slowed"] / ft["n"],
        "detection_stopped": ft["stopped"] / ft["n"],
        "false_positive_any": lt["slowed"] / lt["n"],
        "false_positive_stopped": lt["stopped"] / lt["n"],
        "fraud_money_slowed": ft["money_slowed"] / ft["money"],
        "fraud_money_missed_usd": ft["money"] - ft["money_slowed"],
        "review_load_per_1000": review_load,
        "review_cost_per_fraud_stopped": (
            REVIEW_COST_USD * review_load / frauds_stopped_per_1000 if frauds_stopped_per_1000 else None
        ),
        "model_detection": ft["model"] / ft["n"],
        "model_false_positive": lt["model"] / lt["n"],
        "either_detection": ft["either"] / ft["n"],
        "either_false_positive": lt["either"] / lt["n"],
    }


def train_shadow_model() -> dict[str, Any]:
    """The shadow model, trained on a DIFFERENT random draw of the tuning scenarios than the one scored."""
    from app.risk import model as shadow

    r = random.Random(SEED + 500)  # noqa: S311
    rows = []
    for label, scenarios in ((0, LEGIT), (1, FRAUD)):
        for make, n in scenarios:
            rows += [(shadow.features_of(decide(make(r))), label) for _ in range(n)]
    return shadow.train(rows)


def run(model: dict | None = None) -> dict[str, Any]:
    """The tuning set (rules have been adjusted with these numbers in view)."""
    return _score(random.Random(SEED), LEGIT, FRAUD, model)  # noqa: S311 - a reproducible simulation, not security


def run_held_out(model: dict | None = None) -> dict[str, Any]:
    """The held-out set (see the rule above it: never tune against this)."""
    return _score(random.Random(SEED + 1), HELD_LEGIT, HELD_FRAUD, model)  # noqa: S311


def pct(x: float) -> str:
    return f"{100 * x:.1f}%"


def _title(name: str) -> str:
    return name.removeprefix("v2_").removeprefix("held_").split("_", 1)[1].replace("_", " ")


def _table(result: dict[str, Any]) -> list[str]:
    out = ["| Class | Scenario | Payments | Slowed | Stopped |", "|---|---|---|---|---|"]
    for label, name, n, slowed, stopped, _, _ in result["rows"]:
        out.append(f"| {label} | {_title(name)} | {n} | {pct(slowed / n)} | {pct(stopped / n)} |")
    lt, ft = result["legit"], result["fraud"]
    cost = result["review_cost_per_fraud_stopped"]
    out += [
        "",
        f"- Fraud slowed or stopped (recall): **{pct(result['detection_any'])}** of {ft['n']}; "
        f"stopped outright: {pct(result['detection_stopped'])}",
        f"- Fraud money slowed or stopped: **{pct(result['fraud_money_slowed'])}** of ${ft['money']:,.0f}; "
        f"**${result['fraud_money_missed_usd']:,.0f} went straight through**",
        f"- Legitimate payments slowed (false-positive rate): **{pct(result['false_positive_any'])}** of {lt['n']}; "
        f"stopped outright: {pct(result['false_positive_stopped'])}",
        f"- Review load at {pct(FRAUD_SHARE)} fraud: **{result['review_load_per_1000']:.1f} cases per 1,000 payments** "
        "need a human"
        + (f"; about ${cost:,.0f} of review per fraud case stopped (at ${REVIEW_COST_USD} a review)" if cost else ""),
    ]
    return out


def report() -> str:
    model = train_shadow_model()
    result, held = run(model), run_held_out(model)
    missed = [_title(n) for label, n, _, slowed, *_ in result["rows"] if label == "fraud" and not slowed]
    worst = max((r for r in [*result["rows"], *held["rows"]] if r[0] == "legit"), key=lambda r: r[4] / r[2])
    compare = [
        f"| {name} | {pct(x['detection_any'])} | {pct(x['model_detection'])} | {pct(x['either_detection'])} | "
        f"{pct(x['false_positive_any'])} | {pct(x['model_false_positive'])} | {pct(x['either_false_positive'])} |"
        for name, x in (("Tuning", result), ("Held-out v2", held))
    ]
    return "\n".join(
        [
            f"# Benchmark: risk engine ruleset {RULESET_VERSION} on simulated payments (seed {SEED})",
            "",
            "**Simulated data, written by the authors of the rules. This is not real-world accuracy.**",
            'Reproduce with `python scripts/benchmark.py`. "Slowed" = anything but a straight allow '
            '(confirm payee, delay, hold, block). "Stopped" = held or blocked.',
            "",
            "## What to take from this",
            "",
            "- On fraud it was not written around (the held-out set), the engine slows or stops "
            f"**{pct(held['detection_any'])}** of cases and **{pct(held['fraud_money_slowed'])}** of the money. "
            f"On the tuning set the figures are {pct(result['detection_any'])} and "
            f"{pct(result['fraud_money_slowed'])}. The gap between the two is the main finding.",
            f"- **It misses these tuning-set fraud types completely (0% slowed):** {', '.join(missed)}.",
            f'- **The cost to honest users is concentrated:** {pct(worst[4] / worst[2])} of "{_title(worst[1])}" '
            "payments are stopped outright. Overall false-positive rates hide this because such groups are small.",
            f"- **Review load:** {held['review_load_per_1000']:.1f} cases per 1,000 payments on the held-out mix. "
            "Human review capacity, not recall, is what limits a real system.",
            "- No precision figure is given: it depends on the share of fraud in the mix, which is an assumption "
            f"here ({pct(FRAUD_SHARE)} for the review-load lines).",
            "",
            "## Held-out set (v2)",
            "",
            "Written after the last rule change and scored once. No rule, threshold, floor or model may be changed "
            "because of this table; if anything changes, these scenarios move to the tuning set and new ones are "
            "written. The first held-out set (v1, 9.4% recall on ruleset 2026.11-2) was retired that way when the "
            "graph signals were added.",
            "",
            *_table(held),
            "",
            "## Rules compared with the shadow model",
            "",
            'A logistic regression over "which signals fired", trained on a separate random draw of the tuning '
            "scenarios. It runs in shadow mode in the app and decides nothing. **Trained on simulated data, it can "
            "only see what the rules already extract, so it mostly learns the rules back.** The comparison shows "
            "the method, not a gain.",
            "",
            "| Set | Fraud flagged: rules | model | either | Legit flagged: rules | model | either |",
            "|---|---|---|---|---|---|---|",
            *compare,
            "",
            "## Tuning set",
            "",
            "Rules have been changed with these numbers in view, so they flatter the engine. It includes the retired "
            'held-out v1 scenarios. One floor (`CONFIRMED_FRAUD_RECIPIENT`) was added because "known bad recipient" '
            "scored 15% here; its 100% now is the rule fitted to its own test.",
            "",
            *_table(result),
        ]
    )


if __name__ == "__main__":
    text = report()
    print(text)
    if "--write" in sys.argv:
        Path(__file__).resolve().parent.parent.joinpath("BENCHMARK.md").write_text(text + "\n", encoding="utf-8")
