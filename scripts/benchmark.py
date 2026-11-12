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
]
SLOWED = {"step_up", "warn_and_delay", "hold_review", "block"}  # anything except a straight allow
STOPPED = {"hold_review", "block"}  # no money moves without a reviewer


def run() -> dict[str, Any]:
    r = random.Random(SEED)  # noqa: S311 - a reproducible simulation, not security
    rows, totals = [], {"legit": Counter(), "fraud": Counter()}
    for label, scenarios in (("legit", LEGIT), ("fraud", FRAUD)):
        for make, n in scenarios:
            actions = Counter(decide(make(r))["action"] for _ in range(n))
            slowed, stopped = sum(actions[a] for a in SLOWED), sum(actions[a] for a in STOPPED)
            rows.append((label, make.__name__, n, slowed, stopped))
            totals[label].update(n=n, slowed=slowed, stopped=stopped)
    lt, ft = totals["legit"], totals["fraud"]
    return {
        "rows": rows,
        "legit": lt,
        "fraud": ft,
        "detection_any": ft["slowed"] / ft["n"],
        "detection_stopped": ft["stopped"] / ft["n"],
        "false_positive_any": lt["slowed"] / lt["n"],
        "false_positive_stopped": lt["stopped"] / lt["n"],
        "precision_any": ft["slowed"] / max(1, ft["slowed"] + lt["slowed"]),
    }


def report(result: dict[str, Any]) -> str:
    pct = lambda x: f"{100 * x:.1f}%"  # noqa: E731
    out = [
        f"# Benchmark: risk engine ruleset {RULESET_VERSION} on simulated payments (seed {SEED})",
        "",
        "**Simulated data, written by the authors of the rules. This is not real-world accuracy.**",
        'Reproduce with `python scripts/benchmark.py`. "Slowed" = anything but a straight allow '
        '(confirm payee, delay, hold, block). "Stopped" = held or blocked.',
        "",
        "| Class | Scenario | Payments | Slowed | Stopped |",
        "|---|---|---|---|---|",
    ]
    for label, name, n, slowed, stopped in result["rows"]:
        out.append(
            f"| {label} | {name.split('_', 1)[1].replace('_', ' ')} | {n} | {pct(slowed / n)} | {pct(stopped / n)} |"
        )
    lt, ft = result["legit"], result["fraud"]
    out += [
        "",
        "| Measure | Value |",
        "|---|---|",
        f"| Fraud slowed or stopped (recall) | {pct(result['detection_any'])} of {ft['n']} |",
        f"| Fraud stopped outright | {pct(result['detection_stopped'])} |",
        f"| Legitimate payments slowed (false-positive rate) | {pct(result['false_positive_any'])} of {lt['n']} |",
        f"| Legitimate payments stopped | {pct(result['false_positive_stopped'])} |",
        f"| Of everything slowed, share that was fraud (precision at this mix) | {pct(result['precision_any'])} |",
        "",
        f"The mix is {ft['n']} fraud in {ft['n'] + lt['n']} payments, far more fraud than real traffic has, so the "
        "precision figure would be much lower in production.",
    ]
    return "\n".join(out)


if __name__ == "__main__":
    text = report(run())
    print(text)
    if "--write" in sys.argv:
        Path(__file__).resolve().parent.parent.joinpath("BENCHMARK.md").write_text(text + "\n", encoding="utf-8")
