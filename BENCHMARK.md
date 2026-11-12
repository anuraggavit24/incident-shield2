# Benchmark: risk engine ruleset 2026.11-3 on simulated payments (seed 20261112)

**Simulated data, written by the authors of the rules. This is not real-world accuracy.**
Reproduce with `python scripts/benchmark.py`. "Slowed" = anything but a straight allow (confirm payee, delay, hold, block). "Stopped" = held or blocked.

## What to take from this

- On fraud it was not written around (the held-out set), the engine slows or stops **0.0%** of cases and **0.0%** of the money. On the tuning set the figures are 35.4% and 35.8%. The gap between the two is the main finding.
- **It misses these tuning-set fraud types completely (0% slowed):** takeover patient, scam bland, mule careful, card testing, takeover small amounts, mule aged account, ring member.
- **The cost to honest users is concentrated:** 47.5% of "new phone new payee" payments are stopped outright. Overall false-positive rates hide this because such groups are small.
- **Review load:** 0.0 cases per 1,000 payments on the held-out mix. Human review capacity, not recall, is what limits a real system.
- No precision figure is given: it depends on the share of fraud in the mix, which is an assumption here (0.5% for the review-load lines).

## Held-out set (v2)

Written after the last rule change and scored once. No rule, threshold, floor or model may be changed because of this table; if anything changes, these scenarios move to the tuning set and new ones are written. The first held-out set (v1, 9.4% recall on ruleset 2026.11-2) was retired that way when the graph signals were added.

| Class | Scenario | Payments | Slowed | Stopped |
|---|---|---|---|---|
| legit | colleague on office pc | 40 | 0.0% | 0.0% |
| legit | shop paying suppliers | 40 | 0.0% | 0.0% |
| legit | gift while on a call | 40 | 0.0% | 0.0% |
| legit | student new phone rent | 40 | 5.0% | 0.0% |
| fraud | sim swap takeover | 40 | 0.0% | 0.0% |
| fraud | romance repeat payee | 40 | 0.0% | 0.0% |
| fraud | layering mule | 40 | 0.0% | 0.0% |
| fraud | fresh ring account | 40 | 0.0% | 0.0% |

- Fraud slowed or stopped (recall): **0.0%** of 160; stopped outright: 0.0%
- Fraud money slowed or stopped: **0.0%** of $190,738; **$190,738 went straight through**
- Legitimate payments slowed (false-positive rate): **1.2%** of 160; stopped outright: 0.0%
- Review load at 0.5% fraud: **0.0 cases per 1,000 payments** need a human

## Rules compared with the shadow model

A logistic regression over "which signals fired", trained on a separate random draw of the tuning scenarios. It runs in shadow mode in the app and decides nothing. **Trained on simulated data, it can only see what the rules already extract, so it mostly learns the rules back.** The comparison shows the method, not a gain.

| Set | Fraud flagged: rules | model | either | Legit flagged: rules | model | either |
|---|---|---|---|---|---|---|
| Tuning | 35.4% | 43.2% | 49.2% | 1.8% | 0.3% | 2.0% |
| Held-out v2 | 0.0% | 1.9% | 1.9% | 1.2% | 25.0% | 25.0% |

## Tuning set

Rules have been changed with these numbers in view, so they flatter the engine. It includes the retired held-out v1 scenarios. One floor (`CONFIRMED_FRAUD_RECIPIENT`) was added because "known bad recipient" scored 15% here; its 100% now is the rule fitted to its own test.

| Class | Scenario | Payments | Slowed | Stopped |
|---|---|---|---|---|
| legit | repeat | 560 | 0.0% | 0.0% |
| legit | new payee small | 160 | 0.0% | 0.0% |
| legit | big one off | 50 | 0.0% | 0.0% |
| legit | new phone | 60 | 0.0% | 0.0% |
| legit | new phone new payee | 40 | 47.5% | 47.5% |
| legit | vpn | 40 | 0.0% | 0.0% |
| legit | pays busy new seller | 40 | 0.0% | 0.0% |
| legit | scammy reference | 25 | 0.0% | 0.0% |
| legit | shared household | 25 | 0.0% | 0.0% |
| legit | first rent | 40 | 0.0% | 0.0% |
| legit | traveller | 40 | 0.0% | 0.0% |
| legit | charity appeal | 40 | 0.0% | 0.0% |
| legit | reset then big payment | 40 | 5.0% | 0.0% |
| fraud | takeover | 40 | 100.0% | 100.0% |
| fraud | takeover patient | 25 | 0.0% | 0.0% |
| fraud | takeover session hijack | 25 | 8.0% | 0.0% |
| fraud | scam coached | 40 | 80.0% | 80.0% |
| fraud | scam bland | 30 | 0.0% | 0.0% |
| fraud | mule recipient | 30 | 100.0% | 100.0% |
| fraud | mule careful | 25 | 0.0% | 0.0% |
| fraud | known bad recipient | 20 | 100.0% | 100.0% |
| fraud | card testing | 20 | 0.0% | 0.0% |
| fraud | device farm | 20 | 100.0% | 100.0% |
| fraud | takeover small amounts | 40 | 0.0% | 0.0% |
| fraud | scam from new phone | 40 | 25.0% | 0.0% |
| fraud | mule aged account | 40 | 0.0% | 0.0% |
| fraud | ring member | 40 | 0.0% | 0.0% |

- Fraud slowed or stopped (recall): **35.4%** of 435; stopped outright: 32.6%
- Fraud money slowed or stopped: **35.8%** of $486,285; **$312,245 went straight through**
- Legitimate payments slowed (false-positive rate): **1.8%** of 1160; stopped outright: 1.6%
- Review load at 0.5% fraud: **17.9 cases per 1,000 payments** need a human; about $44 of review per fraud case stopped (at $4 a review)
