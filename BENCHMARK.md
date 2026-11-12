# Benchmark: risk engine ruleset 2026.11-2 on simulated payments (seed 20261112)

**Simulated data, written by the authors of the rules. This is not real-world accuracy.**
Reproduce with `python scripts/benchmark.py`. "Slowed" = anything but a straight allow (confirm payee, delay, hold, block). "Stopped" = held or blocked.

## What to take from this

- The engine slows or stops **53.8%** of the simulated fraud in the tuning set and **9.4%** in the held-out set.
- **It misses these fraud types completely (0% slowed):** takeover patient, scam bland, mule careful, card testing. Each one stays just under a threshold or uses data the app doesn't have.
- **The cost to honest users is concentrated:** 27.5% of "new phone new payee" payments are stopped outright, about one in four people who set up a new phone, reset their password and pay someone new. The overall false-positive rate (1.2%) hides this because that group is small.
- No precision figure is given: it depends on the share of fraud in the mix, which here was chosen by hand and is far higher than in real traffic.

## Tuning set

Rules have been changed with these numbers in view, so they flatter the engine. One floor (`CONFIRMED_FRAUD_RECIPIENT`) was added because "known bad recipient" scored 15% here; its 100% now is the rule fitted to its own test, not evidence that the rule generalises.

| Class | Scenario | Payments | Slowed | Stopped |
|---|---|---|---|---|
| legit | repeat | 560 | 0.0% | 0.0% |
| legit | new payee small | 160 | 0.0% | 0.0% |
| legit | big one off | 50 | 0.0% | 0.0% |
| legit | new phone | 60 | 0.0% | 0.0% |
| legit | new phone new payee | 40 | 27.5% | 27.5% |
| legit | vpn | 40 | 0.0% | 0.0% |
| legit | pays busy new seller | 40 | 0.0% | 0.0% |
| legit | scammy reference | 25 | 4.0% | 4.0% |
| legit | shared household | 25 | 0.0% | 0.0% |
| fraud | takeover | 40 | 100.0% | 100.0% |
| fraud | takeover patient | 25 | 0.0% | 0.0% |
| fraud | takeover session hijack | 25 | 4.0% | 0.0% |
| fraud | scam coached | 40 | 92.5% | 92.5% |
| fraud | scam bland | 30 | 0.0% | 0.0% |
| fraud | mule recipient | 30 | 100.0% | 100.0% |
| fraud | mule careful | 25 | 0.0% | 0.0% |
| fraud | known bad recipient | 20 | 100.0% | 100.0% |
| fraud | card testing | 20 | 0.0% | 0.0% |
| fraud | device farm | 20 | 100.0% | 100.0% |

- Fraud slowed or stopped (recall): **53.8%** of 275; stopped outright: 53.5%
- Legitimate payments slowed (false-positive rate): **1.2%** of 1000; stopped outright: 1.2%

## Held-out set

Written after the last rule change and scored once. No rule, threshold or floor may be changed because of this table; if the rules change, these scenarios are replaced.

| Class | Scenario | Payments | Slowed | Stopped |
|---|---|---|---|---|
| legit | first rent | 40 | 0.0% | 0.0% |
| legit | traveller | 40 | 0.0% | 0.0% |
| legit | charity appeal | 40 | 0.0% | 0.0% |
| legit | reset then big payment | 40 | 2.5% | 0.0% |
| fraud | takeover small amounts | 40 | 0.0% | 0.0% |
| fraud | scam from new phone | 40 | 37.5% | 0.0% |
| fraud | mule aged account | 40 | 0.0% | 0.0% |
| fraud | ring member | 40 | 0.0% | 0.0% |

- Fraud slowed or stopped (recall): **9.4%** of 160; stopped outright: 0.0%
- Legitimate payments slowed (false-positive rate): **0.6%** of 160; stopped outright: 0.0%
