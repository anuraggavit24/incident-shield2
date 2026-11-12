# Benchmark: risk engine ruleset 2026.11-2 on simulated payments (seed 20261112)

**Simulated data, written by the authors of the rules. This is not real-world accuracy.**
Reproduce with `python scripts/benchmark.py`. "Slowed" = anything but a straight allow (confirm payee, delay, hold, block). "Stopped" = held or blocked.

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

| Measure | Value |
|---|---|
| Fraud slowed or stopped (recall) | 53.8% of 275 |
| Fraud stopped outright | 53.5% |
| Legitimate payments slowed (false-positive rate) | 1.2% of 1000 |
| Legitimate payments stopped | 1.2% |
| Of everything slowed, share that was fraud (precision at this mix) | 92.5% |

The mix is 275 fraud in 1275 payments, far more fraud than real traffic has, so the precision figure would be much lower in production.
