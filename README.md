# Incident Shield

> AI can explain financial risk. It cannot overrule the evidence, invent policy, or move money without permission.

Incident Shield is a fraud-protection layer for PayPal-style payments, built as something PayPal could ship as a feature. It has two parts:

1. **A payment app (`/app`) that scores every payment before any money moves.** A 47-signal risk engine returns a 0–100 score; the payment is allowed, needs the payee confirmed, is delayed with a scam warning, is held for a reviewer, or is blocked. Each decision is sealed (encrypted, signed, hash-chained). When a customer later says "that wasn't me" or "I was tricked", the complaint is checked against the sealed record from the moment of payment, consistent complaints go to the front of the queue, and a human reviewer returns the money through PayPal's refund API. The time from complaint to refund is measured and shown.
2. **A webhook monitor for a PayPal business account** that detects money-mule pass-through with deterministic rules and groups it into incidents, with an AI Copilot that explains an incident and whose every answer is checked by code.

AI never moves money and never approves or declines anything. It has four jobs, each fenced by code:

| AI job | What it can do | What it can't do |
|---|---|---|
| Read the payment reference at payment time | Add the scam-reference signal when the wording is a scam the keyword list misses | Remove a keyword hit, lower a score, or delay a payment (4 s timeout, then the keyword result stands) |
| Read a complaint into six yes/no notes | Supply one input to the consistency score | Write numbers, names or verdicts (non-boolean output is discarded) |
| Prioritise the reviewer's queue | Move a case **up** by a fixed amount (+15 still at risk, +10 money needed for essentials) | Move a case down, change the evidence score or outcome, or lift a case marked for manual review over the fast-track line |
| Write the reviewer a case brief, and explain incidents | Summarise facts that code built | Use a number that isn't in the facts, or recommend a decision (such a brief is replaced by a template) |

The evidence decides, and a human approves every refund and release.

Built for the PayPal AI Hackathon (Devpost). **This is a sandbox prototype, not a production payment system:** there is no KYC/AML, settlement, chargeback handling or external security review, and it runs as one process on free-tier hosting. **Sandbox only, by design:** the app refuses to start against any non-sandbox PayPal host.

### What is real and what is simulated

| Part | Status |
|---|---|
| Payer's order, approval, capture, and refund | **Real PayPal sandbox API calls** (Orders v2, capture refund) |
| Webhook intake, signature verification, incident rules | **Real** sandbox webhooks |
| 26 of the 47 signals (payment history, devices and networks per account, payee fan-in and pass-through, links to confirmed fraud, typing and focus behaviour, reference text) | **Computed** from this app's own ledger and the browser |
| 7 signals (active phone call, SIM swap, remote-access tool, compromised device, breached credentials, anonymising network, shared-network risk score) | **Simulated**: switched on by the demo user, and recorded as simulated inside the sealed decision |
| 14 signals (card and issuer data, geolocation, identity verification, peer comparison) | **Not available**: always listed as missing data and scored 0 |
| Crediting the payee | **Simulated**: a ledger entry in this app. No payout is sent |
| Holding funds | The payment is stopped **before** PayPal is called. This app cannot freeze money inside PayPal |

Pages: `/app` (the console: ten tabs covering paying, transactions, cases, AI watch, risk engine, evidence, AI Copilot, audit log and settings), `/review` and `/app/classic` (the earlier pages), `/docs` (API).

### Modes

| Setting | What it does |
|---|---|
| `ENFORCEMENT=monitor` | Every payment is scored, sealed and recorded, and **not stopped by the score**. The record is there to make a later complaint quick to assess. `enforce` (the default) lets the score require confirmation, hold or block. |
| `WATCH_OUTFLOW_USD=150` | **AI watch.** A payment scoring `WATCH_SCORE` (30) or more puts the payer on watch for `WATCH_HOURS` (24). Once more than this many dollars has gone out since, further payments are paused, a "crawler" report traces which accounts received the money, what they then paid and what the payments graph says about them, and a reviewer can ask the AI about it. This is the only thing that stops a payment in monitor mode. `0` (the default) turns it off. |
| `PUBLIC_DEMO=true` | Opens every reviewer and owner screen to anyone, with no key, as the user "judge". **For a sandbox demonstration only:** anyone who finds the site can read every case and approve refunds. Refunds still go only to the original payer through the sandbox. Never set it with real data. |

The "AI watch" is a rule (a score threshold and an outflow limit); the AI's part is answering questions about the watched account from the crawler's facts, with the same checks as the case brief. It does not decide to stop anything.

## How it works

1. **Intake:** global rate limit → 64 KB cap → local header checks (no PayPal call for junk) → signature verified with PayPal (at most 4 at once) → stored once (duplicates ignored by a database constraint) → acknowledged. Unverified requests are never stored (the one exception is the optional `DEMO-` seed, see limitations). Verified events naming a different merchant (`PAYPAL_MERCHANT_ID`, required), and captures with no payee at all, are **quarantined**, not processed. Payout events never carry a payee; they're accepted because PayPal delivers webhook events only for the app the webhook is registered to. If verification or the database is unavailable the app answers 503 and PayPal retries.
2. **Normalise:** captures and payout items become transactions (Decimal money, original currency kept, PayPal's USD value used for conversions). Capture webhooks carry no payer data, so the payer is identified from the order: stable account ID for PayPal wallets, name + card brand + last 4 digits (weaker) for card guests. A failed payer lookup is retried on the next two sweeps before the payment is processed with an unknown payer.
3. **Guard rules** (plain code, versioned, evaluated at event time):
   - R1 burst of payments from new senders (**low** severity when the account has fewer than 3 earlier transactions, because then "new" may just mean "first customers")
   - R2 **at least 80%** (and at least $5) of the money that just arrived from new senders moved out to a recipient without established history (informational alone). "Established" means at least 2 earlier payouts to that recipient, together worth at least half of the new payout, so a single $1 warm-up payment isn't enough (see limitations: it's still easy to fake)
   - R3 probe payment under $1 from a new sender (non-USD payments without a USD value are compared in their own currency when one unit is about a dollar or more, otherwise not evaluated)
   - R4 inflows in 3+ original currencies
   These are Incident Shield's own heuristics. PayPal publishes trigger categories, not thresholds. A hit is a risk indicator, not proof of fraud.
   Rules run at event time. When a webhook arrives late, every later evaluation point within the hour is re-run, so a late payment can still complete a pattern.
   **A single rule firing never opens an incident.** Hits are stored and listed at `GET /rule-hits` (a busy hour of new customers looks exactly like a burst, so R1 alone isn't worth an alert). R4 (currency mix) is only ever a listed hit; it isn't a step of the sequence.
4. **Sequence detector:** probe → burst → money out within an hour = `money_mule_pattern` incident: **high** severity when the account has enough history, **medium** when it doesn't (then "new sender" may include regular customers). **Two of the three steps in order** = `partial_pattern`, a **low-severity "needs review"** incident. That's what someone who stays just under one threshold leaves behind (draining 79%, or paying a "warmed-up" recipient). If the missing step arrives later, the same incident is upgraded, so one pattern is always one incident. What opens nothing: new customers alone (one R1 hit), however busy the hour. What **does** open a needs-review incident in ordinary business: a sale of $1 or less followed by new customers (looks like probe → burst), or new customers followed by a payout of 80%+ of what they paid (burst → out). Low severity, by design: someone should glance at it. `GET /summary` shows counts of incidents by kind, events by status, and anything needing attention (patterns to review, quarantined or failed events).
5. **Incidents** with an append-only audit log. Payer-typed text (names) is stored as `untrusted_text` and never interpreted. When a rule re-fires on a growing burst, the larger hit replaces the smaller one, including inside an existing money-mule incident (with an audit entry), so a burst is never counted twice.
6. **Copilot** (`POST /incidents/{id}/ask`): grounded Q&A over one incident. Every answer separates five parts:
   - **observed** (payments, from the record), **calculated** (rule values), **PayPal docs** (excerpts of PayPal help pages, fixed per question in code, each with its URL, a hash and a note on why it's shown), **Incident Shield observations** (kept separate, never presented as PayPal's words), **recommended** (fixed steps, each with its source), **unknown**
   - plus one **AI interpretation**, the only text the model writes. It's rejected if it mentions a number, date, time, ID or currency not in the record, a count that doesn't match the record for that noun ("30 senders"), or a blocked phrase (clearing, dismissing, accusing, or claiming certainty). Negated or hedged forms ("not confirmed fraud", "ordinary sales can also cause this", "your normal business") are allowed; these exemptions came from the first real Gemini run, where correct sentences were being blocked. Status `passed_checks` means *no detectable fabrication*, **not** verified meaning: a reworded claim can pass, which is why it's always labelled as AI interpretation and never drives any decision.
   - Questions map to five fixed intents; anything else is refused. Payer-typed text and the question reach the model only inside delimited blocks, with angle brackets neutralised so they can't close the block. The model has no tools.
   - If the main model (`GEMINI_MODEL`) is overloaded (429/5xx) or slower than 20 s, the request is tried once on `GEMINI_FALLBACK_MODEL`; each answer records which model replied. Without an API key, over the daily budget, or if both models fail, deterministic template answers take over. Only stable answers are cached; failures are retried next time.
   - The policy hashes detect edits since capture. They don't prove the text came from PayPal: each entry links its source.

## Roles, audit and operations

- **Roles:** the owner key can do everything. Named reviewer keys (`REVIEWERS=asha:<sha256>:<last day>,...`, from `scripts/make_reviewer_key.py`) can work the review queue only, and stop working after their last day. Every release, decline and refund is recorded under the reviewer's name (`GET /review/audit`). Those actions, and every case a reviewer opens, go into a hash-chained, signed audit log (`GET /review/audit`, `GET /review/audit/verify`). A named reviewer can't approve a refund over $500 (`REVIEWER_REFUND_LIMIT_USD`), and `OWNER_KEY_EXPIRES` makes the owner key stop working after a set day.
- **Two-person refunds:** a refund of $100 or more (`REFUND_SECOND_APPROVAL_USD`) needs two different reviewers. The shared owner key counts as one person, so large refunds need at least one named reviewer. Over $500 the owner must be one of the two approvers, in either order; with none configured the approval is refused up front and nothing is recorded.
- **Payments graph:** `GET /risk/graph/{handle}` shows who an account paid and was paid by, the devices and networks it shares, and findings (fan-in, fan-out, device ring, link to confirmed fraud). A fresh account run from the same device as a confirmed-fraud account is flagged before anyone has paid it. Fan-out and device-ring size are scored (signals `RC8`, `RC9`), device links expire after 14 days, and the owner can mark a device as legitimately shared (`POST /risk/shared-devices`). A shared network alone never counts as a link. Simulated demo signals can only add risk: a simulated value never replaces something the ledger worked out.
- **Clearing a fraud flag:** `POST /risk/fraud-flag/{handle}/clear` (owner, with a reason, audited) stops earlier confirmed complaints counting against an account. Use it between demo takes.
- **Labels:** `GET /risk/labels` pairs each reviewer outcome with what the engine decided at the time, with amounts. Refund approved = fraud; declined = "not upheld", which means the reviewer wasn't convinced, not that the payment was proven legitimate. It is the only real measurement here.
- **Alerts and targets:** `/metrics` returns an `alerts` list (PayPal failures, review backlog over an hour, over 30% of payments stopped, scoring slower than the 800 ms target) plus scoring time and review load per 1,000 payments. `scripts/check_alerts.py` exits non-zero on any alert so a scheduler can notify someone.
- **Retention:** `scripts/retention.py` clears complaint text, device ids, network hashes and browser measurements from payments older than 180 days (dry run unless `--confirm`), keeping the financial record and the sealed chains.
- **Operations:** `GET /metrics` (counts, refund time, oldest open complaint, PayPal failures), `GET /review/reconcile` (the ledger against PayPal), one JSON log line per payment event, and `RUNBOOK.md` for deploy, rollback, key rotation and incidents.
- **Threat model:** `THREAT_MODEL.md` lists each attacker, the control in the code, and what is left open.

## Measured on simulated payments (`BENCHMARK.md`)

`python scripts/benchmark.py` scores labelled, simulated payments with the same `decide()` the app uses. **The data is simulated and was written by the authors of the rules, so this is not real-world accuracy.**

| Set | Fraud slowed or stopped | Fraud money that went straight through | Legitimate payments slowed |
|---|---|---|---|
| **Held-out v2** (written after the last rule change, never tuned against) | **0.0% of 160** | **all of it ($190,738)** | 1.2% of 160 |
| Tuning set (rules were adjusted with it in view) | 35.4% of 435 | 64.2% | 1.8% of 1,160 |

**The engine catches none of the fraud it wasn't written around.** The held-out cases are a SIM-swap takeover, a romance scam to a payee already paid twice, a layering mule and a fresh ring account. The two graph signals fire on the last two, but one signal alone doesn't reach the step-up line. An earlier held-out set scored 9.4%; it was retired into the tuning set when the rules changed, as its own rule requires. On the tuning set the engine misses seven fraud types completely and stops 47.5% of honest people who set up a new phone, reset their password and pay someone new. Fixed thresholds chosen by judgement do this.

A logistic-regression **shadow model** over "which signals fired" is scored beside the rules (43.2% on tuning, 1.9% on held-out, and it wrongly flags 25% of held-out legitimate payments). Trained on simulated data it can only see what the rules extract, so it is no better. It runs in the app in shadow mode (`scripts/train_model.py`, `GET /risk/shadow`): its output is sealed with each decision and never acted on. Closing the gap needs real labelled outcomes, which `GET /risk/labels` collects from reviewer decisions.

**Real Gemini:** `python scripts/ai_eval.py` runs the reference reader, complaint reader and case brief against the real model on small labelled sets and prints the scores. Results: _not yet run; paste the three summary lines here._

## Risk decision engine and payment app (`app/risk/`, `app/payapp.py`)

- **`engine.py`**: scores one payment 0–100 from 47 named signals in 9 categories, with fixed points per tier, a cap per category, six combination floors (account takeover 85, mule account 80, card testing 80, device farm 75, authorised scam 70, confirmed-fraud recipient 60) and trust reductions that never go below a floor. Missing evidence scores 0 and is listed under `missing_data`; wrong-type evidence scores 0 and is listed under `invalid_data`.
- **`evidence.py`**: builds the engine's inputs from the ledger (read-only queries) and the browser's aggregate measurements. A device or network only becomes "known" through a **completed** payment, so a blocked attacker can't make a device familiar by retrying.
- **`snapshot.py` / `service.py`**: every decision is sealed with what the engine knew at that moment: AES-256-GCM, HMAC-SHA256 signature, SHA-256 chain. The sealed record holds the score, signals and evidence, and is the copy complaints are judged against. For operations, the score and action are also kept readable in the payment's event row and the log line, which are not sealed. Editing, reordering, or removing a first or middle record is detected by `POST /risk/verify`. **Limit:** records cut off the *end* can't be seen from the chain alone; save `GET /risk/checkpoint` outside the database and pass it to verify. Keys come from environment variables and each record names its key id, so keys can be rotated.
- **`payapp.py`**: sign-up (token shown once, only its hash stored), score → gate → PayPal order → capture. Before capture the app re-reads the order from PayPal and refuses if the amount or payment id doesn't match or it isn't approved. PayPal calls carry an idempotency key, so a retry can't pay or refund twice.
- **`complaint.py` / `claims.py`**: a complaint's consistency (0–100) is computed from the sealed snapshot, not current data. Gemini reads the free text into four booleans, in a delimited block, with the output type-checked; only one of them can affect the score, and the complaint works with the AI off. A low score sends the case to a human; nothing is auto-rejected.
- **`learning.py`**: when a refund is approved the payee counts as confirmed fraud: later payers to that account score higher, earlier payers can be rescored (`POST /risk/rescore/{handle}`), `GET /risk/gap/{payment}` shows what fired, what was missing and what nearly fired, and `GET /risk/scam-library` groups confirmed cases by type.
- Rule IDs in the engine (`RC1_…`) are separate from the incident rules (`R1_BURST`, …); the two systems are not merged.

## Measured in the PayPal sandbox (see SPIKE.md)

- Webhooks: 12 of 12 signature-verified, median delivery 7.9 s. Only payments processed through this app produce webhooks.
- Transaction Search (account-wide): about 2 hours behind, published in batches.
- A newly registered webhook missed a payment made within its first minutes: wait ~5 minutes after registering.
- Reporting a payment as "unauthorized" as a buyer sends the buyer into PayPal's account-security flow, not a dispute.

## Run locally (Windows PowerShell)

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -r requirements-dev.txt
python scripts\make_owner_key.py        # put the printed hash in .env
alembic upgrade head                    # creates tables in DATABASE_URL
uvicorn app.main:app --port 8000
```

`.env` needs `MERCHANT_CLIENT_ID`, `MERCHANT_CLIENT_SECRET`, `PAYPAL_WEBHOOK_ID`, `PAYPAL_MERCHANT_ID`, `DATABASE_URL`, `OWNER_API_KEY_SHA256` (see `.env.example`). The app won't start if any is missing. `GEMINI_API_KEY` is optional; without it the Copilot uses template answers.

Check the AI part against real Gemini (no database needed, 9 calls): `python scripts\copilot_smoke.py`. It prints each answer and whether it passed the checks; passing the checks is not proof the meaning is right, so read the text. Before a demo, run `python scripts\warm_copilot.py <base-url> <incident-id>` (asks for the owner key): it asks the five standard questions slowly so the answers are cached, because the Gemini free tier allows only a few requests per minute.

API: `GET /health/live`, `GET /health/ready`, `POST /webhooks/paypal`, `GET /copilot/questions`, and with header `X-API-Key` (use **Authorize** in `/docs`): `GET /summary`, `GET /transactions`, `GET /rule-hits`, `GET /incidents`, `GET /incidents/{id}`, `POST /incidents/{id}/ask`. Interactive docs at `/docs`.

**Payment app setup:** run `python scripts/make_risk_keys.py`, paste its three lines into `.env`, set `PUBLIC_BASE_URL=http://localhost:8000`, then `alembic upgrade head`. Open `http://localhost:8000/app`, create two accounts (use a second browser profile for the payee), and pay with a sandbox **personal** (buyer) account when PayPal opens.

## Deploy (Render, free plan)

`render.yaml` is a Blueprint: Render dashboard → **New → Blueprint** → this repo, then fill in the secret values it asks for.
- Start command runs `alembic upgrade head` first (the free plan has no pre-deploy step; it's a no-op at head), then **one** uvicorn worker.
- Health check is `/health/live`, which doesn't touch the database, so a cold Neon connect can't fail a deploy. `/health/ready` checks the database with a 5 s connect timeout.
- After the first deploy, register a webhook for `https://<service>.onrender.com/webhooks/paypal` (`python spike/run_spike.py webhook-register --url ...`), put its ID in `PAYPAL_WEBHOOK_ID` on Render, and **wait about 5 minutes** before sending payments (new webhooks miss early events; see SPIKE.md).
- Payment app: generate keys with `python scripts/make_risk_keys.py` and set `RISK_ENC_KEY_K1`, `RISK_SIGN_KEY_K1` and `PUBLIC_BASE_URL` (`https://<service>.onrender.com`, no trailing slash) on Render. Without the keys `/app` payments answer 503.
- Free instances sleep after 15 idle minutes and take a while to wake. Open `/health/ready` before a demo. PayPal retries events the sleeping instance missed.
- Rollback: redeploy the previous commit in the Render dashboard. Migrations only add things (0001–0006), so older code runs on the newer schema; there are no down-migrations to run.

## Tests

```powershell
pytest -q
```

Database tests need PostgreSQL in `TEST_DATABASE_URL`, a **separate** database whose name contains `test` (the tests wipe it, and refuse any other name). Without it they're skipped locally; CI runs them against PostgreSQL 18 on every push. Quickest local setup (Docker):

```powershell
docker run -d --name shield-pg -p 5432:5432 -e POSTGRES_PASSWORD=postgres -e POSTGRES_DB=shield_test postgres:18
$env:TEST_DATABASE_URL="postgresql://postgres:postgres@localhost:5432/shield_test"
pytest -q
```

## Known limitations

**Payment app**
- Browser measurements (device id, fingerprint, typing speed) are sent by the client and can be forged. A real deployment needs device attestation. The client IP is read from `CF-Connecting-IP` (Render serves through Cloudflare, which sets it), falling back to the first `X-Forwarded-For` entry, which a client can forge. Neither has been verified on the live deployment.
- Because that evidence can be staged, a fraudster can arrange a takeover-looking record and then claim "unauthorised" to get a high consistency score. The score only orders the reviewer's queue; a human approves every refund, and the console says the evidence is browser-reported.
- Queue priority uses the customer's own words, so someone can write an urgent-sounding complaint to be seen sooner. The bonus is fixed and small, it is shown to the reviewer with its reason, and it can't override the evidence cap. It changes when a case is looked at, not what is decided.
- The console needs JavaScript, has no charts library, and has not had an accessibility audit; it was checked by a scripted run through every tab, not by people using it.
- **Open findings from the last code review, not fixed:** a cleared payment has no expiry and isn't re-scored at capture, so several approved-but-unpaid payments are each scored against the same baseline; logout ends the account for good because there are no passwords; with no `CF-Connecting-IP` header the client address falls back to a forgeable `X-Forwarded-For` entry; the `CARD_TESTING` floor and 14 signals can never fire because the app has no card, issuer or geolocation data; there is no throttling of owner or reviewer key guesses, and `/docs` is public; the audit count in a checkpoint is not signed and one key signs decisions, audit rows and checkpoints; `POST /app/payments` has no idempotency key, so a double-click makes two scored payments; display names aren't unique, so a lookalike name defeats the name-mismatch signal; the graph cache is discarded on every new payment attempt, so each scoring reloads the 30-day ledger.
- **Not built:** passkeys or device attestation (browser evidence stays forgeable), a KMS or separate signing service (the sealing keys are on the app host), per-person reviewer logins with MFA, shared rate limits and more than one worker, statement-level reconciliation and chargebacks. Each needs an external service or a deployed site to verify against.
- The payments graph is rebuilt in full whenever the ledger changes, which is every attempt. Fine for a demo, too slow at volume; it needs an incremental graph store and a load test. The 800 ms scoring target has never been measured under load.
- Sharing a device with a confirmed-fraud account raises the score of the other accounts on it, which will include innocent family members.
- Withheld evidence lowers a score (missing data scores 0). That is a deliberate choice against guessing, and it is exploitable.
- A refund only goes back to the original payer, and only while the captured funds are still in the sandbox merchant account. In real fraud the money has often left; this app can't recover it, and it can't freeze funds inside PayPal.
- Demo mode (`SIMULATION_ENABLED=true`) shows the score and reasons to the payer. A real service wouldn't show that to an attacker.
- Demo mode also lets any account load a ready-made history (`/app/demo/history`), which earns trust it didn't build. Turn `SIMULATION_ENABLED` off for anything but a demo.
- The demo accounts have no password: the token in the browser is the login and never expires unless the payer logs out. Sign-up is open, rate-limited per address, and reveals which handles exist. The reviewer console uses the single owner key.
- Run once against the live PayPal sandbox, on the Render deployment, on 2026-11-12: one $20 payment through order creation, payer approval, capture, a complaint and a reviewer-approved refund. That is a single manual run, not a test suite: the automated tests use a fake PayPal client. Failure paths (declined capture, failed refund, PayPal outage) have only run against the fake.

- **No dispute or evidence flow.** It was planned, but buyer disputes couldn't be created in the sandbox (reporting "unauthorized" sent the buyer into account recovery instead), so it was cut rather than faked.
- **Read-only apart from Copilot questions.** Incident status stays `detected`; there's no endpoint to acknowledge, dismiss or resolve an incident yet.
- **"Known sender" needs more than an hour of history**: senders count as known only if seen before the one-hour lookback. The sandbox can't backdate payments, so a live demo of "repeat buyer → no alert" needs a history run over an hour earlier (or replay).
- **Demo data**: the sandbox can run the full probe → burst → out sequence live (real captures and a real payout), but it can't backdate the history that makes it high severity, and nothing opens an incident until someone runs the attack. `python scripts/demo_seed.py --confirm` (after `alembic upgrade head`, on a **demo database only**) inserts one complete pattern as events labelled `DEMO-`. These are **not from PayPal and were never signature-verified**: they're the one exception to "unverified requests are never stored", and their fake history affects detection of real events in the same database. The seed goes straight into the database, so it shows detection and the Copilot but **not** the webhook path. `--remove` deletes the demo events and every hit and incident built from them.
- **A mule and a small shop can look the same.** Probe → new senders → most of the money out to a new payee is what both look like when a shop pays a brand-new supplier nearly everything it just took in. The 80% bar and the established-recipient check exist to keep honest shops out of the full pattern; they are **not** protection against an attacker (see next point). That's why the result is called a pattern, not fraud.
- **The rules are easy to evade for anyone who reads them**, and they're public in this repo. Two examples: drain 79% instead of 80%, or pay your own cash-out account twice more than an hour earlier so it counts as "established" (that costs nothing, because the money goes to yourself). Fixed thresholds catch careless patterns, not an adversary who knows them. Closing this needs per-account baselines and signals PayPal has but doesn't expose (device, login, linked accounts).
- **Shops with cheap items will see needs-review incidents.** Any new-customer sale of $1 or less looks exactly like a probe payment, so "cheap sale, then a few new customers" opens one. Raising the bar doesn't help: an attacker would just probe with $1.01. Pocket-change payouts (under $5) are ignored by R2, which also means an account draining less than $5 in total isn't covered at all.
- **Partial patterns catch the obvious evasions, not all of them.** Draining 79% or warming up the recipient still leaves probe → burst, so a needs-review incident opens. An attacker who also skips the probe (no sub-$1 test payment) and stays under the R2 bar leaves only a single R1 hit, which never opens an incident.
- **One pattern per window.** The detector matches the earliest complete (or partial) pattern among the hits from the last ~3 hours. A second, separate pattern in the same period doesn't get its own incident until the first one's hits age out; its hits are still listed at `/rule-hits`.
- **R1 can't tell a good sales day from a burst** without per-account baselines, which is why it never opens an incident by itself.
- The webhook rate limit is global, not per sender: one noisy source can delay legitimate deliveries (PayPal retries them).

- Single merchant per deployment; multi-merchant onboarding needs PayPal partner approval.
- Webhooks only cover payments made through this app; account-wide coverage comes from Transaction Search with ~2 h delay.
- Card guests have no stable PayPal identity, so "new sender" for cards relies on name + card digits.
- No adaptive baselines, FX valuation, or production hardening.

## License

MIT, see [LICENSE](LICENSE).
