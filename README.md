# Incident Shield

> AI can explain financial risk. It cannot overrule the evidence, invent policy, or move money without permission.

Incident Shield watches a PayPal business account through PayPal's own APIs (sandbox), detects fraud patterns such as money-mule pass-through with deterministic rules, and groups them into incidents with a full audit trail. An AI Copilot answers questions about an incident, but it only narrates: it can't create, change or close incidents, and Incident Shield never moves money or acts on PayPal at all. Recommended steps are things **you** do on paypal.com.

Built for the PayPal AI Hackathon (Devpost). **Sandbox only, by design:** the app refuses to start against any non-sandbox PayPal host.

## How it works

1. **Intake:** global rate limit → 64 KB cap → local header checks (no PayPal call for junk) → signature verified with PayPal (at most 4 at once) → stored once (duplicates ignored by a database constraint) → acknowledged. Unverified requests are never stored. Verified events naming a different merchant (`PAYPAL_MERCHANT_ID`, required), and captures with no payee at all, are **quarantined**, not processed. Payout events never carry a payee; they're accepted because PayPal delivers webhook events only for the app the webhook is registered to. If verification or the database is unavailable the app answers 503 and PayPal retries.
2. **Normalise:** captures and payout items become transactions (Decimal money, original currency kept, PayPal's USD value used for conversions). Capture webhooks carry no payer data, so the payer is identified from the order: stable account ID for PayPal wallets, name + card brand + last 4 digits (weaker) for card guests. A failed payer lookup is retried on the next two sweeps before the payment is processed with an unknown payer.
3. **Guard rules** (plain code, versioned, evaluated at event time):
   - R1 burst of payments from new senders (**low** severity when the account has fewer than 3 earlier transactions, because then "new" may just mean "first customers")
   - R2 **at least 80%** of the money that just arrived from new senders moved out to a recipient without established history (informational alone). "Established" means at least 2 earlier payouts to that recipient, together worth at least half of the new payout, so a single $1 warm-up payment isn't enough (see limitations: it's still easy to fake)
   - R3 probe payment under $1 from a new sender (non-USD payments without a USD value are compared in their own currency when one unit is about a dollar or more, otherwise not evaluated)
   - R4 inflows in 3+ original currencies
   These are Incident Shield's own heuristics. PayPal publishes trigger categories, not thresholds. A hit is a risk indicator, not proof of fraud.
   Rules run at event time. When a webhook arrives late, every later evaluation point within the hour is re-run, so a late payment can still complete a pattern.
   **A single rule firing never opens an incident.** Hits are stored and listed at `GET /rule-hits` (a busy hour of new customers looks exactly like a burst, so R1 alone isn't worth an alert). Only the full sequence below opens one.
4. **Sequence detector:** probe → burst → money out within an hour = `money_mule_pattern` incident: **high** severity when the account has enough history, **medium** when it doesn't (then "new sender" may include regular customers).
5. **Incidents** with an append-only audit log. Payer-typed text (names) is stored as `untrusted_text` and never interpreted. When a rule re-fires on a growing burst, the larger hit replaces the smaller one, including inside an existing money-mule incident (with an audit entry), so a burst is never counted twice.
6. **Copilot** (`POST /incidents/{id}/ask`): grounded Q&A over one incident. Every answer separates five parts:
   - **observed** (payments, from the record), **calculated** (rule values), **PayPal docs** (excerpts of PayPal help pages, fixed per question in code, each with its URL, a hash and a note on why it's shown), **Incident Shield observations** (kept separate, never presented as PayPal's words), **recommended** (fixed steps, each with its source), **unknown**
   - plus one **AI interpretation**, the only text the model writes. It's rejected if it mentions a number, date, time, ID or currency not in the record, a count that doesn't match the record for that noun ("30 senders"), or a blocked phrase (clearing, dismissing, accusing, or claiming certainty). Status `passed_checks` means *no detectable fabrication*, **not** verified meaning: a reworded claim can pass, which is why it's always labelled as AI interpretation and never drives any decision.
   - Questions map to five fixed intents; anything else is refused. Payer-typed text and the question reach the model only inside delimited blocks, with angle brackets neutralised so they can't close the block. The model has no tools.
   - Without an API key, over the daily budget, or on any AI failure, deterministic template answers take over. Only stable answers are cached; failures are retried next time.
   - The policy hashes detect edits since capture. They don't prove the text came from PayPal: each entry links its source.

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

Check the AI part against real Gemini (no database needed, 6 calls): `python scripts\copilot_smoke.py`. It prints each answer and whether it passed the checks; passing the checks is not proof the meaning is right, so read the text.

API: `GET /health/live`, `GET /health/ready`, `POST /webhooks/paypal`, `GET /copilot/questions`, and with header `X-API-Key` (use **Authorize** in `/docs`): `GET /transactions`, `GET /rule-hits`, `GET /incidents`, `GET /incidents/{id}`, `POST /incidents/{id}/ask`. Interactive docs at `/docs`.

## Tests

```powershell
pytest -q
```

Database tests need PostgreSQL in `TEST_DATABASE_URL`, a **separate** database whose name contains `test` (the tests wipe it, and refuse any other name). Without it they're skipped locally; CI runs them against PostgreSQL 16.

## Known limitations

- **No dispute or evidence flow.** It was planned, but buyer disputes couldn't be created in the sandbox (reporting "unauthorized" sent the buyer into account recovery instead), so it was cut rather than faked.
- **Read-only apart from Copilot questions.** Incident status stays `detected`; there's no endpoint to acknowledge, dismiss or resolve an incident yet.
- **"Known sender" needs more than an hour of history**: senders count as known only if seen before the one-hour lookback. The sandbox can't backdate payments, so a live demo of "repeat buyer → no alert" needs a history run over an hour earlier (or replay).
- **Demo data**: the sandbox cannot produce the full probe → burst → out sequence, so incidents never appear on their own. Run `python scripts/demo_seed.py` (after `alembic upgrade head`) on a demo database to create one complete, clearly labelled `DEMO-` pattern, then open `/incidents`.
- **A mule and a small shop can look the same.** Probe → new senders → most of the money out to a new payee is what both look like when a shop pays a brand-new supplier nearly everything it just took in. The 80% bar and the established-recipient check reduce this; they don't remove it. That's why the result is called a pattern, not fraud.
- **The rules are easy to evade for anyone who reads them**, and they're public in this repo. Two examples: drain 79% instead of 80%, or pay your own cash-out account twice more than an hour earlier so it counts as "established" (that costs nothing, because the money goes to yourself). Fixed thresholds catch careless patterns, not an adversary who knows them. Closing this needs per-account baselines and signals PayPal has but doesn't expose (device, login, linked accounts).
- **R1 can't tell a good sales day from a burst** without per-account baselines, which is why it never opens an incident by itself.
- The webhook rate limit is global, not per sender: one noisy source can delay legitimate deliveries (PayPal retries them).

- Single merchant per deployment; multi-merchant onboarding needs PayPal partner approval.
- Webhooks only cover payments made through this app; account-wide coverage comes from Transaction Search with ~2 h delay.
- Card guests have no stable PayPal identity, so "new sender" for cards relies on name + card digits.
- No adaptive baselines, FX valuation, or production hardening.

## License

MIT, see [LICENSE](LICENSE).
