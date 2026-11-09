# Incident Shield

> AI can explain financial risk. It cannot overrule the evidence, invent policy, or move money without permission.

Incident Shield watches a PayPal business account through PayPal's own APIs (sandbox), detects fraud patterns such as money-mule pass-through with deterministic rules, and groups them into incidents with a full audit trail. AI (in progress) only explains the evidence; irreversible actions always need the owner's explicit approval.

Built for the PayPal AI Hackathon (Devpost). **Sandbox only, by design:** the app refuses to start against any non-sandbox PayPal host.

## How it works

1. **Intake:** PayPal webhook → signature verified with PayPal → stored once (duplicates ignored by a database constraint) → acknowledged. Unverified requests are never stored. If verification or the database is unavailable the app answers 503 and PayPal retries.
2. **Normalise:** captures and payout items become transactions (Decimal money, original currency kept, PayPal's USD value used for conversions). Capture webhooks carry no payer data, so the payer is identified from the order: stable account ID for PayPal wallets, name + card brand + last 4 digits (weaker) for card guests.
3. **Guard rules** (plain code, versioned, evaluated at event time):
   - R1 burst of payments from new senders
   - R2 money moved out soon after new-sender inflows (informational alone)
   - R3 probe payment under $1 from a new sender
   - R4 inflows in 3+ original currencies
   These are Incident Shield's own heuristics. PayPal publishes trigger categories, not thresholds. A hit is a risk indicator, not proof of fraud.
4. **Sequence detector:** probe → burst → money out within an hour = `money_mule_pattern` incident, high severity.
5. **Incidents** with an append-only audit log. Payer-typed text (names) is stored as `untrusted_text` and never interpreted.

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

`.env` needs `MERCHANT_CLIENT_ID`, `MERCHANT_CLIENT_SECRET`, `PAYPAL_WEBHOOK_ID`, `DATABASE_URL`, `OWNER_API_KEY_SHA256` (see `.env.example`).

API: `GET /health/live`, `GET /health/ready`, `POST /webhooks/paypal`, and with header `X-API-Key`: `GET /transactions`, `GET /incidents`, `GET /incidents/{id}`. Interactive docs at `/docs`.

## Tests

```powershell
pytest -q
```

Database tests need PostgreSQL in `TEST_DATABASE_URL`, a **separate** database whose name contains `test` (the tests wipe it, and refuse any other name). Without it they're skipped locally; CI runs them against PostgreSQL 16.

## Known limitations

- Single merchant per deployment; multi-merchant onboarding needs PayPal partner approval.
- Webhooks only cover payments made through this app; account-wide coverage comes from Transaction Search with ~2 h delay.
- Card guests have no stable PayPal identity, so "new sender" for cards relies on name + card digits.
- No adaptive baselines, FX valuation, or production hardening.

## License

MIT, see [LICENSE](LICENSE).
