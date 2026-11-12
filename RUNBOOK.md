# Runbook

For one Render free instance and one Neon database. Sandbox prototype: there is no on-call, paging or SLA.

## Health and what to watch

| Check | How | Act when |
|---|---|---|
| Process up | `GET /health/live` | Not 200: see "Service down" |
| Database reachable | `GET /health/ready` | Not 200 for more than a minute: see "Database" |
| Money path | `GET /metrics` → `paypal_failures_24h` | Above 0: see "PayPal failing" |
| Review backlog | `GET /metrics` → `oldest_open_complaint_seconds` | Above your target (for example 3600) |
| Ledger agrees with PayPal | `GET /review/reconcile` | `ok` is false: see "Ledger mismatch" |
| Sealed records intact | `POST /risk/verify` with the saved checkpoint | `ok` is false: see "Chain fails" |
| Logs | Render → Logs. Every payment event is one JSON line: `{"event": ..., "payment_id": ..., "actor": ...}` | Search by `payment_id` |

`/metrics`, `/review/reconcile`, `/review/audit` and `/risk/*` need the owner key in `X-API-Key`.
There is no alerting: someone has to look. An uptime monitor on `/health/ready` is the minimum to add.

## Routine

- **Before a demo:** open `/health/ready` (free instances sleep after 15 minutes), then `/metrics`.
- **Daily, if anyone is using it:** `GET /risk/checkpoint` and save the JSON outside the database (a password
  manager note is enough). Without it, records removed from the end of the chain can't be detected.
- **Add a reviewer:** `python scripts/make_reviewer_key.py <name> [days]`, add the printed `name:hash:last-day`
  to `REVIEWERS` on Render, redeploy. Keys stop working after their last day (default 30 days): reissue before then.
  Refunds of $100 or more need two different reviewers, so keep at least two valid keys. **Remove one:** delete their entry, redeploy. Their past actions stay in `/review/audit`.

## Deploy and rollback

- **Deploy:** push to `main`. Render builds, runs `alembic upgrade head`, then starts one worker. Check CI is
  green first.
- **Rollback:** Render → Deploys → redeploy the previous commit. Migrations 0001–0005 only add things, so the
  older code runs on the newer schema. Exception: code older than migration 0005 can create duplicate
  complaints again; the constraint will reject them with a 500 instead of a 409.
- **A migration fails at start:** the instance never becomes healthy and Render keeps the previous deploy
  serving. Read the log, fix forward, push again. Don't edit the database by hand.

## Incidents

**Service down.** Render → Logs for the start-up error. The usual causes: a missing environment variable
(the app names it and exits), a non-sandbox `PAYPAL_API_BASE` (refused by design), or the database.

**Database.** Neon console → check the project is active (free projects suspend when idle and wake on the
next connection). Restore: Neon → Branches → restore to a point in time. **This has never been drilled.**
After any restore, run `/risk/verify` with the newest saved checkpoint: a restore to before that checkpoint
will, correctly, fail verification.

**PayPal failing.** Payments stay cleared-to-pay and captures release their claim, so nothing is marked paid.
Payers retry with "Continue to PayPal" or "Finish payment"; every call carries an idempotency key, so a retry
can't pay twice. A failed refund leaves the complaint as `refund_approved`; approve again to retry.

**Ledger mismatch (`/review/reconcile`).** Do not edit the row. Note the payment id, read the order in the
PayPal sandbox dashboard, and treat PayPal as the truth about money. If PayPal shows a capture the app
doesn't, call `POST /app/payments/{id}/capture` as the payer: the app records an already-completed order
without capturing again.

**Chain fails verification.** Treat the database as tampered with or wrongly restored. Stop approving refunds
(complaints are judged against these records). Find `first_bad_index`, compare with the last backup, and
keep the failing database for examination instead of repairing it in place.

**A key leaks.**

| Key | Do |
|---|---|
| PayPal client secret | Regenerate in the PayPal developer dashboard, update Render, redeploy |
| Owner key | `python scripts/make_owner_key.py`, put the new hash in `OWNER_API_KEY_SHA256`, redeploy |
| Reviewer key | Remove their `REVIEWERS` entry, redeploy, issue a new one |
| Gemini key | Delete it in Google Cloud, create a new one, update Render |
| Database URL | Reset the role password in Neon, update both `DATABASE_URL` values |
| Sealing keys | Add a new pair as `RISK_ENC_KEY_K2` / `RISK_SIGN_KEY_K2`, set `RISK_ACTIVE_KEY_ID=k2`, **keep K1** so old records still open. Records sealed under a leaked key can no longer be trusted as tamper-evident |

Never commit `.env`. If a secret reaches git, rotate it first; rewriting history does not un-leak it.

## Known operational gaps

No alerting, tracing or dashboards; no backup drill; migrations run at start-up; rate limits are in memory
and reset on restart; one instance, one worker, no queue; free-tier database and compute.
