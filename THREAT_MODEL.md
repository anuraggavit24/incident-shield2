# Threat model

Scope: the payment app (`/app`, `/review`, `/risk`, `/metrics`) and the webhook monitor, as deployed on one
Render instance with one Neon database, against the PayPal **sandbox**. This is a sandbox prototype. Nothing
here has had an external security review.

## What is worth protecting

| Asset | Why it matters |
|---|---|
| The ability to move money (PayPal capture and refund calls) | A wrong refund or capture is the worst outcome |
| Sealed decision records | They are the evidence complaints are judged against |
| The reviewer queue and its order | Decides whose case a human sees first |
| PayPal credentials, owner and reviewer keys, sealing keys, database URL | Each gives control of one of the above |
| Payer tokens, device ids, IP hashes, complaint text | Personal data of the people using the app |

## Who might attack, and what stops them

| Attacker | Attack | Control in the code | What is left open |
|---|---|---|---|
| **Fraudster as payer** | Take over an account and pay out | Takeover floor blocks before PayPal is called; a blocked attempt doesn't make the device "known" | Evasion: wait 72 hours, stay under 3x the usual amount, or act from the victim's own device. Measured in `BENCHMARK.md`: 0% of patient takeovers are slowed |
| | Forge browser signals (device id, typing, fingerprint) | None that holds | All browser evidence is client-asserted. Needs device attestation |
| | Forge the client address | `CF-Connecting-IP` preferred over `X-Forwarded-For` | Unverified on Render; if the edge passes a client's header through, per-address limits fail |
| | Withhold evidence to lower the score | Missing data is listed in every decision | Missing evidence scores 0 by design |
| **Fraudster as complainant** | Stage a takeover-looking record, then claim "unauthorised" | Score only orders the queue; a named human approves; console labels evidence as browser-reported | A convincing staged record still reaches the front of the queue |
| | Write urgent text to jump the queue | Fixed bonus (+15, +10), shown with its reason, capped below fast-track for manual-review cases | Ordering within a tier is influenced by the customer's own words |
| | Prompt-inject the AI through complaint or reference text | Text is delimited, angle brackets removed; output must be booleans; briefs are checked for numbers and verdict wording | A reworded false statement can pass the brief check. The AI cannot approve, decline or move money in any case |
| **Scammer's victim** (coached) | Pays willingly | Scam floor holds the payment; softer signs delay it with a warning | A bland reference and no call signal: 0% slowed in the benchmark |
| **Outsider** | Flood sign-up or payments | Per-address and global sign-up limits, per-payer hourly cap under a lock, user cap | A distributed flood fills the demo; limits are in memory and reset on restart |
| | XSS in the pages | No `innerHTML`; strict CSP with no inline script or style; `nosniff` | Not pen-tested |
| | Forge a PayPal webhook | Signature verified with PayPal; unknown merchant quarantined; rate-limited | Depends on PayPal's verify endpoint being up |
| **Stolen payer token** | Use the account | Only the hash is stored; logout invalidates it | Token is in `localStorage`, never expires on its own, and there is no password or second factor |
| **Stolen reviewer key** | Approve refunds | Refunds only go to the original payer through PayPal; the amount must be typed; every action is in the audit trail under that reviewer's name; remove the entry from `REVIEWERS` to revoke | No second approver, no expiry, no IP restriction |
| **Database read access** | Read decisions | Score, signals and evidence are AES-256-GCM encrypted | Payments, handles, IP hashes, device ids and complaint text are plaintext |
| **Database write access** | Edit or delete decisions | Hash chain and HMAC detect edits, reorders and removals in the middle; a saved checkpoint detects a cut-off tail | Can roll the chain back to an older checkpoint if the checkpoint is also stored in the database. Can edit payments, complaints and the audit trail, which are not sealed |
| **Control of the host** | Everything | None | The sealing keys, PayPal credentials and owner hash are environment variables on the same host. Tamper-evidence does not hold against whoever controls the server. Needs an HSM or KMS and a separate signing service |
| **Malicious or mistaken insider (owner key)** | Approve a wrong refund, read every case | Audit trail records the action | The owner key is shared, so "owner" is not one identifiable person. The owner can read all complaint text |

## Not in scope, and not built

KYC and AML checks, PCI DSS scope, settlement and chargebacks, dispute-scheme rules, data retention and
deletion, multi-region availability, and penetration testing. A real payment product needs all of them.

## Assumptions that must hold

1. TLS is terminated by Render and the app is only reachable through it.
2. The PayPal host is the sandbox (the app refuses to start otherwise).
3. One process and one worker (rate limits and a lock are in memory).
4. Environment variables on Render are readable only by the account owner.
