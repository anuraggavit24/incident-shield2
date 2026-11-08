# Incident Shield

> AI can explain financial risk. It cannot overrule the evidence, invent policy, or move money without permission.

Incident Shield watches a PayPal business account through PayPal's own APIs (sandbox), detects fraud patterns such as money-mule pass-through with deterministic rules, and uses AI only to explain the evidence and point to the official PayPal action. Irreversible actions always require the owner's explicit approval.

**Status:** day 1. This repo currently contains the sandbox spike that measures real PayPal sandbox behavior before the product is built. See [SPIKE.md](SPIKE.md).

Built for the PayPal AI Hackathon (Devpost). Sandbox only, by design: the app refuses to start against any non-sandbox PayPal host.

## License

MIT, see [LICENSE](LICENSE).
