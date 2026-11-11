"""Ask all five standard questions about one incident in advance, slowly, so the answers are cached.

Why: the Gemini free tier allows only a few requests per minute. Answers that pass the checks are
cached, so after warming, anyone opening this incident (judges included) gets them instantly and
without using quota. Free-text questions are not pre-warmed; they still call the model.

Usage:   python scripts/warm_copilot.py http://localhost:8000 1
         python scripts/warm_copilot.py https://your-app.onrender.com 1
The owner API key is asked for at the prompt (not read from .env, which only holds its hash).
"""

from __future__ import annotations

import getpass
import sys
import time

import httpx

INTENTS = ["why_flagged", "what_first", "evidence", "rule_meaning", "is_confirmed"]
PAUSE_S = 15


def main() -> int:
    if len(sys.argv) != 3:
        print(__doc__)
        return 2
    base, incident = sys.argv[1].rstrip("/"), sys.argv[2]
    key = getpass.getpass("Owner API key (input hidden): ").strip()
    failures = 0
    with httpx.Client(timeout=60) as http:
        for n, intent in enumerate(INTENTS):
            if n:
                time.sleep(PAUSE_S)
            r = http.post(f"{base}/incidents/{incident}/ask", json={"intent": intent}, headers={"X-API-Key": key})
            if r.status_code != 200:
                print(f"[FAIL] {intent}: HTTP {r.status_code}")
                failures += 1
                continue
            body = r.json()
            ai = body.get("ai_interpretation", {})
            status = "cached" if body.get("cached") else ai.get("status", "?")
            ok = body.get("cached") or ai.get("status") == "passed_checks"
            failures += 0 if ok else 1
            detail = ai.get("model", "") if ok else ai.get("reason") or "; ".join(ai.get("problems", []))
            print(f"[{'OK  ' if ok else 'FAIL'}] {intent}: {status} {detail}")
    if failures:
        print(f"{failures} not cached. Wait a minute (or until tomorrow if the daily quota is gone) and rerun:")
        print("already-cached answers are skipped instantly, only the missing ones call the model.")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
