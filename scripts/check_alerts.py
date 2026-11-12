"""Exit non-zero when /metrics reports an alert, so a scheduler or uptime tool can page someone.

Usage: python scripts/check_alerts.py https://your-service.onrender.com
The owner key is read from the OWNER_API_KEY environment variable (never pass it on the command line).
Run it every few minutes from any scheduler (GitHub Actions cron, Windows Task Scheduler, a cron job).
"""

import os
import sys

import httpx

if __name__ == "__main__":
    base = (sys.argv[1] if len(sys.argv) > 1 else "").rstrip("/")
    key = os.getenv("OWNER_API_KEY", "")
    if not base.startswith("http") or not key:
        sys.exit("usage: OWNER_API_KEY=... python scripts/check_alerts.py <base-url>")
    try:
        ready = httpx.get(f"{base}/health/ready", timeout=30)
        metrics = httpx.get(f"{base}/metrics", headers={"X-API-Key": key}, timeout=30)
    except httpx.HTTPError as exc:
        print(f"ALERT: service unreachable: {type(exc).__name__}")
        sys.exit(2)
    alerts = [] if ready.status_code == 200 else [f"/health/ready returned {ready.status_code}"]
    if metrics.status_code != 200:
        alerts.append(f"/metrics returned {metrics.status_code}")
    else:
        alerts += metrics.json().get("alerts", [])
    for line in alerts:
        print("ALERT:", line)
    sys.exit(1 if alerts else 0)
