"""Create a key for one named reviewer. Usage: python scripts/make_reviewer_key.py asha [days]

Prints the key ONCE (give it to that person) and the entry to add to the REVIEWERS variable, which holds only
hashes: REVIEWERS=asha:<sha256>:<last day>,ravi:<sha256>:<last day>. The key stops working after the last
day (default 30 days from now). To remove a reviewer sooner, delete their entry and redeploy.
"""

import hashlib
import re
import secrets
import sys
from datetime import datetime, timedelta, timezone

if __name__ == "__main__":
    name = (sys.argv[1] if len(sys.argv) > 1 else "").strip().lower()
    days = int(sys.argv[2]) if len(sys.argv) > 2 and sys.argv[2].isdigit() else 30
    if not re.fullmatch(r"[a-z0-9_]{2,24}", name) or name == "owner" or not 1 <= days <= 365:
        sys.exit("usage: python scripts/make_reviewer_key.py <name> [days 1-365]   (name: a-z, 0-9, _)")
    key = secrets.token_urlsafe(32)
    last_day = (datetime.now(timezone.utc) + timedelta(days=days)).date().isoformat()
    print(f"Reviewer key for {name} (shown once, do not commit or paste in chat):\n  {key}")
    print(f"Add to REVIEWERS in .env / Render (works until {last_day}):")
    print(f"  {name}:{hashlib.sha256(key.encode()).hexdigest()}:{last_day}")
