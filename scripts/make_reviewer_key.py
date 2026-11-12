"""Create a key for one named reviewer. Usage: python scripts/make_reviewer_key.py asha

Prints the key ONCE (give it to that person) and the entry to add to the REVIEWERS variable, which holds only
hashes: REVIEWERS=asha:<sha256>,ravi:<sha256>. To remove a reviewer, delete their entry and redeploy.
"""

import hashlib
import re
import secrets
import sys

if __name__ == "__main__":
    name = (sys.argv[1] if len(sys.argv) > 1 else "").strip().lower()
    if not re.fullmatch(r"[a-z0-9_]{2,24}", name) or name == "owner":
        sys.exit("usage: python scripts/make_reviewer_key.py <name>   (2-24 characters: a-z, 0-9, _)")
    key = secrets.token_urlsafe(32)
    print(f"Reviewer key for {name} (shown once, do not commit or paste in chat):\n  {key}")
    print(f"Add to REVIEWERS in .env / Render:\n  {name}:{hashlib.sha256(key.encode()).hexdigest()}")
