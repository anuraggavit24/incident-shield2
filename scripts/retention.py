"""Apply the data-retention rule: after N days, remove personal details that are no longer needed.

Usage: python scripts/retention.py [days=180]            (dry run: prints what would change)
       python scripts/retention.py [days=180] --confirm  (applies it)

For payments older than N days it blanks the complaint text and the AI-read notes, and removes the device id,
network hash and browser measurements from the payment. It keeps amounts, statuses, timestamps, the sealed
decision and the audit chain, which are the financial and evidential record. Sealed decisions still contain
the evidence used at the time (encrypted); deleting those would break the chain, so they are kept, and
destroying the old encryption key is the way to make them unreadable.
"""

import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from dotenv import load_dotenv  # noqa: E402

load_dotenv()

from sqlalchemy import select, update  # noqa: E402

from app import audit, db  # noqa: E402
from app.models import AppComplaint, AppPayment  # noqa: E402


def run(days: int, confirm: bool) -> dict[str, int]:
    cutoff = datetime.now(timezone.utc) - timedelta(days=days)
    with db.session_scope() as session:
        old = select(AppPayment.id).where(AppPayment.created_at < cutoff)
        payments = session.scalars(
            select(AppPayment.id).where(AppPayment.created_at < cutoff, AppPayment.device_id.is_not(None))
        ).all()
        complaints = session.scalars(
            select(AppComplaint.id).where(AppComplaint.payment_id.in_(old), AppComplaint.text != "")
        ).all()
        if confirm and (payments or complaints):
            session.execute(
                update(AppPayment).where(AppPayment.id.in_(payments)).values(device_id=None, ip_hash=None, client={})
            )
            for c in session.scalars(select(AppComplaint).where(AppComplaint.id.in_(complaints))):
                c.text = ""
                c.claims = {k: v for k, v in c.claims.items() if k.startswith("_")}
            audit.record(
                session,
                "owner",
                "retention_applied",
                f"older_than_days:{days}",
                {"payments": len(payments), "complaints": len(complaints)},
                datetime.now(timezone.utc),
            )
        return {"payments": len(payments), "complaints": len(complaints)}


if __name__ == "__main__":
    args = [a for a in sys.argv[1:] if a != "--confirm"]
    days = int(args[0]) if args and args[0].isdigit() else 180
    if days < 30:
        sys.exit("refusing: retention under 30 days would remove evidence for open complaints")
    done = run(days, "--confirm" in sys.argv)
    verb = "Cleared" if "--confirm" in sys.argv else "Would clear (dry run, add --confirm)"
    print(f"{verb}: device/network/behaviour on {done['payments']} payments, text on {done['complaints']} complaints")
