"""one complaint per payment, enforced by the database

Revision ID: 0005
Revises: 0004
"""

from alembic import op

revision = "0005"
down_revision = "0004"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # If duplicates already exist, keep the one furthest along (a refunded or decided complaint must never
    # be the one deleted), then the oldest. A fresh database has none.
    op.execute(
        """
        DELETE FROM app_complaints WHERE id IN (
            SELECT id FROM (
                SELECT id, row_number() OVER (
                    PARTITION BY payment_id
                    ORDER BY CASE status
                        WHEN 'refunded' THEN 0 WHEN 'refund_approved' THEN 1 WHEN 'refund_declined' THEN 2
                        WHEN 'fast_tracked' THEN 3 WHEN 'in_review' THEN 4 ELSE 5 END,
                        id
                ) AS n FROM app_complaints
            ) ranked WHERE n > 1
        )
        """
    )
    op.drop_index("ix_app_complaints_payment_id", table_name="app_complaints")
    op.create_unique_constraint("uq_app_complaints_payment_id", "app_complaints", ["payment_id"])


def downgrade() -> None:
    op.drop_constraint("uq_app_complaints_payment_id", "app_complaints", type_="unique")
    op.create_index("ix_app_complaints_payment_id", "app_complaints", ["payment_id"])
