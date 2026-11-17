"""Distinguish encrypted scan list pairs from library credentials."""

import sqlalchemy as sa
from alembic import op

revision = "0003"
down_revision = "0002"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column(
        "credentials", sa.Column("generated", sa.Boolean(), nullable=False, server_default=sa.false())
    )


def downgrade():
    op.drop_column("credentials", "generated")
