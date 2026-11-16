"""Run hostnames and optional SearchSploit results."""

import ipaddress
from urllib.parse import urlsplit

import sqlalchemy as sa
from alembic import op

revision = "0002"
down_revision = "0001"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column("run_hosts", sa.Column("hostname", sa.Text(), nullable=False, server_default=""))
    op.create_table(
        "cve_matches",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("run_id", sa.String(36), sa.ForeignKey("scan_runs.id", ondelete="CASCADE"), nullable=False),
        sa.Column("service_id", sa.String(36), sa.ForeignKey("services.id"), nullable=False),
        sa.Column("ip", sa.String(45), nullable=False),
        sa.Column("port", sa.Integer(), nullable=False),
        *[sa.Column(name, sa.Text(), nullable=False) for name in ["banner", "query", "cve", "title", "url"]],
        sa.Column("edb_id", sa.String(32), nullable=False),
        sa.Column("status", sa.String(32), nullable=False),
        sa.UniqueConstraint("run_id", "service_id", "edb_id"),
    )
    op.create_index("ix_cve_matches_run_id", "cve_matches", ["run_id"])
    op.create_index("ix_cve_matches_created_at", "cve_matches", ["created_at"])
    # Recover names already recorded with historical HTTP endpoints without DNS lookups.
    connection = op.get_bind()
    names = {}
    for row in connection.execute(sa.text("SELECT run_id, ip, url FROM endpoint_observations")).mappings():
        hostname = urlsplit(row["url"]).hostname
        if not hostname:
            continue
        try:
            ipaddress.ip_address(hostname)
        except ValueError:
            names.setdefault((row["run_id"], row["ip"]), set()).add(hostname)
    for (run_id, ip), hosts in names.items():
        connection.execute(
            sa.text("UPDATE run_hosts SET hostname=:hostname WHERE run_id=:run_id AND ip=:ip"),
            {"hostname": "\n".join(sorted(hosts)), "run_id": run_id, "ip": ip},
        )


def downgrade():
    op.drop_table("cve_matches")
    op.drop_column("run_hosts", "hostname")
