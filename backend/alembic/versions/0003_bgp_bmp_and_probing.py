"""BGP BMP routes and active probing extension

Revision ID: 0003_bgp_bmp_and_probing
Revises: 0002_snmp_engine
Create Date: 2026-10-22 11:30:00.000000

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa

revision: str = '0003_bgp_bmp_and_probing'
down_revision: Union[str, None] = '0002_snmp_engine'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # 1. BGP Routes Table
    op.create_table(
        'bgp_routes',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('prefix', sa.String(length=50), nullable=False),
        sa.Column('peer_ip', sa.String(length=45), nullable=False),
        sa.Column('peer_asn', sa.BigInteger(), nullable=False),
        sa.Column('best_path', sa.String(length=100), nullable=True),
        sa.Column('next_hop', sa.String(length=45), nullable=True),
        sa.Column('as_path', sa.String(length=255), nullable=True),
        sa.Column('origin', sa.String(length=20), server_default='IGP', nullable=False),
        sa.Column('med', sa.Integer(), nullable=True),
        sa.Column('local_pref', sa.Integer(), nullable=True),
        sa.Column('communities', sa.String(length=255), nullable=True),
        sa.Column('data_source', sa.String(length=30), server_default='simulated', nullable=False),
        sa.Column('is_active', sa.Boolean(), server_default='true', nullable=False),
        sa.Column('last_updated', sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_bgp_routes_id'), 'bgp_routes', ['id'], unique=False)
    op.create_index(op.f('ix_bgp_routes_prefix'), 'bgp_routes', ['prefix'], unique=False)
    op.create_index(op.f('ix_bgp_routes_peer_ip'), 'bgp_routes', ['peer_ip'], unique=False)

    # 2. Add columns to bgp_peers
    op.add_column('bgp_peers', sa.Column('router_id', sa.String(length=45), nullable=True))
    op.add_column('bgp_peers', sa.Column('last_error', sa.String(length=255), nullable=True))

    # 3. Add columns to probe_targets
    op.add_column('probe_targets', sa.Column('port', sa.Integer(), server_default='80', nullable=True))
    op.add_column('probe_targets', sa.Column('source_ip', sa.String(length=45), nullable=True))
    op.add_column('probe_targets', sa.Column('last_probed_at', sa.DateTime(timezone=True), nullable=True))
    op.add_column('probe_targets', sa.Column('last_latency_ms', sa.Float(), nullable=True))
    op.add_column('probe_targets', sa.Column('last_loss_percent', sa.Float(), nullable=True))
    op.add_column('probe_targets', sa.Column('last_status', sa.String(length=30), server_default='standby', nullable=False))

    # 4. Add columns to probe_results
    op.add_column('probe_results', sa.Column('min_latency_ms', sa.Float(), nullable=True))
    op.add_column('probe_results', sa.Column('max_latency_ms', sa.Float(), nullable=True))
    op.add_column('probe_results', sa.Column('egress_mode', sa.String(length=30), server_default='os_routing', nullable=False))


def downgrade() -> None:
    op.drop_column('probe_results', 'egress_mode')
    op.drop_column('probe_results', 'max_latency_ms')
    op.drop_column('probe_results', 'min_latency_ms')

    op.drop_column('probe_targets', 'last_status')
    op.drop_column('probe_targets', 'last_loss_percent')
    op.drop_column('probe_targets', 'last_latency_ms')
    op.drop_column('probe_targets', 'last_probed_at')
    op.drop_column('probe_targets', 'source_ip')
    op.drop_column('probe_targets', 'port')

    op.drop_column('bgp_peers', 'last_error')
    op.drop_column('bgp_peers', 'router_id')

    op.drop_table('bgp_routes')
