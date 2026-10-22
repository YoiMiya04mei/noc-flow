"""SNMP engine and interface metrics migration

Revision ID: 0002_snmp_engine
Revises: 0001_initial_schema
Create Date: 2026-10-22 10:40:00.000000

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa

revision: str = '0002_snmp_engine'
down_revision: Union[str, None] = '0001_initial_schema'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # 1. SNMP Profiles table
    op.create_table(
        'snmp_profiles',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('name', sa.String(length=100), nullable=False),
        sa.Column('version', sa.String(length=10), server_default='v3', nullable=False),
        sa.Column('port', sa.Integer(), server_default='161', nullable=False),
        sa.Column('timeout_sec', sa.Float(), server_default='3.0', nullable=False),
        sa.Column('retries', sa.Integer(), server_default='2', nullable=False),
        sa.Column('security_name', sa.String(length=64), nullable=True),
        sa.Column('auth_protocol', sa.String(length=20), server_default='SHA', nullable=True),
        sa.Column('auth_pass_encrypted', sa.String(length=512), nullable=True),
        sa.Column('priv_protocol', sa.String(length=20), server_default='AES', nullable=True),
        sa.Column('priv_pass_encrypted', sa.String(length=512), nullable=True),
        sa.Column('community_encrypted', sa.String(length=512), nullable=True),
        sa.Column('is_active', sa.Boolean(), server_default='true', nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('name')
    )
    op.create_index(op.f('ix_snmp_profiles_id'), 'snmp_profiles', ['id'], unique=False)

    # 2. Add columns to devices
    op.add_column('devices', sa.Column('snmp_profile_id', sa.Integer(), sa.ForeignKey('snmp_profiles.id', ondelete='SET NULL'), nullable=True))
    op.add_column('devices', sa.Column('snmp_status', sa.String(length=30), server_default='unconfigured', nullable=False))
    op.add_column('devices', sa.Column('sys_uptime', sa.BigInteger(), nullable=True))
    op.add_column('devices', sa.Column('sys_descr', sa.String(length=255), nullable=True))
    op.add_column('devices', sa.Column('last_polled_at', sa.DateTime(timezone=True), nullable=True))
    op.add_column('devices', sa.Column('last_poll_duration_ms', sa.Float(), nullable=True))
    op.add_column('devices', sa.Column('last_poll_error', sa.String(length=255), nullable=True))

    # 3. Add columns to interfaces
    op.add_column('interfaces', sa.Column('in_pps', sa.BigInteger(), server_default='0', nullable=False))
    op.add_column('interfaces', sa.Column('out_pps', sa.BigInteger(), server_default='0', nullable=False))
    op.add_column('interfaces', sa.Column('last_in_octets', sa.BigInteger(), nullable=True))
    op.add_column('interfaces', sa.Column('last_out_octets', sa.BigInteger(), nullable=True))
    op.add_column('interfaces', sa.Column('last_in_pkts', sa.BigInteger(), nullable=True))
    op.add_column('interfaces', sa.Column('last_out_pkts', sa.BigInteger(), nullable=True))
    op.add_column('interfaces', sa.Column('last_uptime', sa.BigInteger(), nullable=True))

    # 4. Interface Metrics History table
    op.create_table(
        'interface_metrics_history',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('interface_id', sa.Integer(), sa.ForeignKey('interfaces.id', ondelete='CASCADE'), nullable=False),
        sa.Column('device_id', sa.Integer(), sa.ForeignKey('devices.id', ondelete='CASCADE'), nullable=False),
        sa.Column('timestamp', sa.DateTime(timezone=True), nullable=False),
        sa.Column('in_bps', sa.BigInteger(), server_default='0', nullable=False),
        sa.Column('out_bps', sa.BigInteger(), server_default='0', nullable=False),
        sa.Column('in_pps', sa.BigInteger(), server_default='0', nullable=False),
        sa.Column('out_pps', sa.BigInteger(), server_default='0', nullable=False),
        sa.Column('utilization_pct', sa.Float(), server_default='0.0', nullable=False),
        sa.Column('oper_status', sa.String(length=20), server_default='up', nullable=False),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_interface_metrics_history_id'), 'interface_metrics_history', ['id'], unique=False)
    op.create_index(op.f('ix_interface_metrics_history_interface_id'), 'interface_metrics_history', ['interface_id'], unique=False)
    op.create_index(op.f('ix_interface_metrics_history_device_id'), 'interface_metrics_history', ['device_id'], unique=False)
    op.create_index(op.f('ix_interface_metrics_history_timestamp'), 'interface_metrics_history', ['timestamp'], unique=False)


def downgrade() -> None:
    op.drop_table('interface_metrics_history')
    op.drop_column('interfaces', 'last_uptime')
    op.drop_column('interfaces', 'last_out_pkts')
    op.drop_column('interfaces', 'last_in_pkts')
    op.drop_column('interfaces', 'last_out_octets')
    op.drop_column('interfaces', 'last_in_octets')
    op.drop_column('interfaces', 'out_pps')
    op.drop_column('interfaces', 'in_pps')

    op.drop_column('devices', 'last_poll_error')
    op.drop_column('devices', 'last_poll_duration_ms')
    op.drop_column('devices', 'last_polled_at')
    op.drop_column('devices', 'sys_descr')
    op.drop_column('devices', 'sys_uptime')
    op.drop_column('devices', 'snmp_status')
    op.drop_column('devices', 'snmp_profile_id')

    op.drop_table('snmp_profiles')
