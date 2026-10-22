"""Initial schema migration

Revision ID: 0001_initial_schema
Revises: 
Create Date: 2026-10-22 09:30:00.000000

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa

revision: str = '0001_initial_schema'
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Users
    op.create_table(
        'users',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('username', sa.String(length=64), nullable=False),
        sa.Column('email', sa.String(length=128), nullable=False),
        sa.Column('password_hash', sa.String(length=255), nullable=False),
        sa.Column('full_name', sa.String(length=128), nullable=True),
        sa.Column('role', sa.String(length=32), nullable=False),
        sa.Column('status', sa.String(length=32), nullable=False),
        sa.Column('is_active', sa.Boolean(), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('last_login_at', sa.DateTime(timezone=True), nullable=True),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index(op.f('ix_users_username'), 'users', ['username'], unique=True)
    op.create_index(op.f('ix_users_email'), 'users', ['email'], unique=True)

    # Sites
    op.create_table(
        'sites',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('name', sa.String(length=100), nullable=False),
        sa.Column('code', sa.String(length=20), nullable=False),
        sa.Column('location', sa.String(length=255), nullable=True),
        sa.Column('status', sa.String(length=30), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('name'),
    )
    op.create_index(op.f('ix_sites_code'), 'sites', ['code'], unique=True)

    # Providers
    op.create_table(
        'providers',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('name', sa.String(length=100), nullable=False),
        sa.Column('provider_asn', sa.BigInteger(), nullable=False),
        sa.Column('cost_weight', sa.Float(), nullable=False),
        sa.Column('capacity_bps', sa.BigInteger(), nullable=False),
        sa.Column('status', sa.String(length=30), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('name'),
    )
    op.create_index(op.f('ix_providers_provider_asn'), 'providers', ['provider_asn'])

    # Devices
    op.create_table(
        'devices',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('hostname', sa.String(length=128), nullable=False),
        sa.Column('mgmt_ip', sa.String(length=45), nullable=False),
        sa.Column('vendor', sa.String(length=64), nullable=False),
        sa.Column('model', sa.String(length=64), nullable=True),
        sa.Column('site_id', sa.Integer(), nullable=True),
        sa.Column('status', sa.String(length=30), nullable=False),
        sa.Column('last_seen_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(['site_id'], ['sites.id']),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index(op.f('ix_devices_hostname'), 'devices', ['hostname'], unique=True)

    # Interfaces
    op.create_table(
        'interfaces',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('device_id', sa.Integer(), nullable=False),
        sa.Column('if_index', sa.Integer(), nullable=False),
        sa.Column('if_name', sa.String(length=64), nullable=False),
        sa.Column('alias', sa.String(length=128), nullable=True),
        sa.Column('speed_bps', sa.BigInteger(), nullable=False),
        sa.Column('admin_status', sa.String(length=20), nullable=False),
        sa.Column('oper_status', sa.String(length=20), nullable=False),
        sa.Column('in_bps', sa.BigInteger(), nullable=False),
        sa.Column('out_bps', sa.BigInteger(), nullable=False),
        sa.Column('utilization_pct', sa.Float(), nullable=False),
        sa.Column('last_polled_at', sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(['device_id'], ['devices.id']),
        sa.PrimaryKeyConstraint('id'),
    )

    # Collectors
    op.create_table(
        'collectors',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('name', sa.String(length=100), nullable=False),
        sa.Column('host', sa.String(length=128), nullable=False),
        sa.Column('port', sa.Integer(), nullable=False),
        sa.Column('collector_type', sa.String(length=30), nullable=False),
        sa.Column('site_id', sa.Integer(), nullable=True),
        sa.Column('status', sa.String(length=30), nullable=False),
        sa.Column('packets_received', sa.BigInteger(), nullable=False),
        sa.Column('flows_parsed', sa.BigInteger(), nullable=False),
        sa.Column('parse_errors', sa.BigInteger(), nullable=False),
        sa.Column('last_seen_at', sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(['site_id'], ['sites.id']),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('name'),
    )

    # BGP Peers & Route Events
    op.create_table(
        'bgp_peers',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('device_id', sa.Integer(), nullable=True),
        sa.Column('peer_ip', sa.String(length=45), nullable=False),
        sa.Column('local_as', sa.BigInteger(), nullable=False),
        sa.Column('remote_as', sa.BigInteger(), nullable=False),
        sa.Column('peer_name', sa.String(length=100), nullable=True),
        sa.Column('state', sa.String(length=30), nullable=False),
        sa.Column('uptime_seconds', sa.BigInteger(), nullable=False),
        sa.Column('prefixes_received', sa.Integer(), nullable=False),
        sa.Column('prefixes_advertised', sa.Integer(), nullable=False),
        sa.Column('data_source', sa.String(length=30), nullable=False),
        sa.Column('last_change_at', sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(['device_id'], ['devices.id']),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index(op.f('ix_bgp_peers_peer_ip'), 'bgp_peers', ['peer_ip'], unique=True)

    op.create_table(
        'route_events',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('peer_ip', sa.String(length=45), nullable=False),
        sa.Column('event_type', sa.String(length=30), nullable=False),
        sa.Column('prefix', sa.String(length=50), nullable=False),
        sa.Column('as_path', sa.String(length=255), nullable=True),
        sa.Column('next_hop', sa.String(length=45), nullable=True),
        sa.Column('communities', sa.String(length=255), nullable=True),
        sa.Column('data_source', sa.String(length=30), nullable=False),
        sa.Column('timestamp', sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint('id'),
    )

    # Probes
    op.create_table(
        'probe_targets',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('target_ip', sa.String(length=45), nullable=False),
        sa.Column('target_name', sa.String(length=100), nullable=False),
        sa.Column('probe_type', sa.String(length=20), nullable=False),
        sa.Column('provider_id', sa.Integer(), nullable=True),
        sa.Column('egress_interface', sa.String(length=64), nullable=True),
        sa.Column('interval_seconds', sa.Integer(), nullable=False),
        sa.Column('timeout_ms', sa.Integer(), nullable=False),
        sa.Column('is_active', sa.Boolean(), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(['provider_id'], ['providers.id']),
        sa.PrimaryKeyConstraint('id'),
    )

    op.create_table(
        'probe_results',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('target_id', sa.Integer(), nullable=False),
        sa.Column('provider_id', sa.Integer(), nullable=True),
        sa.Column('latency_ms', sa.Float(), nullable=False),
        sa.Column('loss_percent', sa.Float(), nullable=False),
        sa.Column('jitter_ms', sa.Float(), nullable=False),
        sa.Column('hops', sa.Integer(), nullable=False),
        sa.Column('status', sa.String(length=20), nullable=False),
        sa.Column('data_source', sa.String(length=30), nullable=False),
        sa.Column('timestamp', sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(['provider_id'], ['providers.id']),
        sa.ForeignKeyConstraint(['target_id'], ['probe_targets.id']),
        sa.PrimaryKeyConstraint('id'),
    )

    # Policies & Allowlists
    op.create_table(
        'prefix_allowlists',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('prefix', sa.String(length=50), nullable=False),
        sa.Column('description', sa.String(length=255), nullable=True),
        sa.Column('is_active', sa.Boolean(), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index(op.f('ix_prefix_allowlists_prefix'), 'prefix_allowlists', ['prefix'], unique=True)

    op.create_table(
        'peer_allowlists',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('peer_ip', sa.String(length=45), nullable=False),
        sa.Column('peer_asn', sa.Integer(), nullable=False),
        sa.Column('description', sa.String(length=255), nullable=True),
        sa.Column('is_active', sa.Boolean(), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index(op.f('ix_peer_allowlists_peer_ip'), 'peer_allowlists', ['peer_ip'], unique=True)

    op.create_table(
        'scoring_policies',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('name', sa.String(length=100), nullable=False),
        sa.Column('latency_weight', sa.Float(), nullable=False),
        sa.Column('loss_weight', sa.Float(), nullable=False),
        sa.Column('jitter_weight', sa.Float(), nullable=False),
        sa.Column('cost_weight', sa.Float(), nullable=False),
        sa.Column('utilization_weight', sa.Float(), nullable=False),
        sa.Column('hold_down_minutes', sa.Integer(), nullable=False),
        sa.Column('hysteresis_threshold_pct', sa.Float(), nullable=False),
        sa.Column('is_active', sa.Boolean(), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('name'),
    )

    # Recommendations & Change Requests
    op.create_table(
        'recommendations',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('prefix', sa.String(length=50), nullable=False),
        sa.Column('current_path', sa.String(length=128), nullable=False),
        sa.Column('candidate_path', sa.String(length=128), nullable=False),
        sa.Column('score_current', sa.Float(), nullable=False),
        sa.Column('score_candidate', sa.Float(), nullable=False),
        sa.Column('confidence_pct', sa.Float(), nullable=False),
        sa.Column('reason', sa.Text(), nullable=False),
        sa.Column('risk_level', sa.String(length=20), nullable=False),
        sa.Column('status', sa.String(length=30), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint('id'),
    )

    op.create_table(
        'change_requests',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('recommendation_id', sa.Integer(), nullable=True),
        sa.Column('requester_id', sa.Integer(), nullable=False),
        sa.Column('approver_id', sa.Integer(), nullable=True),
        sa.Column('target_peer', sa.String(length=45), nullable=False),
        sa.Column('prefix', sa.String(length=50), nullable=False),
        sa.Column('diff_payload', sa.Text(), nullable=False),
        sa.Column('justification', sa.Text(), nullable=False),
        sa.Column('validation_status', sa.String(length=30), nullable=False),
        sa.Column('execution_status', sa.String(length=30), nullable=False),
        sa.Column('rollback_instructions', sa.Text(), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('approved_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('executed_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('rolled_back_at', sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(['approver_id'], ['users.id']),
        sa.ForeignKeyConstraint(['recommendation_id'], ['recommendations.id']),
        sa.ForeignKeyConstraint(['requester_id'], ['users.id']),
        sa.PrimaryKeyConstraint('id'),
    )

    # Alerts & Incidents
    op.create_table(
        'alert_rules',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('name', sa.String(length=100), nullable=False),
        sa.Column('rule_type', sa.String(length=40), nullable=False),
        sa.Column('severity', sa.String(length=20), nullable=False),
        sa.Column('threshold_value', sa.Float(), nullable=False),
        sa.Column('is_active', sa.Boolean(), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('name'),
    )

    op.create_table(
        'alert_incidents',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('rule_id', sa.Integer(), nullable=True),
        sa.Column('severity', sa.String(length=20), nullable=False),
        sa.Column('title', sa.String(length=150), nullable=False),
        sa.Column('description', sa.Text(), nullable=False),
        sa.Column('target_entity', sa.String(length=100), nullable=False),
        sa.Column('status', sa.String(length=20), nullable=False),
        sa.Column('acknowledged_by', sa.String(length=64), nullable=True),
        sa.Column('started_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('acknowledged_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('resolved_at', sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(['rule_id'], ['alert_rules.id']),
        sa.PrimaryKeyConstraint('id'),
    )

    # Audit Events (Append-only)
    op.create_table(
        'audit_events',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('actor_username', sa.String(length=64), nullable=False),
        sa.Column('actor_role', sa.String(length=32), nullable=False),
        sa.Column('action', sa.String(length=64), nullable=False),
        sa.Column('resource_type', sa.String(length=64), nullable=False),
        sa.Column('resource_id', sa.String(length=64), nullable=True),
        sa.Column('details', sa.Text(), nullable=True),
        sa.Column('ip_address', sa.String(length=45), nullable=True),
        sa.Column('timestamp', sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index(op.f('ix_audit_events_actor_username'), 'audit_events', ['actor_username'])
    op.create_index(op.f('ix_audit_events_action'), 'audit_events', ['action'])
    op.create_index(op.f('ix_audit_events_resource_type'), 'audit_events', ['resource_type'])
    op.create_index(op.f('ix_audit_events_timestamp'), 'audit_events', ['timestamp'])


def downgrade() -> None:
    op.drop_table('audit_events')
    op.drop_table('alert_incidents')
    op.drop_table('alert_rules')
    op.drop_table('change_requests')
    op.drop_table('recommendations')
    op.drop_table('scoring_policies')
    op.drop_table('peer_allowlists')
    op.drop_table('prefix_allowlists')
    op.drop_table('probe_results')
    op.drop_table('probe_targets')
    op.drop_table('route_events')
    op.drop_table('bgp_peers')
    op.drop_table('collectors')
    op.drop_table('interfaces')
    op.drop_table('devices')
    op.drop_table('providers')
    op.drop_table('sites')
    op.drop_table('users')
