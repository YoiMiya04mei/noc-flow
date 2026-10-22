"""Phase 7: Mitigation (FlowSpec & RTBH), Rollout State Machine, and Circuit Breaker

Revision ID: 0006_phase7_mitigation_and_rollout
Revises: 0005_bgp_lab_and_rollback
Create Date: 2026-10-22 16:30:00.000000

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa

revision: str = '0006_phase7_mitigation_and_rollout'
down_revision: Union[str, None] = '0005_bgp_lab_and_rollback'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # 1. Threat Candidates table
    op.create_table(
        'threat_candidates',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('threat_type', sa.String(length=50), nullable=False),
        sa.Column('severity', sa.String(length=20), server_default='HIGH', nullable=False),
        sa.Column('target_prefix', sa.String(length=50), nullable=False),
        sa.Column('source_prefix', sa.String(length=50), nullable=True),
        sa.Column('protocol', sa.Integer(), nullable=True),
        sa.Column('target_port', sa.Integer(), nullable=True),
        sa.Column('source_port', sa.Integer(), nullable=True),
        sa.Column('detected_bps', sa.Float(), server_default='0.0', nullable=False),
        sa.Column('detected_pps', sa.Float(), server_default='0.0', nullable=False),
        sa.Column('confidence_score', sa.Float(), server_default='85.0', nullable=False),
        sa.Column('status', sa.String(length=30), server_default='DETECTED', nullable=False),
        sa.Column('evidence_summary', sa.Text(), nullable=False),
        sa.Column('recommended_action', sa.String(length=50), server_default='flowspec_rate_limit', nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('expires_at', sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_threat_candidates_id'), 'threat_candidates', ['id'], unique=False)
    op.create_index(op.f('ix_threat_candidates_target_prefix'), 'threat_candidates', ['target_prefix'], unique=False)

    # 2. Mitigation Rules table
    op.create_table(
        'mitigation_rules',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('threat_id', sa.Integer(), sa.ForeignKey('threat_candidates.id', ondelete='SET NULL'), nullable=True),
        sa.Column('change_request_id', sa.Integer(), sa.ForeignKey('change_requests.id', ondelete='SET NULL'), nullable=True),
        sa.Column('rule_type', sa.String(length=20), nullable=False),
        sa.Column('target_prefix', sa.String(length=50), nullable=False),
        sa.Column('source_prefix', sa.String(length=50), nullable=True),
        sa.Column('protocol', sa.Integer(), nullable=True),
        sa.Column('src_port_range', sa.String(length=50), nullable=True),
        sa.Column('dst_port_range', sa.String(length=50), nullable=True),
        sa.Column('tcp_flags', sa.String(length=50), nullable=True),
        sa.Column('action_type', sa.String(length=30), nullable=False),
        sa.Column('action_value', sa.String(length=100), nullable=True),
        sa.Column('status', sa.String(length=30), server_default='DRAFT', nullable=False),
        sa.Column('ttl_minutes', sa.Integer(), server_default='60', nullable=False),
        sa.Column('expires_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('withdrawal_plan', sa.Text(), nullable=False),
        sa.Column('created_by_id', sa.Integer(), sa.ForeignKey('users.id'), nullable=False),
        sa.Column('approved_by_id', sa.Integer(), sa.ForeignKey('users.id'), nullable=True),
        sa.Column('second_approved_by_id', sa.Integer(), sa.ForeignKey('users.id'), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('activated_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('withdrawn_at', sa.DateTime(timezone=True), nullable=True),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_mitigation_rules_id'), 'mitigation_rules', ['id'], unique=False)
    op.create_index(op.f('ix_mitigation_rules_target_prefix'), 'mitigation_rules', ['target_prefix'], unique=False)

    # 3. Rollout Executions table
    op.create_table(
        'rollout_executions',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('change_request_id', sa.Integer(), sa.ForeignKey('change_requests.id', ondelete='SET NULL'), nullable=True),
        sa.Column('mitigation_rule_id', sa.Integer(), sa.ForeignKey('mitigation_rules.id', ondelete='SET NULL'), nullable=True),
        sa.Column('rollout_type', sa.String(length=30), server_default='CANARY', nullable=False),
        sa.Column('current_stage', sa.Integer(), server_default='1', nullable=False),
        sa.Column('total_stages', sa.Integer(), server_default='3', nullable=False),
        sa.Column('status', sa.String(length=30), server_default='DRAFT', nullable=False),
        sa.Column('scope_prefixes', sa.Text(), nullable=False),
        sa.Column('change_window_start', sa.DateTime(timezone=True), nullable=True),
        sa.Column('change_window_end', sa.DateTime(timezone=True), nullable=True),
        sa.Column('pre_check_report', sa.Text(), nullable=True),
        sa.Column('post_check_report', sa.Text(), nullable=True),
        sa.Column('rollback_details', sa.Text(), nullable=True),
        sa.Column('correlation_id', sa.String(length=64), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('completed_at', sa.DateTime(timezone=True), nullable=True),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_rollout_executions_id'), 'rollout_executions', ['id'], unique=False)
    op.create_index(op.f('ix_rollout_executions_correlation_id'), 'rollout_executions', ['correlation_id'], unique=False)

    # 4. Circuit Breaker Events table
    op.create_table(
        'circuit_breaker_events',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('scope', sa.String(length=30), server_default='GLOBAL', nullable=False),
        sa.Column('scope_target', sa.String(length=100), nullable=True),
        sa.Column('state', sa.String(length=20), server_default='CLOSED', nullable=False),
        sa.Column('trigger_reason', sa.Text(), nullable=False),
        sa.Column('consecutive_failures', sa.Integer(), server_default='0', nullable=False),
        sa.Column('triggered_by', sa.String(length=50), nullable=True),
        sa.Column('reset_by_id', sa.Integer(), sa.ForeignKey('users.id'), nullable=True),
        sa.Column('reset_notes', sa.Text(), nullable=True),
        sa.Column('triggered_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('reset_at', sa.DateTime(timezone=True), nullable=True),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_circuit_breaker_events_id'), 'circuit_breaker_events', ['id'], unique=False)


def downgrade() -> None:
    op.drop_index(op.f('ix_circuit_breaker_events_id'), table_name='circuit_breaker_events')
    op.drop_table('circuit_breaker_events')

    op.drop_index(op.f('ix_rollout_executions_correlation_id'), table_name='rollout_executions')
    op.drop_index(op.f('ix_rollout_executions_id'), table_name='rollout_executions')
    op.drop_table('rollout_executions')

    op.drop_index(op.f('ix_mitigation_rules_target_prefix'), table_name='mitigation_rules')
    op.drop_index(op.f('ix_mitigation_rules_id'), table_name='mitigation_rules')
    op.drop_table('mitigation_rules')

    op.drop_index(op.f('ix_threat_candidates_target_prefix'), table_name='threat_candidates')
    op.drop_index(op.f('ix_threat_candidates_id'), table_name='threat_candidates')
    op.drop_table('threat_candidates')
