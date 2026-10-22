"""Recommendation engine scoring, lifecycle, and dual-approval workflow

Revision ID: 0004_recommendation_and_approval_workflow
Revises: 0003_bgp_bmp_and_probing
Create Date: 2026-10-22 13:10:00.000000

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa

revision: str = '0004_recommendation_and_approval_workflow'
down_revision: Union[str, None] = '0003_bgp_bmp_and_probing'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # 1. Add columns to recommendations
    op.add_column('recommendations', sa.Column('policy_id', sa.Integer(), sa.ForeignKey('scoring_policies.id'), nullable=True))
    op.add_column('recommendations', sa.Column('score_breakdown', sa.Text(), nullable=True))
    op.add_column('recommendations', sa.Column('current_metrics', sa.Text(), nullable=True))
    op.add_column('recommendations', sa.Column('candidate_metrics', sa.Text(), nullable=True))
    op.add_column('recommendations', sa.Column('data_quality', sa.Text(), nullable=True))
    op.add_column('recommendations', sa.Column('rejection_reasons', sa.Text(), nullable=True))
    op.add_column('recommendations', sa.Column('input_snapshot_hash', sa.String(length=64), nullable=True))
    op.add_column('recommendations', sa.Column('expires_at', sa.DateTime(timezone=True), nullable=True))

    # 2. Add columns to change_requests
    op.add_column('change_requests', sa.Column('second_approver_id', sa.Integer(), sa.ForeignKey('users.id'), nullable=True))
    op.add_column('change_requests', sa.Column('second_approved_at', sa.DateTime(timezone=True), nullable=True))
    op.add_column('change_requests', sa.Column('requires_dual_approval', sa.Boolean(), server_default='true', nullable=False))
    op.add_column('change_requests', sa.Column('policy_snapshot', sa.Text(), nullable=True))
    op.add_column('change_requests', sa.Column('impact_summary', sa.Text(), nullable=True))
    op.add_column('change_requests', sa.Column('expires_at', sa.DateTime(timezone=True), nullable=True))
    op.add_column('change_requests', sa.Column('is_cancelled', sa.Boolean(), server_default='false', nullable=False))
    op.add_column('change_requests', sa.Column('cancellation_reason', sa.Text(), nullable=True))

    # 3. Add columns to scoring_policies
    op.add_column('scoring_policies', sa.Column('min_improvement_score', sa.Float(), server_default='10.0', nullable=False))
    op.add_column('scoring_policies', sa.Column('max_acceptable_loss_pct', sa.Float(), server_default='5.0', nullable=False))
    op.add_column('scoring_policies', sa.Column('max_acceptable_latency_ms', sa.Float(), server_default='250.0', nullable=False))
    op.add_column('scoring_policies', sa.Column('max_utilization_pct', sa.Float(), server_default='90.0', nullable=False))


def downgrade() -> None:
    op.drop_column('scoring_policies', 'max_utilization_pct')
    op.drop_column('scoring_policies', 'max_acceptable_latency_ms')
    op.drop_column('scoring_policies', 'max_acceptable_loss_pct')
    op.drop_column('scoring_policies', 'min_improvement_score')

    op.drop_column('change_requests', 'cancellation_reason')
    op.drop_column('change_requests', 'is_cancelled')
    op.drop_column('change_requests', 'expires_at')
    op.drop_column('change_requests', 'impact_summary')
    op.drop_column('change_requests', 'policy_snapshot')
    op.drop_column('change_requests', 'requires_dual_approval')
    op.drop_column('change_requests', 'second_approved_at')
    op.drop_column('change_requests', 'second_approver_id')

    op.drop_column('recommendations', 'expires_at')
    op.drop_column('recommendations', 'input_snapshot_hash')
    op.drop_column('recommendations', 'rejection_reasons')
    op.drop_column('recommendations', 'data_quality')
    op.drop_column('recommendations', 'candidate_metrics')
    op.drop_column('recommendations', 'current_metrics')
    op.drop_column('recommendations', 'score_breakdown')
    op.drop_column('recommendations', 'policy_id')
