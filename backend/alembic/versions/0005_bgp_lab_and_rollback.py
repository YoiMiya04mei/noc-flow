"""BGP Lab integration and automated rollback schema

Revision ID: 0005_bgp_lab_and_rollback
Revises: 0004_recommendation_and_approval_workflow
Create Date: 2026-10-22 15:45:00.000000

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa

revision: str = '0005_bgp_lab_and_rollback'
down_revision: Union[str, None] = '0004_recommendation_and_approval_workflow'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # 1. Create lab_test_runs table
    op.create_table(
        'lab_test_runs',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('change_request_id', sa.Integer(), sa.ForeignKey('change_requests.id', ondelete='SET NULL'), nullable=True),
        sa.Column('test_type', sa.String(length=30), nullable=False),
        sa.Column('target_speaker', sa.String(length=50), nullable=False),
        sa.Column('target_peer', sa.String(length=45), nullable=False),
        sa.Column('prefix', sa.String(length=50), nullable=False),
        sa.Column('pre_check_status', sa.String(length=20), server_default='PENDING', nullable=False),
        sa.Column('pre_check_details', sa.Text(), nullable=True),
        sa.Column('post_check_status', sa.String(length=20), server_default='PENDING', nullable=False),
        sa.Column('post_check_details', sa.Text(), nullable=True),
        sa.Column('execution_status', sa.String(length=30), server_default='PENDING', nullable=False),
        sa.Column('rollback_status', sa.String(length=30), server_default='NONE', nullable=False),
        sa.Column('rollback_details', sa.Text(), nullable=True),
        sa.Column('initial_snapshot', sa.Text(), nullable=True),
        sa.Column('final_snapshot', sa.Text(), nullable=True),
        sa.Column('error_message', sa.Text(), nullable=True),
        sa.Column('operator_id', sa.Integer(), sa.ForeignKey('users.id'), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('completed_at', sa.DateTime(timezone=True), nullable=True),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_lab_test_runs_id'), 'lab_test_runs', ['id'], unique=False)
    op.create_index(op.f('ix_lab_test_runs_prefix'), 'lab_test_runs', ['prefix'], unique=False)
    op.create_index(op.f('ix_lab_test_runs_change_request_id'), 'lab_test_runs', ['change_request_id'], unique=False)

    # 2. Add lab_tested and lab_test_run_id to change_requests
    op.add_column('change_requests', sa.Column('lab_tested', sa.Boolean(), server_default=sa.text('false'), nullable=False))
    op.add_column('change_requests', sa.Column('lab_test_run_id', sa.Integer(), sa.ForeignKey('lab_test_runs.id', ondelete='SET NULL'), nullable=True))


def downgrade() -> None:
    op.drop_column('change_requests', 'lab_test_run_id')
    op.drop_column('change_requests', 'lab_tested')
    op.drop_index(op.f('ix_lab_test_runs_change_request_id'), table_name='lab_test_runs')
    op.drop_index(op.f('ix_lab_test_runs_prefix'), table_name='lab_test_runs')
    op.drop_index(op.f('ix_lab_test_runs_id'), table_name='lab_test_runs')
    op.drop_table('lab_test_runs')
