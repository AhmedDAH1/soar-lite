"""Add triage_results table (AI triage suggestions)

Revision ID: a3f1c9e2b7d4
Revises: 0d8827f40b4f
Create Date: 2026-11-08 19:00:00.000000

"""
from typing import Sequence, Union

import sqlalchemy as sa

from alembic import op

revision: str = 'a3f1c9e2b7d4'
down_revision: Union[str, Sequence[str], None] = '0d8827f40b4f'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table('triage_results',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('incident_id', sa.Integer(), nullable=False),
    sa.Column('status', sa.String(length=20), nullable=False),
    sa.Column('mode', sa.String(length=20), nullable=False),
    sa.Column('model', sa.String(length=200), nullable=True),
    sa.Column('verdict', sa.String(length=30), nullable=True),
    sa.Column('severity', sa.String(length=20), nullable=True),
    sa.Column('confidence', sa.Float(), nullable=True),
    sa.Column('reasoning', sa.Text(), nullable=True),
    sa.Column('next_steps', sa.JSON(), nullable=True),
    sa.Column('evidence', sa.JSON(), nullable=True),
    sa.Column('injection_suspected', sa.Boolean(), nullable=True),
    sa.Column('model_flagged_injection', sa.Boolean(), nullable=True),
    sa.Column('overrides', sa.JSON(), nullable=True),
    sa.Column('context', sa.JSON(), nullable=True),
    sa.Column('valid', sa.Boolean(), nullable=True),
    sa.Column('error', sa.Text(), nullable=True),
    sa.Column('decision', sa.String(length=20), nullable=True),
    sa.Column('decided_by', sa.String(length=100), nullable=True),
    sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('(CURRENT_TIMESTAMP)'), nullable=True),
    sa.Column('completed_at', sa.DateTime(timezone=True), nullable=True),
    sa.ForeignKeyConstraint(['incident_id'], ['incidents.id'], ),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_triage_results_id'), 'triage_results', ['id'], unique=False)
    op.create_index(op.f('ix_triage_results_incident_id'), 'triage_results', ['incident_id'], unique=False)


def downgrade() -> None:
    op.drop_index(op.f('ix_triage_results_incident_id'), table_name='triage_results')
    op.drop_index(op.f('ix_triage_results_id'), table_name='triage_results')
    op.drop_table('triage_results')
