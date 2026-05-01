"""add rule_owners and certification_reviews tables

Revision ID: b3g4h5i6j7k8
Revises: a2f3c4d5e6f7
Create Date: 2026-04-03

"""
from alembic import op
import sqlalchemy as sa

revision = 'b3g4h5i6j7k8'
down_revision = 'a2f3c4d5e6f7'
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        'rule_owners',
        sa.Column('id', sa.String(36), primary_key=True, nullable=False),
        sa.Column('rule_id', sa.String(36), sa.ForeignKey('firewall_rules.id'), nullable=True),
        sa.Column('owner_name', sa.String(100), nullable=False),
        sa.Column('owner_email', sa.String(255), nullable=False),
        sa.Column('department', sa.String(100), nullable=True),
        sa.Column('assigned_date', sa.DateTime, nullable=False),
        sa.Column('last_certified_date', sa.DateTime, nullable=True),
        sa.Column('certification_due_date', sa.DateTime, nullable=True),
        sa.Column('status', sa.String(30), nullable=False, server_default='active'),
    )
    op.create_table(
        'certification_reviews',
        sa.Column('id', sa.String(36), primary_key=True, nullable=False),
        sa.Column('rule_id', sa.String(36), sa.ForeignKey('firewall_rules.id'), nullable=True),
        sa.Column('reviewer_name', sa.String(100), nullable=False),
        sa.Column('review_date', sa.DateTime, nullable=False),
        sa.Column('decision', sa.String(30), nullable=False),
        sa.Column('justification', sa.Text, nullable=True),
        sa.Column('risk_accepted', sa.Boolean, nullable=False, server_default='0'),
        sa.Column('next_review_date', sa.DateTime, nullable=True),
    )


def downgrade():
    op.drop_table('certification_reviews')
    op.drop_table('rule_owners')
