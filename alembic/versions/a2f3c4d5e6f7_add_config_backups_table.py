"""add config_backups table

Revision ID: a2f3c4d5e6f7
Revises: e1a08b67ecbc
Create Date: 2026-04-02

"""
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = 'a2f3c4d5e6f7'
down_revision = 'e1a08b67ecbc'
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        'config_backups',
        sa.Column('id', sa.String(36), primary_key=True, nullable=False),
        sa.Column('device_name', sa.String(100), nullable=False, index=True),
        sa.Column('timestamp', sa.DateTime, nullable=False, index=True),
        sa.Column('file_path', sa.String(500), nullable=False),
        sa.Column('file_hash', sa.String(64), nullable=False),
        sa.Column('file_size', sa.BigInteger, nullable=False),
        sa.Column('version_number', sa.Integer, nullable=False),
        sa.Column('change_detected', sa.Boolean, nullable=False, default=False),
        sa.Column('change_summary', sa.Text, nullable=True),
    )


def downgrade():
    op.drop_table('config_backups')
