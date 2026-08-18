"""create custom_ocsf_classes table

Revision ID: 0001
Revises: 
Create Date: 2026-08-17

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = '0001'
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        'custom_ocsf_classes',
        sa.Column('id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('organization_id', sa.String(length=255), nullable=False),
        sa.Column('class_uid', sa.Integer(), nullable=False),
        sa.Column('class_name', sa.String(length=255), nullable=False),
        sa.Column('category_uid', sa.Integer(), nullable=False),
        sa.Column('attributes', sa.JSON(), nullable=False),
        sa.Column('version', sa.Integer(), nullable=False, server_default='1'),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=True),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('organization_id', 'class_uid', name='uix_org_class_uid')
    )
    op.create_index(
        'ix_custom_ocsf_classes_organization_id',
        'custom_ocsf_classes',
        ['organization_id'],
        unique=False
    )


def downgrade() -> None:
    op.drop_index('ix_custom_ocsf_classes_organization_id', table_name='custom_ocsf_classes')
    op.drop_table('custom_ocsf_classes')