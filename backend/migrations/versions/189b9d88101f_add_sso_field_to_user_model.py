"""Add sso field to user model

Revision ID: 189b9d88101f
Revises: 8e622cad5d1b
Create Date: 2025-03-26 17:10:02.113147

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '189b9d88101f'
down_revision = '8e622cad5d1b'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('users', schema=None) as batch_op:
        batch_op.add_column(sa.Column('sso_provider', sa.String(length=50), nullable=True))
        batch_op.alter_column('password_hash',
               existing_type=sa.VARCHAR(length=255),
               nullable=True)

    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('users', schema=None) as batch_op:
        batch_op.alter_column('password_hash',
               existing_type=sa.VARCHAR(length=255),
               nullable=False)
        batch_op.drop_column('sso_provider')

    # ### end Alembic commands ###
