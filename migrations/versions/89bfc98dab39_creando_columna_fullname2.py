"""Creando columna fullname2

Revision ID: 89bfc98dab39
Revises: f801f3453769
Create Date: 2024-01-09 13:19:17.150847

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '89bfc98dab39'
down_revision: Union[str, None] = 'f801f3453769'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # ### commands auto generated by Alembic - please adjust! ###
    op.add_column('user', sa.Column('full_name2', sa.String(), nullable=True))
    # ### end Alembic commands ###


def downgrade() -> None:
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_column('user', 'full_name2')
    # ### end Alembic commands ###