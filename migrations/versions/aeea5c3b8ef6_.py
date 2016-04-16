"""empty message

Revision ID: aeea5c3b8ef6
Revises: None
Create Date: 2016-04-16 00:14:12.118150

"""

# revision identifiers, used by Alembic.
revision = 'aeea5c3b8ef6'
down_revision = None

from alembic import op
import sqlalchemy as sa


def upgrade():
    ### commands auto generated by Alembic - please adjust! ###
    op.create_table('users',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('email', sa.Unicode(length=80), nullable=True),
    sa.Column('password_hash', sa.LargeBinary(), nullable=True),
    sa.Column('is_facebook', sa.Boolean(), nullable=True),
    sa.Column('fb_id', sa.Unicode(length=100), nullable=True),
    sa.Column('token_hash', sa.Unicode(length=32), nullable=True),
    sa.Column('number', sa.Integer(), nullable=True),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_users_fb_id'), 'users', ['fb_id'], unique=False)
    op.create_index(op.f('ix_users_id'), 'users', ['id'], unique=False)
    ### end Alembic commands ###


def downgrade():
    ### commands auto generated by Alembic - please adjust! ###
    op.drop_index(op.f('ix_users_id'), table_name='users')
    op.drop_index(op.f('ix_users_fb_id'), table_name='users')
    op.drop_table('users')
    ### end Alembic commands ###
