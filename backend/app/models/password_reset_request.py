import secrets
from datetime import datetime, timedelta

from sqlalchemy import text
from sqlalchemy.sql import func
from sqlalchemy_utils import EmailType

from .db import Base, db
from .user import User


MINUTES_ALIVE = 30
N_BYTES_SECRET = 128


class PasswordResetRequest(Base):
    __tablename__ = 'password_reset_requests'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    user_id = db.Column(db.Integer, db.ForeignKey(User.id), nullable=False)
    secret_code = db.Column(db.String(N_BYTES_SECRET*2), nullable=False)
    created_at = db.Column(db.DateTime(), nullable=False, server_default=func.now())
    expires_at = db.Column(db.DateTime(), nullable=False, server_default=text(f"(now() + '{MINUTES_ALIVE} minutes')"))

    def generate_secret_code() -> str:
        return secrets.token_hex(N_BYTES_SECRET)
