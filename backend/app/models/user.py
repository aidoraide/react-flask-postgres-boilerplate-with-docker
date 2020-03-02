from datetime import datetime

from sqlalchemy.sql import func, expression
from sqlalchemy_utils import EmailType

from .db import Base, Convert2Dict, db


class User(Base, Convert2Dict):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    email = db.Column(EmailType, nullable=False, unique=True, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    last_logout = db.Column(db.DateTime(), nullable=True)
    confirmed_email = db.Column(db.Boolean(), nullable=False, server_default=expression.false())

    def __repr__(self):
        return f'<User {self.id}:{self.email}>'
