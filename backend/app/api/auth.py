import bcrypt
import jwt
from datetime import datetime, timedelta

from flask import jsonify, request, current_app
from flask_restful import reqparse, Resource
from flask_sqlalchemy_session import current_session

from .transaction import TransactionalResource
from .error import ClientError, UnauthorizedError
from ..models.user import User as UserModel

emailAndPasswordParser = reqparse.RequestParser()
emailAndPasswordParser.add_argument('email', help='This field cannot be blank', required=True)
emailAndPasswordParser.add_argument('password', help='This field cannot be blank', required=True)


def generate_jwt(user):
    data = {
        'id': user.id,
        'expiresAt': (datetime.utcnow() + timedelta(minutes=30)).timestamp(),
    }
    return jwt.encode(data, current_app.config['JWT_PRIVATE_KEY'], algorithm='HS256').decode()


def parse_jwt(encoded_jwt):
    return jwt.decode(encoded_jwt, current_app.config['JWT_PRIVATE_KEY'], algorithms=['HS256'])


def auth_required(func):
    def wrapped(*args, **kwargs):
        authorization = request.headers.get('Authorization')
        if not authorization:
            raise UnauthorizedError()
        try:
            decoded_jwt = parse_jwt(authorization.strip())
        except Exception:
            raise UnauthorizedError()
        if datetime.utcnow().timestamp() > decoded_jwt['expiresAt']:
            raise UnauthorizedError('EXPIRED_TOKEN')
        user = current_session.query(UserModel).filter(UserModel.id == decoded_jwt['id']).first()
        if user is None:
            raise Exception('Valid JWT has no corresponding user in DB') # 500 error, email admins
        if len(args) > 0 and isinstance(args[0], Resource):
            # Make sure 'self' is the first arg
            return func(args[0], user, *args[1:], **kwargs)
        else:
            return func(user, *args, **kwargs)
    return wrapped


class SignUp(TransactionalResource):
    def post(self):
        data = emailAndPasswordParser.parse_args()
        email, password = data['email'].lower().strip(), data['password']
        if current_session.query(UserModel).filter(UserModel.email == email).first():
            raise ClientError('EMAIL_IN_USE')

        salt = bcrypt.gensalt()
        hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
        new_user = UserModel(email=email, password_hash=hashed)
        current_session.add(new_user)
        fetched_user = current_session.query(UserModel).filter(UserModel.email == email).first()
        return jsonify({'token': generate_jwt(fetched_user)})


class Login(TransactionalResource):
    def post(self):
        data = emailAndPasswordParser.parse_args()
        email, password = data['email'], data['password']
        user = current_session.query(UserModel).filter(UserModel.email == email).scalar()
        if user is None:
            raise UnauthorizedError()
        try:
            bcrypt.checkpw(password.encode(), user.password_hash.encode())
        except ValueError as e:
            raise UnauthorizedError()
        return jsonify({'token': generate_jwt(user)})
