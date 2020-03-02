from datetime import datetime, timedelta
from functools import wraps

import bcrypt
import jwt

from flask import jsonify, request, current_app, render_template
from flask_restful import reqparse, Resource
from flask_sqlalchemy_session import current_session
from flask_mail import Message

from .resource import TransactionalJSONResource, JSONResource
from .error import ClientError, UnauthorizedError
from ..models.user import User as UserModel
from ..models.password_reset_request import PasswordResetRequest
from ..utils.mail import mail

emailParser = reqparse.RequestParser()
emailParser.add_argument('email', help='This field cannot be blank', required=True)

emailAndPasswordParser = emailParser.copy()
emailAndPasswordParser.add_argument('password', help='This field cannot be blank', required=True)


def generate_jwt(user):
    data = {
        'id': user.id,
        'expiresAt': (datetime.utcnow() + timedelta(minutes=60)).timestamp(),
        'issuedAt': datetime.utcnow().timestamp(),
    }
    return jwt.encode(data, current_app.config['JWT_PRIVATE_KEY'], algorithm='RS256').decode()


def parse_jwt(encoded_jwt):
    return jwt.decode(encoded_jwt, current_app.config['JWT_PUBLIC_KEY'])


def auth_required(original_func=None, *, refresh=True):
    def decorate(func):
        @wraps(func)
        def wrapped(*args, **kwargs):
            authorization = request.headers.get('Authorization')
            if not authorization:
                raise UnauthorizedError()
            strip_auth = authorization.lstrip('Bearer').strip()
            if authorization == strip_auth:
                raise UnauthorizedError()
            try:
                decoded_jwt = parse_jwt(strip_auth)
            except Exception as e:
                raise UnauthorizedError()
            if datetime.utcnow().timestamp() > decoded_jwt['expiresAt']:
                raise UnauthorizedError('EXPIRED_TOKEN')
            user = current_session.query(UserModel).filter(UserModel.id == decoded_jwt['id']).first()
            if user is None:
                raise Exception('Valid JWT has no corresponding user in DB') # 500 error, email admins
            if user.last_logout is not None and  decoded_jwt['issuedAt'] < user.last_logout.timestamp():
                raise UnauthorizedError()
            if len(args) > 0 and isinstance(args[0], Resource):
                # Make sure 'self' is the first arg
                resp = func(args[0], user, *args[1:], **kwargs)
            else:
                resp = func(user, *args, **kwargs)
            
            if refresh:
                return {
                    'token': generate_jwt(user),
                    'response': resp,
                }
            else:
                return {
                    'response': resp,
                }
        return wrapped
    
    if original_func:
        return decorate(original_func)
    return decorate


class SignUp(TransactionalJSONResource):
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
        return {'token': generate_jwt(fetched_user)}


class Login(TransactionalJSONResource):
    def post(self):
        data = emailAndPasswordParser.parse_args()
        email, password = data['email'], data['password']
        user = current_session.query(UserModel).filter(UserModel.email == email).scalar()
        if user is None:
            raise UnauthorizedError()
        try:
            matches = bcrypt.checkpw(password.encode(), user.password_hash.encode())
            if not matches:
                raise UnauthorizedError()
        except ValueError as e:
            raise UnauthorizedError()
        return {'token': generate_jwt(user)}


class LogoutEverywhere(TransactionalJSONResource):
    @auth_required(refresh=False)
    def post(self, user):
        user.last_logout = datetime.utcnow()
        return {'status': 'success'}


class InitiatePasswordReset(JSONResource):
    def post(self):
        data = emailParser.parse_args()
        email = data['email']
        user = current_session.query(UserModel).filter(UserModel.email == email).scalar()
        if user is None:
            return {'status': 'success'}
        
        secret_code = PasswordResetRequest.generate_secret_code()
        reset_request = PasswordResetRequest(user_id=user.id, secret_code=secret_code)
        current_session.add(reset_request)
        current_session.commit()
        msg = Message("Reset Your Password",
            sender="from@example.com",
            recipients=[user.email],
            html=render_template('reset_password.html', **{'user': user, 'reset_request': reset_request, 'REACT_URL': 'http://localhost:3000'})
        )
        mail.send(msg)
        return {'status': 'success'}


resetPasswordArgs = reqparse.RequestParser()
resetPasswordArgs.add_argument('password', help='This field cannot be blank', required=True)
resetPasswordArgs.add_argument('secret_code', help='This field cannot be blank', required=True)
resetPasswordArgs.add_argument('password_reset_request_id', type=int, help='This field cannot be blank', required=True)
class ResetPassword(TransactionalJSONResource):
    def post(self):
        data = resetPasswordArgs.parse_args()

        reset_request = current_session.query(PasswordResetRequest)\
            .filter(PasswordResetRequest.id == data['password_reset_request_id'])\
            .filter(PasswordResetRequest.secret_code == data['secret_code'])\
            .scalar()
        
        if reset_request is None:
            return UnauthorizedError()
        if reset_request.expires_at < datetime.utcnow():
            return ClientError('EXPIRED_RESET_REQUEST')
        
        user = current_session.query(UserModel).filter(UserModel.id == reset_request.user_id).first()
        salt = bcrypt.gensalt()
        hashed = bcrypt.hashpw(data['password'].encode(), bcrypt.gensalt()).decode()
        user.password_hash = hashed

        return {'status': 'success'}


endpoints = {
    '/signup': SignUp,
    '/login': Login,
    '/logout_everywhere': LogoutEverywhere,
    '/initiate_password_reset': InitiatePasswordReset,
    '/reset_password': ResetPassword,
}
