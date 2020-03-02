from flask_restful import Api, Resource
from flask_sqlalchemy_session import current_session

from .user import User, Me
from .auth import SignUp, Login, LogoutEverywhere, InitiatePasswordReset, ResetPassword

api = Api()
api.add_resource(User, '/')
api.add_resource(Me, '/me')
api.add_resource(SignUp, '/auth/signup')
api.add_resource(Login, '/auth/login')
api.add_resource(LogoutEverywhere, '/auth/logout_everywhere')
api.add_resource(InitiatePasswordReset, '/auth/initiate_password_reset')
api.add_resource(ResetPassword, '/auth/reset_password')
