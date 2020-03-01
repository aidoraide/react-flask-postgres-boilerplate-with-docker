from flask_restful import Api, Resource
from flask_sqlalchemy_session import current_session

from .user import User, Me
from .auth import SignUp, Login

api = Api()
api.add_resource(User, '/')
api.add_resource(Me, '/me')
api.add_resource(SignUp, '/auth/signup')
api.add_resource(Login, '/auth/login')
