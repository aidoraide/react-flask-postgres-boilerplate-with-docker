from flask import jsonify, request
from flask_restful import Resource
from flask_sqlalchemy_session import current_session

from .resource import JSONResource
from .auth import auth_required
from ..models.user import User as UserModel

class User(JSONResource):
    def get(self):
        users = [user.to_dict() for user in current_session.query(UserModel).all()]
        return users

class Me(JSONResource):
    @auth_required
    def get(self, user):
        return user.to_dict()
