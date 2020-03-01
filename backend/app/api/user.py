from flask import jsonify, request
from flask_restful import Resource
from flask_sqlalchemy_session import current_session

from .auth import auth_required
from ..models.user import User as UserModel

class User(Resource):
    def get(self):
        users = [user.to_dict() for user in current_session.query(UserModel).all()]
        return jsonify(users)

class Me(Resource):
    @auth_required
    def get(self, user):
        return jsonify(user.to_dict())
