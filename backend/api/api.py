from flask import jsonify
from flask_restful import Resource, Api
from flask_sqlalchemy_session import current_session

from .models.User import User as UserModel

api = Api()

class User(Resource):
    def get(self):
        users = [user.to_dict() for user in current_session.query(UserModel).all()]
        return jsonify(users)

api.add_resource(User, '/')
