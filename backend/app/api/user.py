from flask import jsonify, request
from flask_restful import Resource
from flask_sqlalchemy_session import current_session

from ..models.user import User as UserModel

class User(Resource):
    def get(self):
        print(request.headers.get('host'), flush=True)
        users = [user.to_dict() for user in current_session.query(UserModel).all()]
        return jsonify(users)
