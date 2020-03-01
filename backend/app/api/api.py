from flask import jsonify, request
from flask_restful import Api
from flask_sqlalchemy_session import current_session

from .user import User

def wrapper(func):
    def wrapped(*args, **kwargs):
        print('IN WRAPPY BOI')
        r = func(*args, **kwargs)
        print('AFTER FUNC', r, flush=True)
        return r
    return wrapped

api = Api()
api.add_resource(User, '/')
