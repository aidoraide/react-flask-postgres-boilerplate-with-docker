from flask_restful import Api, Resource
from flask_sqlalchemy_session import current_session

class TransactionalResource(Resource):
    def dispatch_request(self, *args, **kwargs):
        resp = super(Resource, self).dispatch_request(*args, **kwargs)
        current_session.commit()
        return resp
