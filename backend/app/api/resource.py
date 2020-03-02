from flask import jsonify
from flask_restful import Resource
from flask_sqlalchemy_session import current_session


class JSONResource(Resource):
    def dispatch_request(self, *args, **kwargs):
        resp = super().dispatch_request(*args, **kwargs)
        if 'response' in resp: 
            return jsonify(resp)
        else:
            return jsonify({'response': resp})


class TransactionalJSONResource(JSONResource):
    def dispatch_request(self, *args, **kwargs):
        resp = super().dispatch_request(*args, **kwargs)
        current_session.commit()
        return resp
