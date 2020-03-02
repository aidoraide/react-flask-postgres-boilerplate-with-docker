from typing import Dict

from flask_restful import Api, Resource
from flask_sqlalchemy_session import current_session

from .user import endpoints as user_endpoints
from .auth import endpoints as auth_endpoints


def add_endpoints(api: Api, path_root: str, endpoints: Dict[str,Resource]):
    path_root = path_root.strip('/')
    for path, resource in endpoints.items():
        path = path.strip('/')
        full_path = f'/{path_root}/{path}'
        api.add_resource(resource, full_path)


api = Api()
add_endpoints(api, '/user', user_endpoints)
add_endpoints(api, '/auth', auth_endpoints)
