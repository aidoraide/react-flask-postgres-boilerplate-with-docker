from flask import jsonify
from flask_restful import Resource, Api

from .models import Player as PlayerModel, to_dict

api = Api()

class Player(Resource):
    def get(self):
        all_players = [to_dict(player) for player in PlayerModel.query.all()]
        return jsonify(all_players)

api.add_resource(Player, '/')
