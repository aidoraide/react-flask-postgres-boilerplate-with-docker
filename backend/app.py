import logging
from flask import Flask, jsonify
from flask_cors import CORS
from flask_sqlalchemy_session import flask_scoped_session

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.api.api import api
from app.api.error import APIException
from app.models.db import db
from app.utils.mail import mail
from app.utils.config import Config


def create_app(config):
    app = Flask(__name__, template_folder='app/templates')
    app.config.from_object(config)
    engine = create_engine(Config.SQLALCHEMY_DATABASE_URI)
    session_factory = sessionmaker(bind=engine)
    session = flask_scoped_session(session_factory, app)
    register_extensions(app)
    CORS(app)
    return app


def register_extensions(app):
    api.init_app(app)
    db.init_app(app)
    mail.init_app(app)


app = create_app(Config)


@app.errorhandler(APIException)
def handle_invalid_usage(error):
    response = jsonify(error.to_dict())
    response.status_code = error.status_code
    return response


# Run the application
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=80, debug=True)
