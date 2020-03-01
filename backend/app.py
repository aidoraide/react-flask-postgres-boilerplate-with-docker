from flask import Flask
from flask_cors import CORS
from flask_sqlalchemy_session import flask_scoped_session

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from api.api import api
from api.models.db import db
from api.config import Config

def create_app(config):
    app = Flask(__name__)
    CORS(app)
    app.config.from_object(config)
    register_extensions(app)
    return app


def register_extensions(app):
    api.init_app(app)
    db.init_app(app)


engine = create_engine(Config.SQLALCHEMY_DATABASE_URI)
session_factory = sessionmaker(bind=engine)

app = create_app(Config)
session = flask_scoped_session(session_factory, app)
app.logger.info('Starting server...')

# Run the application
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=80, debug=True)
