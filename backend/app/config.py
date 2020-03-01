import os

class DevConfig(object):
    DEBUG = True
    TESTING = True
    SQLALCHEMY_DATABASE_URI = 'postgresql+psycopg2://dev:mypassword@db/application'
    SQLALCHEMY_TRACK_MODIFICATIONS = False

if os.environ.get('FLASK_ENV') == 'production':
    # TODO make a prod config
    raise Exception('No config for production yet')
else:
    Config = DevConfig
