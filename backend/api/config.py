class DevConfig(object):
    DEBUG = True
    TESTING = True
    SQLALCHEMY_DATABASE_URI = 'postgresql+psycopg2://myuser:mypassword@db/sport_stats'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
