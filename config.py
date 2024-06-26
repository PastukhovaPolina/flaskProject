import os

basedir = os.path.abspath(os.path.dirname(__file__))


class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY') or "hard to unlock"
    MAIL_SERVER = os.environ.get('MAIL_SERVER') or "smtp.googlemail.com"
    MAIL_PORT = os.environ.get('MAIL_PORT') or "587"
    MAIL_USE_TLS = int(os.environ.get('MAIL_USE_TLS', '5870'))
    MAIL_USERNAME = os.environ.get('MAIL_USERNAME') or "poltest1708@gmail.com"
    MAIL_PASSWORD = os.environ.get('MAIL_PASSWORD') or "zihs xewo wcco rchu"
    SQLALCHEMY_TRACK_MODIFICATIONS = True
    FLASK_ADMIN = 'test@testovich.ru'

    @staticmethod
    def init_app(app):
        pass


class DevelopmentConfig(Config):
    DEBUG = True
    SQLALCHEMY_DATABASE_URI = os.environ.get('DEV_DATABASE_URL') or \
        'mysql://root:@localhost/flask_education'


class TestingConfig(Config):
    TESTING = True
    SQLALCHEMY_DATABASE_URI = os.environ.get('TEST_DATABASE_URL') or \
        'mysql://root:@localhost/flask_education'


class ProductionConfig(Config):
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or \
        'mysql://root:@localhost/flask_education'


config = {
    'development': DevelopmentConfig,
    'testing': TestingConfig,
    'production': ProductionConfig,
    'default': DevelopmentConfig
}
