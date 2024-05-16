from flask import Flask, Response
from os import path

def create_app():
    app = Flask(__name__)

    app.secret_key = 'super secret key'
    app.config['SESSION_TYPE'] = 'filesystem'

    from .views import views
    from .attack import attack
    from .detection import detection

    app.register_blueprint(views, url_prefix='/')
    app.register_blueprint(attack, url_prefix='/attack')
    app.register_blueprint(detection, url_prefix='/detection')

    return app