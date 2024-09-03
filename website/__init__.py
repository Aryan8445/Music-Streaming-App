from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from os import path
from flask_login import LoginManager

db = SQLAlchemy()
DATABASE_NAME = "music_streaming_app.db"


def create_app():
    app = Flask(__name__)
    app.config['SECRET_KEY'] = 'sjhfsdfkisjfdisnmf' 
    app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{DATABASE_NAME}'



    db.init_app(app)
    
    from .controllers import controllers
    from .auth import auth
    from .models import User

    
    
    app.register_blueprint(controllers, url_prefix='/')
    app.register_blueprint(auth, url_prefix='/')
    
    if not path.exists('instance/' + DATABASE_NAME):
        with app.app_context():
            db.create_all()
    
    
    login_manager = LoginManager()
    login_manager.login_view = 'auth.login'
    login_manager.init_app(app)

    @login_manager.user_loader
    def load_user(id):
        return User.query.get(int(id))

    return app

    