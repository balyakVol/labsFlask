from flask import Flask
from .extensions import db, migrate, bcrypt, jwt, login_manager
from config import config

def create_app(config_name = None):
    app = Flask(__name__)
    app.config.from_object(config.get(config_name))

    from config import DevConfig, ProdConfig, TestConfig

    if config_name == 'prod':
        app.config.from_object(ProdConfig)
    elif config_name == 'test':
        app.config.from_object(TestConfig)
    else:
        app.config.from_object(DevConfig)

    db.init_app(app)
    migrate.init_app(app, db, render_as_batch=True)
    login_manager.init_app(app)
    bcrypt.init_app(app)
    jwt.init_app(app)

    login_manager.login_view = "auth_bp.login"
    login_manager.login_message = "Щоб побачити цю сторінку, необхідно авторизуватися!"
    login_manager.login_message_category = "error"
    
    with app.app_context():
        from .home import home_blueprint
        app.register_blueprint(home_blueprint, url_prefix='/')

        from .auth import auth_blueprint
        app.register_blueprint(auth_blueprint, url_prefix='/auth')

        from .account import account_blueprint
        app.register_blueprint(account_blueprint, url_prefix='/account')

        from .todo import todo_blueprint
        app.register_blueprint(todo_blueprint, url_prefix='/todo')

        from .cookies import cookies_blueprint
        app.register_blueprint(cookies_blueprint, url_prefix='/cookies')

        from .post import post_blueprint
        app.register_blueprint(post_blueprint, url_prefix='/post')

        from .api import api_blueprint
        app.register_blueprint(api_blueprint, url_prefix='/api')

        from .contacts import contacts_blueprint
        app.register_blueprint(contacts_blueprint, url_prefix='/contacts')

        return app