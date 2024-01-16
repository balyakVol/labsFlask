from app import app, bcrypt, login_manager
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_login import UserMixin
import os

app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv("DATABASE_URL", "sqlite:///flaskdb.db")

db = SQLAlchemy(app)

class Todo(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100))
    description = db.Column(db.String(200))
    complete = db.Column(db.Boolean)

@login_manager.user_loader
def user_loader(user_id):
    return User.query.get(int(user_id))

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    image_file = db.Column(db.String(20), nullable=False, default='default.jpg')
    password = db.Column(db.String(60), nullable=False)

    def __init__(self, username, email, image_file, password):
        self.username = username
        self.email = email
        self.image_file = image_file
        self.password = bcrypt.generate_password_hash(password).decode('utf-8')

    def validate_password(self, form_password):
        return bcrypt.check_password_hash(self.password, form_password)

    def __repr__(self):
        return f"User('{self.username}', '{self.email}', '{self.password}')"

migrate = Migrate(app, db)