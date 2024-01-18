from app import db, bcrypt, login_manager
from flask_login import UserMixin
from datetime import datetime

@login_manager.user_loader
def user_loader(user_id):
    return User.query.get(int(user_id))

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    about_me = db.Column(db.String(140))
    last_seen = db.Column(db.DateTime, default=datetime.now())
    password = db.Column(db.String(60), nullable=False)
    image_file = db.Column(db.String(60), nullable=False, server_default='default.jpg')

    def __init__(self, username, email, password, image_file=None):
        self.username = username
        self.email = email
        self.password = bcrypt.generate_password_hash(password).decode('utf-8')
        self.image_file = image_file or 'default.jpg'

    def validate_password(self, form_password):
        return bcrypt.check_password_hash(self.password, form_password)

    def __repr__(self):
        return f"User('{self.username}', '{self.email}', '{self.password}')"