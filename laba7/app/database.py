from app import app
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_bcrypt import Bcrypt
import os

app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv("DATABASE_URL", "sqlite:///flaskdb.db")

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)

class Todo(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100))
    description = db.Column(db.String(200))
    complete = db.Column(db.Boolean)

class User(db.Model):
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
    
with app.app_context():
    db.create_all()

migrate = Migrate(app, db)