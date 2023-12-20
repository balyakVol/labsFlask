from app import app
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
import os

app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv("DATABASE_URL", "sqlite:///flaskdb.db")

db = SQLAlchemy(app)

class Todo(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100))
    description = db.Column(db.String(200))
    complete = db.Column(db.Boolean)

with app.app_context():
    db.create_all()

migrate = Migrate(app, db)