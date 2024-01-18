from app import db

class Contacts(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100))
    second_name = db.Column(db.String(100))
    number = db.Column(db.Integer)