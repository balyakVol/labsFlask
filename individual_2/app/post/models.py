import enum

from app import db
from datetime import datetime
from sqlalchemy.types import Enum

class PostType(enum.Enum):
    News = 'News'
    Publication = 'Publication'
    Other = 'Other'

post_tag = db.Table('post_tag',
                    db.Column('post_id', db.Integer, db.ForeignKey('post.id')),
                    db.Column('tag_id', db.Integer, db.ForeignKey('tag.id'))
                    )

class Post(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    text = db.Column(db.Text, nullable=True)
    image_file = db.Column(db.String(64), nullable=False, server_default='postdefault.png')
    created = db.Column(db.DateTime, default=datetime.now())
    type = db.Column(db.Enum(PostType))   
    enabled = db.Column(db.Boolean, default=True, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    category_id = db.Column(db.Integer, db.ForeignKey('category.id', name='fk_category_id'), nullable=True)
    tags = db.relationship('Tag', secondary=post_tag, backref='posts')

    def __repr__(self):
        return f"Post('{self.title}', '{self.created}', '{self.type}', '{self.user_id})"
    
class Category(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), nullable=False)
    posts = db.relationship('Post', backref='category', lazy=True)

class Tag(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), nullable=False)