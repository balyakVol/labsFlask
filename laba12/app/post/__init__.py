from flask import Blueprint

post_blueprint = Blueprint('post_bp', __name__, template_folder="templates/post", static_folder="static/post")

from . import views