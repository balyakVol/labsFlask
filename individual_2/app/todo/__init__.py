from flask import Blueprint

todo_blueprint = Blueprint('todo_bp', __name__, template_folder="templates/todo")

from . import views