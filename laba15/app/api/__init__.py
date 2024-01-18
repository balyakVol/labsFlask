from flask import Blueprint

api_blueprint = Blueprint('api_bp', __name__, template_folder="templates/api")

from . import views