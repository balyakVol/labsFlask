from flask import Blueprint

cookies_blueprint = Blueprint('cookies_bp', __name__, template_folder="templates/cookies")

from . import views