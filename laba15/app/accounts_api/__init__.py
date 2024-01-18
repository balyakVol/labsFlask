from flask import Blueprint

accounts_api_blueprint = Blueprint('account_api_bp', __name__, template_folder="templates/accounts_api")

from . import views