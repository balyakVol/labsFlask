from flask import Blueprint

contacts_blueprint = Blueprint('contacts_bp', __name__, template_folder="templates/contacts")

from . import views