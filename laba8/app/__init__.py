from flask import Flask
from flask_bcrypt import Bcrypt
from flask_login import LoginManager
import os

app = Flask(__name__)
app.secret_key = b"277764450344399279392461713642952840400"
#using secrets.SystemRandom().getrandbits(128)

bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.login_message_category = 'warning'

from app import views
from app import database