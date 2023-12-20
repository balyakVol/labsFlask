from flask import Flask

app = Flask(__name__)
app.secret_key = b"277764450344399279392461713642952840400"
#using secrets.SystemRandom().getrandbits(128)

from app import views
from app import database