from flask import Flask
from flask_jwt_extended import JWTManager
from flask_login import LoginManager
from flask_migrate import Migrate
from .config import Config
from flask_cors import CORS
from flask_talisman import Talisman
from .config import csp
from .db import db
from . import session_cleanup

# Initialize the app
app = Flask(__name__)

app.config.from_object(Config)

db.init_app(app)

migrate = Migrate(app, db)

# Initialize JWTManager
jwt = JWTManager(app)

CORS(app, resources={r"/api/*": {"origins": "http://localhost:5173"}}, supports_credentials=True)

# Initialize Talisman
Talisman(app, content_security_policy=csp, frame_options='DENY') 

# Initialize LoginManager
login_manager = LoginManager(app)

session_cleanup.scheduler.start()

from . import routes, models

