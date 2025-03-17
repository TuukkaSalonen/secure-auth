from flask import Flask
from flask_jwt_extended import JWTManager
from flask_login import LoginManager
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from .config import Config
from flask_cors import CORS

# Initialize the app
app = Flask(__name__)

app.config.from_object(Config)

CORS(app, resources={r"/api/*": {"origins": "http://localhost:5173"}}, supports_credentials=True)

# Initialize SQLAlchemy
db = SQLAlchemy(app)

migrate = Migrate(app, db)

# Initialize JWTManager
jwt = JWTManager(app)

# Initialize LoginManager
login_manager = LoginManager(app)

from . import routes, models

