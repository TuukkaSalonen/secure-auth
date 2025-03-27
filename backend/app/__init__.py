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
from authlib.integrations.flask_client import OAuth

# Initialize the app
app = Flask(__name__)

app.config.from_object(Config)

db.init_app(app)

migrate = Migrate(app, db)

# Initialize JWTManager
jwt = JWTManager(app)

# Initialize OAuth
oauth = OAuth(app)

oauth.register(
    name="google",
    client_id=app.config['GOOGLE_CLIENT_ID'],
    client_secret=app.config['GOOGLE_CLIENT_SECRET'],
    authorize_url="https://accounts.google.com/o/oauth2/auth",
    authorize_params=None,
    access_token_url="https://oauth2.googleapis.com/token",
    access_token_params=None,
    client_kwargs={"scope": "openid email profile"},
    api_base_url="https://www.googleapis.com/",
    jwks_uri="https://www.googleapis.com/oauth2/v3/certs",
)

oauth.register(
    name="github",
    client_id=app.config["GITHUB_CLIENT_ID"],
    client_secret=app.config["GITHUB_CLIENT_SECRET"],
    authorize_url="https://github.com/login/oauth/authorize",
    authorize_params={"scope": "user:email"},
    access_token_url="https://github.com/login/oauth/access_token",
    api_base_url="https://api.github.com/",
    client_kwargs={"scope": "user:email"},
)

CORS(app, resources={r"/api/*": {"origins": "http://localhost:5173"}}, supports_credentials=True)

# Initialize Talisman
Talisman(app, content_security_policy=csp, frame_options='DENY') 

# Initialize LoginManager
login_manager = LoginManager(app)

session_cleanup.scheduler.start()

from . import routes, models