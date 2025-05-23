from flask import Flask
from flask_jwt_extended import JWTManager
from flask_migrate import Migrate
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from .config import Config
from flask_cors import CORS
from flask_talisman import Talisman
from .config import csp
from .db import db
from . import session_cleanup
from . import db_backup
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

# Register OAuth providers
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

# Setup CORS
CORS(app, resources={r"/api/*": {"origins": "http://localhost:5173/*"}}, supports_credentials=True, expose_headers=["Content-Disposition"])

# Initialize Talisman
Talisman(app, content_security_policy=csp, frame_options='DENY', force_https=False) 

# Initialize rate limiter
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["1000 per day", "200 per hour"],
    storage_uri="memory://",
)

# Start the session cleanup scheduler
session_cleanup.start_cleanup_scheduler()

# Start the database backup scheduler
db_backup.start_backup_scheduler()

from . import routes, models