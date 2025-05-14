import os
from dotenv import load_dotenv
from datetime import timedelta
import logging
from logging.handlers import RotatingFileHandler

load_dotenv()

# Set the environment variables for the application
class Config:
    FRONTEND_URL = os.getenv('FRONTEND_URL', 'http://localhost:5173')
    SECRET_KEY = os.getenv('SECRET_KEY', 'secret-key')
    JWT_SECRET_KEY = os.getenv('JWT_SECRET_KEY', 'jwt-secret-key')
    SQLALCHEMY_DATABASE_URI = os.getenv('DATABASE_URL')
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    JWT_TOKEN_LOCATION = ["cookies"]
    JWT_ACCESS_COOKIE_NAME = "access_token_cookie"
    JWT_REFRESH_COOKIE_NAME = "refresh_token_cookie"
    JWT_COOKIE_SECURE = True
    JWT_COOKIE_HTTPONLY = True
    JWT_COOKIE_SAMESITE = "Strict"
    JWT_COOKIE_CSRF_PROTECT = True
    JWT_ACCESS_TOKEN_EXPIRES = timedelta(minutes=15)
    JWT_REFRESH_TOKEN_EXPIRES = timedelta(days=7)
    JWT_SESSION_COOKIE = False
    ENCRYPTION_KEY_MFA = os.getenv('ENCRYPTION_KEY_MFA', 'encryption-key-mfa')
    GOOGLE_CLIENT_ID = os.getenv('GOOGLE_CLIENT_ID')
    GOOGLE_CLIENT_SECRET = os.getenv('GOOGLE_CLIENT_SECRET')
    GOOGLE_REDIRECT_URI = os.getenv('GOOGLE_REDIRECT_URI', 'http://localhost:5000/api/login/google/callback')
    GITHUB_CLIENT_ID = os.getenv('GITHUB_CLIENT_ID')
    GITHUB_CLIENT_SECRET = os.getenv('GITHUB_CLIENT_SECRET')
    GITHUB_REDIRECT_URI = os.getenv('GITHUB_REDIRECT_URI', 'http://localhost:5000/api/login/github/callback')
    MASTER_KEY = os.getenv('MASTER_KEY')
    PREFERRED_URL_SCHEME = os.getenv('PREFERRED_URL_SCHEME', 'http')
    SERVER_NAME = os.getenv('SERVER_NAME', 'localhost:5000')
    LOG_FILE = os.getenv('LOG_FILE', './app/logs/app.log')
    BACKUP_DIR = os.getenv('BACKUP_DIR', './backups')

# Content Security Policy
csp = {
    'default-src': ["'self'"],
    'script-src': [
        "'self'",
    ],
    'img-src': ["'self'", "data:"], 
    'connect-src': ["'self'", "http://localhost:5173"],
    'frame-src': ["'none'"],
    'object-src': ["'none'"],
}

# Configure logging
logger = logging.getLogger('secure_app')
logger.setLevel(logging.INFO)

rotating_handler = RotatingFileHandler(Config.LOG_FILE, maxBytes=100000, backupCount=5, encoding='utf-8', delay=True)
rotating_handler.setFormatter(logging.Formatter('%(asctime)s %(levelname)s %(message)s'))

if not logger.handlers:
    logger.addHandler(rotating_handler)
logger.propagate = False