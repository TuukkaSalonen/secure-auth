from app import db
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timezone
from .keyUtils import encrypt_secret_MFA, decrypt_secret_MFA

# User model
class User(db.Model):
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=True)
    mfa_enabled = db.Column(db.Boolean, default=False)
    mfa_secret_hash = db.Column(db.String(255), nullable=True)
    sso_provider = db.Column(db.String(50), nullable=True)
 
    def __init__(self, username, password=None, sso_provider=None):
        self.username = username
        if password:
            self.password_hash = generate_password_hash(password) 
        if sso_provider:
            self.sso_provider = sso_provider

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)
    
    def set_mfa_secret(self, secret):
        self.mfa_secret_hash = encrypt_secret_MFA(secret)

    def get_mfa_secret(self):
        return decrypt_secret_MFA(self.mfa_secret_hash)

# User session model   
class UserSession(db.Model):
    __tablename__ = 'user_sessions'

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(255), nullable=False)
    access_token = db.Column(db.String(1024), nullable=False)
    refresh_token_jti = db.Column(db.String(36), nullable=False)
    expires_at = db.Column(db.DateTime, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.now(timezone.utc))

    def __repr__(self):
        return f"<UserSession {self.user_id}>"