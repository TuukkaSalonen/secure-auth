from app import db
import os
import uuid
from sqlalchemy.dialects.postgresql import UUID
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timezone
from .keyUtils import encrypt_secret_MFA, decrypt_secret_MFA, encrypt_user_key, decrypt_user_key

# User model
class User(db.Model):
    __tablename__ = 'users'

    id = db.Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=True)
    mfa_enabled = db.Column(db.Boolean, default=False)
    mfa_secret_hash = db.Column(db.String(255), nullable=True)
    sso_provider = db.Column(db.String(50), nullable=True)
    user_key = db.Column(db.LargeBinary, nullable=True)
    iv = db.Column(db.LargeBinary, nullable=True)
 
    def __init__(self, username, password=None, sso_provider=None):
        self.username = username
        if password:
            self.password_hash = generate_password_hash(password) 
        if sso_provider:
            self.sso_provider = sso_provider
        self.user_key, self.iv = encrypt_user_key(os.urandom(32)) # Generate a random user key and encrypt it on register

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)
    
    def set_mfa_secret(self, secret):
        self.mfa_secret_hash = encrypt_secret_MFA(secret)

    def get_mfa_secret(self):
        return decrypt_secret_MFA(self.mfa_secret_hash)
    
    def decrypt_user_key(self):
        return decrypt_user_key(self.user_key, self.iv)

# User session model   
class UserSession(db.Model):
    __tablename__ = 'user_sessions'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(UUID(as_uuid=True), db.ForeignKey('users.id'), nullable=False)
    access_token = db.Column(db.String(1024), nullable=False)
    refresh_token_jti = db.Column(db.String(36), nullable=False)
    expires_at = db.Column(db.DateTime, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.now(timezone.utc))

    def __repr__(self):
        return f"<UserSession {self.user_id}>"

# File model
class UploadedFile(db.Model):
    __tablename__ = 'uploaded_files'

    id = db.Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id = db.Column(UUID(as_uuid=True), db.ForeignKey('users.id'), nullable=False)
    user = db.relationship('User', backref=db.backref('files', lazy=True))

    filename = db.Column(db.String(255), nullable=False)
    mimetype = db.Column(db.String(100), nullable=False)
    file_size = db.Column(db.Integer, nullable=False)

    encrypted_data = db.Column(db.LargeBinary, nullable=False)
    encrypted_key = db.Column(db.LargeBinary, nullable=False)
    iv = db.Column(db.LargeBinary, nullable=False)

    uploaded_at = db.Column(db.DateTime, default=datetime.now(timezone.utc))

    def __repr__(self):
        return f"<UploadedFile {self.filename} ({self.id})>"