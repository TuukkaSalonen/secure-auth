from datetime import timedelta, datetime
from sqlalchemy import DateTime
from flask import request, jsonify, send_file
import io
from flask_jwt_extended import get_jwt, create_access_token, create_refresh_token, jwt_required, get_jwt_identity, set_access_cookies, set_refresh_cookies
from . import db
from . import app 
from .models import User, UserSession
import pyotp
import qrcode
from .validators import check_login_input, check_mfa_input

# Check if the JWT is valid
@app.route('/api/check', methods=['GET'])
@jwt_required()
def check_token():
    current_user = get_jwt_identity()
    claims = get_jwt()

    if not current_user:
        return jsonify(message="No active session", mfa_enabled=False), 401
    
    mfa_enabled = claims.get('mfa_enabled', False)
    return jsonify(user=current_user, mfa_enabled=mfa_enabled), 200

# Refresh access token with refresh token
@app.route('/api/refresh', methods=['POST'])
@jwt_required(refresh=True)
def refresh():
    current_user = get_jwt_identity()
    claims = get_jwt()
    existing_session = UserSession.query.filter_by(username=current_user).first()
    
    if existing_session and existing_session.expires_at < datetime.now():
        delete_session(existing_session)
        existing_session = None

    if not existing_session:
        return jsonify(message="Session expired, please log in again."), 401
    
    mfa_enabled = claims.get('mfa_enabled', False)

    access_token = create_access_token(identity=current_user, additional_claims={ 'mfa_enabled': mfa_enabled })
    update_session(existing_session, access_token)

    response = jsonify(user=current_user, mfa_enabled=mfa_enabled)
    set_access_cookies(response, access_token)
    
    return response, 200

# Login with username and password
@app.route('/api/login', methods=['POST'])
def login():
    data = request.json

    if not data or not isinstance(data, dict):
        return jsonify(message="Invalid request"), 400

    username = data.get('username', '').strip()
    password = data.get('password', '').strip()
    
    is_valid, message = check_login_input(username, password)
    if not is_valid:
        return jsonify(message=message), 400

    user = User.query.filter_by(username=username).first()

    if user and user.check_password(password):
        if user.mfa_enabled:
            return jsonify(message="MFA required", mfa_required=True), 403
        
        access_token = create_access_token(identity=username, additional_claims={ "mfa_enabled": user.mfa_enabled }, expires_delta=timedelta(minutes=15))
        refresh_token = create_refresh_token(identity=username, expires_delta=timedelta(days=7))

        create_session(username, access_token, refresh_token)
        response = jsonify(user=username, mfa_enabled=user.mfa_enabled)

        set_access_cookies(response, access_token)
        set_refresh_cookies(response, refresh_token)

        return response, 200

    return jsonify(message="Invalid credentials"), 401

# Logout, clear session and cookies
@app.route('/api/logout', methods=['POST'])
@jwt_required()
def logout():
    current_user = get_jwt_identity()
    session = UserSession.query.filter_by(username=current_user).first() 

    if session:
        delete_session(session)
    
    response = jsonify({"message": "Logout successful"})
    response.delete_cookie('access_token_cookie')
    response.delete_cookie('refresh_token_cookie')
    return response, 200

# Register new user
@app.route('/api/register', methods=['POST'])
def register():
    data = request.json

    if not data or not isinstance(data, dict):
        return jsonify(message="Invalid request"), 400

    username = data.get('username', '').strip()
    password = data.get('password', '').strip()

    is_valid, message = check_login_input(username, password)
    if not is_valid:
        return jsonify(message=message), 400

    if User.query.filter_by(username=username).first():
        return jsonify(message="Username already exists"), 400

    new_user = User(username=username, password=password)

    db.session.add(new_user)
    db.session.commit()

    return jsonify(message="User registered successfully"), 201


# Verify MFA with TOTP code
@app.route('/api/login/verify', methods=['POST'])
def verify_mfa():
    data = request.json
    username = data.get("username", "").strip()
    totp_code = data.get("totp_code")

    if not data or not isinstance(data, dict):
        return jsonify(message="Invalid request"), 400

    is_valid, message = check_mfa_input(username, totp_code)
    if not is_valid:
        return jsonify(message=message), 400
    
    user = User.query.filter_by(username=username).first()

    if not user:
        return jsonify(message="User not found"), 404
    
    if not user.mfa_enabled or not user.mfa_secret:
        return jsonify(message="MFA setup required"), 400

    totp = pyotp.TOTP(user.mfa_secret)
    if not totp.verify(totp_code):
        return jsonify(message="Invalid MFA code"), 403
    
    access_token = create_access_token(identity=username, additional_claims={"mfa_enabled": True }, expires_delta=timedelta(minutes=15))
    refresh_token = create_refresh_token(identity=username, expires_delta=timedelta(days=7))
    
    response = jsonify(user=username, mfa_enabled=True)
    set_access_cookies(response, access_token)
    set_refresh_cookies(response, refresh_token)

    return response, 200

# Enable MFA with setup, generate QR code
@app.route('/api/mfa/setup', methods=['GET'])
@jwt_required()
def generate_mfa_qr():
    username = get_jwt_identity()
    user = User.query.filter_by(username=username).first()

    if not user:
        return jsonify(message="User not found"), 404

    if user.mfa_enabled:
        return jsonify(message="MFA already enabled"), 400

    totp = pyotp.TOTP(pyotp.random_base32())
    user.mfa_secret = totp.secret
    db.session.commit()

    issuer = "Secure Programming Application"
    qr_uri = totp.provisioning_uri(name=username, issuer_name=issuer)

    qr = qrcode.make(qr_uri)
    img_io = io.BytesIO()
    qr.save(img_io, 'PNG')
    img_io.seek(0)

    return send_file(img_io, mimetype='image/png'), 200

# Verify MFA setup with TOTP code
@app.route('/api/mfa/setup/verify', methods=['POST'])
@jwt_required()
def verify_mfa_setup():
    username = get_jwt_identity()
    user = User.query.filter_by(username=username).first()
    
    if not user:
        return jsonify(message="User not found"), 404
    
    if not user.mfa_secret:
        return jsonify(message="MFA setup required"), 400

    data = request.json
    totp_code = data.get("totp_code")

    if not totp_code:
        return jsonify(message="TOTP code is required"), 400

    totp = pyotp.TOTP(user.mfa_secret)
    
    if totp.verify(totp_code):
        user.mfa_enabled = True
        db.session.commit()
        
        response = jsonify(message="MFA successfully enabled")
        access_token = create_access_token(identity=username, additional_claims={ "mfa_enabled": True }, expires_delta=timedelta(minutes=15))
        set_access_cookies(response, access_token)

        return response, 200
    
    return jsonify(message="Invalid TOTP code"), 401

# Create a new session
def create_session(username, access_token, refresh_token=None):
    expires_at = datetime.now() + timedelta(days=7)
    session = UserSession(
        username=username,
        access_token=access_token,
        refresh_token=refresh_token,
        expires_at=expires_at
    )
    db.session.add(session)
    db.session.commit()
    return session

# Update an existing session
def update_session(session, access_token):
    session.access_token = access_token
    session.expires_at = datetime.now() + timedelta(days=7)
    db.session.commit()

# Delete session on logout
def delete_session(session):
    db.session.delete(session)
    db.session.commit()