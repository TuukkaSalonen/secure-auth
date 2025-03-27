from datetime import timedelta, datetime, timezone
from flask import make_response, request, jsonify, send_file, redirect
import io
from flask_jwt_extended import get_csrf_token, decode_token, get_jwt, create_access_token, create_refresh_token, jwt_required, get_jwt_identity, set_access_cookies, set_refresh_cookies
from . import db
from . import app 
from .models import User, UserSession
import pyotp
import qrcode
from .validators import check_login_input, check_mfa_input
from . import oauth

# Check if the JWT is valid
@app.route('/api/check', methods=['GET'])
@jwt_required()
def check_token():
    current_user = get_jwt_identity()
    claims = get_jwt()

    if not current_user:
        return jsonify(message="Invalid user"), 401
    
    if claims.get('temporary_token', False): # Temporary token for MFA
        return jsonify(message="MFA required"), 403
    
    mfa_enabled = claims.get('mfa_enabled', False)
    return jsonify(user=current_user, mfa_enabled=mfa_enabled), 200

# Refresh access token with refresh token
@app.route('/api/refresh', methods=['POST'])
@jwt_required(refresh=True)
def refresh():
    current_user = get_jwt_identity()
    claims = get_jwt()

    existing_session = UserSession.query.filter_by(username=current_user).first()
    if not existing_session:
        return jsonify(message="Session expired, please log in again."), 401
    
    request_refresh_token = get_jwt()["jti"]
    if existing_session.refresh_token_jti != request_refresh_token:
        return jsonify(message="Invalid refresh token"), 401
    
    if existing_session and existing_session.expires_at.replace(tzinfo=timezone.utc) < datetime.now(timezone.utc):
        delete_session(existing_session)
        return jsonify(message="Session expired, please log in again."), 401

    mfa_enabled = claims.get('mfa_enabled', False)

    access_token = create_access_token(identity=current_user, additional_claims={ 'mfa_enabled': mfa_enabled })
    update_session(existing_session, access_token)

    response = jsonify(user=current_user, mfa_enabled=mfa_enabled)
    set_access_cookies(response, access_token, 15*60)
    
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

    if user and user.sso_provider:
        return jsonify(message=("This user has connected a " + user.sso_provider + " account. Please login with " + user.sso_provider)), 404
    
    if user and user.check_password(password):
        if user.mfa_enabled:
            temp_token = create_access_token(identity=username, additional_claims={"temporary_token": True }, expires_delta=timedelta(minutes=5))
            response = jsonify(message="MFA required", mfa_required=True)
            set_access_cookies(response, temp_token, 5*60)
            return response, 403

        access_token = create_access_token(identity=username, additional_claims={ "mfa_enabled": user.mfa_enabled })
        refresh_token = create_refresh_token(identity=username)

        create_session(username, access_token, refresh_token)
        response = jsonify(user=username, mfa_enabled=user.mfa_enabled)

        set_access_cookies(response, access_token, 15*60)
        set_refresh_cookies(response, refresh_token, 7*24*60*60)

        return response, 200

    return jsonify(message="Invalid credentials"), 401

# Login with Google OAuth
@app.route('/api/login/google', methods=['GET'])
def login_google():
    return oauth.google.authorize_redirect(app.config['GOOGLE_REDIRECT_URI'])

# Callback for Google OAuth
@app.route('/api/login/google/callback', methods=['GET'])
def google_callback():
    token = oauth.google.authorize_access_token()
    if not token:
        return jsonify(message="Invalid token"), 400
    
    user_info = oauth.google.get("https://www.googleapis.com/oauth2/v2/userinfo").json()
    username = user_info.get('email')
    if not username:
        return jsonify(message="Invalid email"), 400
    
    user = User.query.filter_by(username=username).first()
    if not user: # Create new user if not found
        user = User(username=username, sso_provider="Google")
        db.session.add(user)
        db.session.commit()

    if user.mfa_enabled:
        temp_token = create_access_token(identity=username, additional_claims={"temporary_token": True }, expires_delta=timedelta(minutes=5))
        csrf_temp_token = get_csrf_token(temp_token)
        # Need to add cookies manually for redirect response
        redirect_response = make_response(redirect(f"{app.config['FRONTEND_URL']}/login?mfa_required=true"))
        redirect_response.set_cookie('access_token_cookie', temp_token, max_age=5*60, secure=True, httponly=True, samesite='Strict')
        redirect_response.set_cookie('csrf_access_token', csrf_temp_token, max_age=5*60, secure=True, httponly=False, samesite='Strict')
        
        return redirect_response, 302

    access_token = create_access_token(identity=username, additional_claims={ "mfa_enabled": user.mfa_enabled })
    refresh_token = create_refresh_token(identity=username)
    csrf_access_token = get_csrf_token(access_token)
    csrf_refresh_token = get_csrf_token(refresh_token)

    create_session(username, access_token, refresh_token)

    # Need to add cookies manually for redirect response
    redirect_response = make_response(redirect(app.config['FRONTEND_URL']))
    redirect_response.set_cookie('access_token_cookie', access_token, max_age=15*60, secure=True, httponly=True, samesite='Strict')
    redirect_response.set_cookie('refresh_token_cookie', refresh_token, max_age=7*24*60*60, secure=True, httponly=True, samesite='Strict')
    redirect_response.set_cookie('csrf_access_token', csrf_access_token, max_age=15*60, secure=True, httponly=False, samesite='Strict')
    redirect_response.set_cookie('csrf_refresh_token', csrf_refresh_token, max_age=7*24*60*60, secure=True, httponly=False, samesite='Strict')

    return redirect_response, 302

# Login with GitHub OAuth
@app.route('/api/login/github', methods=['GET'])
def login_github():
    return oauth.github.authorize_redirect(redirect_uri=app.config['GITHUB_REDIRECT_URI'], prompt="select_account")

# Callback for GitHub OAuth
@app.route('/api/login/github/callback', methods=['GET'])
def github_callback():
    token = oauth.github.authorize_access_token()
    if not token:
        return jsonify(message="Invalid token"), 400
    
    user_info = oauth.github.get("user").json()
    username = user_info.get('login')
    if not username:
        return jsonify(message="Invalid username"), 400
    
    user = User.query.filter_by(username=username).first()
    if not user: # Create new user if not found
        user = User(username=username, sso_provider="GitHub")
        db.session.add(user)
        db.session.commit()

    if user.mfa_enabled:
        temp_token = create_access_token(identity=username, additional_claims={"temporary_token": True }, expires_delta=timedelta(minutes=5))
        csrf_temp_token = get_csrf_token(temp_token)
        # Need to add cookies manually for redirect response
        redirect_response = make_response(redirect(f"{app.config['FRONTEND_URL']}/login?mfa_required=true"))
        redirect_response.set_cookie('access_token_cookie', temp_token, max_age=5*60, secure=True, httponly=True, samesite='Strict')
        redirect_response.set_cookie('csrf_access_token', csrf_temp_token, max_age=5*60, secure=True, httponly=False, samesite='Strict')
        
        return redirect_response, 302

    access_token = create_access_token(identity=username, additional_claims={ "mfa_enabled": user.mfa_enabled })
    refresh_token = create_refresh_token(identity=username)
    csrf_access_token = get_csrf_token(access_token)
    csrf_refresh_token = get_csrf_token(refresh_token)

    create_session(username, access_token, refresh_token)

    # Need to add cookies manually for redirect response
    redirect_response = make_response(redirect(app.config['FRONTEND_URL']))
    redirect_response.set_cookie('access_token_cookie', access_token, max_age=15*60, secure=True, httponly=True, samesite='Strict')
    redirect_response.set_cookie('refresh_token_cookie', refresh_token, max_age=7*24*60*60, secure=True, httponly=True, samesite='Strict')
    redirect_response.set_cookie('csrf_access_token', csrf_access_token, max_age=15*60, secure=True, httponly=False, samesite='Strict')
    redirect_response.set_cookie('csrf_refresh_token', csrf_refresh_token, max_age=7*24*60*60, secure=True, httponly=False, samesite='Strict')

    return redirect_response, 302

# Logout, clear session and cookies
@app.route('/api/logout', methods=['POST'])
@jwt_required()
def logout():
    current_user = get_jwt_identity()
    session = UserSession.query.filter_by(username=current_user).order_by(UserSession.expires_at.desc()).first() # There should be only one session per user but just in case
    if session:
        delete_session(session)

    response = jsonify({"message": "Logout successful"})
    response.delete_cookie('access_token_cookie')
    response.delete_cookie('refresh_token_cookie')
    response.delete_cookie('csrf_access_token')
    response.delete_cookie('csrf_refresh_token')
    response.delete_cookie('session')

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
        return jsonify(message="Account with username/email already exists"), 400

    new_user = User(username=username, password=password)
    db.session.add(new_user)
    db.session.commit()

    return jsonify(message="User registered successfully"), 201

# Verify MFA with TOTP code
@app.route('/api/login/verify', methods=['POST'])
@jwt_required()
def verify_mfa():
    current_user = get_jwt_identity()
    temp_token = get_jwt().get('temporary_token', False)
    if not temp_token:
        return jsonify(message="MFA required"), 403

    data = request.json
    if not data or not isinstance(data, dict):
        return jsonify(message="Invalid request"), 400
    
    totp_code = data.get("totp_code")
    is_valid, message = check_mfa_input(totp_code)
    if not is_valid:
        return jsonify(message=message), 400
    
    if not current_user:
        return jsonify(message="Invalid user"), 401

    user = User.query.filter_by(username=current_user).first()
    if not user:
        return jsonify(message="User not found"), 404
    
    if not user.mfa_enabled or not user.mfa_secret_hash:
        return jsonify(message="MFA not enabled"), 400
    
    decrypted_secret = user.get_mfa_secret()
    totp = pyotp.TOTP(decrypted_secret)
    
    if not totp.verify(totp_code):
        return jsonify(message="Invalid MFA code"), 403
    
    access_token = create_access_token(identity=current_user, additional_claims={"mfa_enabled": True })
    refresh_token = create_refresh_token(identity=current_user)
    
    response = jsonify(user=current_user, mfa_enabled=True)
    set_access_cookies(response, access_token, 15*60)
    set_refresh_cookies(response, refresh_token, 7*24*60*60)

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
    user.set_mfa_secret(totp.secret)
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
    
    if not user.mfa_secret_hash:
        return jsonify(message="MFA setup required"), 400

    data = request.json
    totp_code = data.get("totp_code")
    if not totp_code:
        return jsonify(message="TOTP code is required"), 400

    decrypted_secret = user.get_mfa_secret()
    totp = pyotp.TOTP(decrypted_secret)

    if totp.verify(totp_code):
        user.mfa_enabled = True
        db.session.commit()
        
        response = jsonify(message="MFA successfully enabled")
        access_token = create_access_token(identity=username, additional_claims={ "mfa_enabled": True })
        set_access_cookies(response, access_token, 15*60)

        return response, 200
    
    return jsonify(message="Invalid TOTP code"), 401

# Remove MFA from this user
@app.route('/api/mfa/disable', methods=['POST'])
@jwt_required()
def remove_mfa():
    username = get_jwt_identity()
    user = User.query.filter_by(username=username).first()
    if not user:
        return jsonify(message="User not found"), 404
    
    if not user.mfa_enabled or not user.mfa_secret_hash:
        return jsonify(message="MFA setup required to remove it"), 400

    data = request.json
    totp_code = data.get("totp_code")
    if not totp_code:
        return jsonify(message="TOTP code is required"), 400

    decrypted_secret = user.get_mfa_secret()
    totp = pyotp.TOTP(decrypted_secret)

    if totp.verify(totp_code):
        user.mfa_enabled = False
        user.mfa_secret_hash = None
        db.session.commit()
        
        response = jsonify(message="MFA successfully disabled")
        access_token = create_access_token(identity=username, additional_claims={ "mfa_enabled": False })
        set_access_cookies(response, access_token, 15*60)

        return response, 200
    
    return jsonify(message="Invalid TOTP code"), 401

# Get the JTI from a refresh token
def get_jti_from_token(token):
    decoded_token = decode_token(token)
    return decoded_token['jti']

# Create a new session
def create_session(username, access_token, refresh_token=None):
    expires_at = datetime.now(timezone.utc) + timedelta(days=7)
    refresh_token_jti = get_jti_from_token(refresh_token)
    session = UserSession(
        username=username,
        access_token=access_token,
        refresh_token_jti=refresh_token_jti,
        expires_at=expires_at
    )
    db.session.add(session)
    db.session.commit()
    return session

# Update an existing session
def update_session(session, access_token):
    session.access_token = access_token
    db.session.commit()

# Delete session on logout
def delete_session(session):
    db.session.delete(session)
    db.session.commit()