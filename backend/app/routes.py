from datetime import timedelta, datetime, timezone
import zipfile
from flask import make_response, jsonify, send_file, redirect, request
import io
from flask_jwt_extended import get_csrf_token, decode_token, get_jwt, create_access_token, create_refresh_token, jwt_required, get_jwt_identity, set_access_cookies, set_refresh_cookies
import traceback
from flask_limiter import RateLimitExceeded
from . import db
from . import app 
from .models import User, UserSession, UploadedFile
import pyotp
import qrcode
from .utils.validators import check_login_input, check_mfa_input, check_file_id, validate_file_type
from . import oauth
from . import limiter
from .utils.fileUtils import encrypt_file, decrypt_file
from .utils.logUtils import log_security_event

# Check if the JWT is valid
@app.route('/api/check', methods=['GET'])
@limiter.limit("30 per minute")
@jwt_required()
def check_token():
    current_user = get_jwt_identity()
    claims = get_jwt()

    if not current_user:
        log_security_event("CHECK_TOKEN", "INVALID_USER", current_user, "Invalid user in token")
        return jsonify(message="Invalid user"), 401

    if claims.get('temporary_token', False):  # Temporary token for MFA
        log_security_event("CHECK_TOKEN", "TEMPORARY_TOKEN", current_user, "User data not returned, MFA required")
        return jsonify(message="MFA required"), 403

    user = User.query.filter_by(id=current_user).first()
    if not user:
        log_security_event("CHECK_TOKEN", "USER_NOT_FOUND", current_user, "User not found in database")
        return jsonify(message="User not found"), 404

    log_security_event("CHECK_TOKEN", "VALID_TOKEN", current_user, "Valid token check", extra_data={'mfa_enabled': user.mfa_enabled})
    return jsonify(user=user.username, mfa_enabled=user.mfa_enabled), 200

# Refresh access token with refresh token
@app.route('/api/refresh', methods=['POST'])
@limiter.limit("30 per minute")
@jwt_required(refresh=True)
def refresh():
    current_user = get_jwt_identity()
    claims = get_jwt()

    # Check for missing user or claims in the token
    if not current_user or not claims:
        log_security_event("REFRESH_TOKEN", "MISSING_USER_OR_CLAIMS", current_user, "Invalid user or claims in token")
        return jsonify(message="Invalid user"), 401

    user = User.query.filter_by(id=current_user).first()
    if not user:
        log_security_event("REFRESH_TOKEN", "USER_NOT_FOUND", current_user, "User not found in database")
        return jsonify(message="User not found"), 404

    # Session validity check
    existing_session = UserSession.query.filter_by(user_id=current_user).first()
    if not existing_session:
        log_security_event("REFRESH_TOKEN", "NO_SESSION_FOUND", current_user, "No session found for user")
        return jsonify(message="Session expired, please log in again."), 401

    request_refresh_token = claims.get("jti")
    if existing_session.refresh_token_jti != request_refresh_token:
        log_security_event("REFRESH_TOKEN", "INVALID_REFRESH_TOKEN", current_user, "Refresh token mismatch")
        return jsonify(message="Invalid refresh token"), 401

    if existing_session.expires_at.replace(tzinfo=timezone.utc) < datetime.now(timezone.utc):
        log_security_event("REFRESH_TOKEN", "SESSION_EXPIRED", current_user, "Session expired")
        delete_session(existing_session)
        return jsonify(message="Session expired, please log in again."), 401

    mfa_enabled = claims.get('mfa_enabled', False)
    access_token = create_access_token(identity=current_user, additional_claims={ 'mfa_enabled': mfa_enabled })
    update_session(existing_session, access_token)

    response = jsonify(user=user.username, mfa_enabled=mfa_enabled)
    set_access_cookies(response, access_token, 15*60)
    
    log_security_event("REFRESH_TOKEN", "VALID_REFRESH_TOKEN", current_user, "Valid refresh token", extra_data={'mfa_enabled': mfa_enabled})
    return response, 200

# Login with username and password
@app.route('/api/login', methods=['POST'])
@limiter.limit("10 per minute")
def login():
    data = request.json
    if not data or not isinstance(data, dict):
        log_security_event("LOGIN", "INVALID_REQUEST", None, "Invalid request format")
        return jsonify(message="Invalid request"), 400

    username = data.get('username', '').strip()
    password = data.get('password', '').strip()

    is_valid, message = check_login_input(username, password)
    if not is_valid:
        log_security_event("LOGIN", "INVALID_LOGIN_INPUT", username, message)
        return jsonify(message=message), 400

    user = User.query.filter_by(username=username).first()

    if user and user.password_hash and user.check_password(password):
        if user.mfa_enabled:
            # Create a temporary MFA token
            temp_token = create_access_token(identity=user.id, additional_claims={"temporary_token": True }, expires_delta=timedelta(minutes=5))
            
            log_security_event("LOGIN", "MFA_REQUIRED", user.id, "MFA token required", extra_data={"temporary_token": temp_token})

            response = jsonify(message="MFA required", mfa_required=True)
            set_access_cookies(response, temp_token, 5*60)
            return response, 403

        access_token = create_access_token(identity=user.id, additional_claims={ "mfa_enabled": user.mfa_enabled })
        refresh_token = create_refresh_token(identity=user.id)

        create_session(user.id, access_token, refresh_token)

        log_security_event("LOGIN", "SUCCESSFUL_LOGIN", user.id, "User successfully logged in", extra_data={'mfa_enabled': user.mfa_enabled})

        response = jsonify(user=username, mfa_enabled=user.mfa_enabled)
        set_access_cookies(response, access_token, 15*60)
        set_refresh_cookies(response, refresh_token, 7*24*60*60)

        return response, 200

    log_security_event("LOGIN", "FAILED_LOGIN", username, "Invalid credentials", extra_data={"reason": "Incorrect username or password"})
    return jsonify(message="Invalid credentials. If you signed up with Google/GitHub, try logging in with them."), 401


# Login with Google OAuth
@app.route('/api/login/google', methods=['GET'])
@limiter.limit("10 per minute")
def login_google():
    return oauth.google.authorize_redirect(app.config['GOOGLE_REDIRECT_URI'], prompt="select_account")

# Callback for Google OAuth
@app.route('/api/login/google/callback', methods=['GET'])
@limiter.limit("10 per minute")
def google_callback():
    error = request.args.get('error')
    if error:
        log_security_event("GOOGLE_CALLBACK", "OAUTH_ERROR", None, "OAuth error", extra_data={"error": error})
        redirect_response = make_response(redirect(app.config['FRONTEND_URL']))
        return redirect_response, 302
    
    token = oauth.google.authorize_access_token()
    if not token:
        log_security_event("GOOGLE_CALLBACK", "INVALID_TOKEN", None, "Invalid token", extra_data={"token": token})
        return jsonify(message="Invalid token"), 400
    
    user_info = oauth.google.get("https://www.googleapis.com/oauth2/v2/userinfo").json()
    username = user_info.get('email')
    if not username:
        log_security_event("GOOGLE_CALLBACK", "INVALID_EMAIL", None, "Invalid email", extra_data={"user_info": user_info})
        return jsonify(message="Invalid email"), 400
    
    user = User.query.filter_by(username=username).first()
    if not user: # Create new user if not found
        user = User(username=username, sso_provider="Google")
        db.session.add(user)
        db.session.commit()

    if user.mfa_enabled:
        temp_token = create_access_token(identity=user.id, additional_claims={"temporary_token": True }, expires_delta=timedelta(minutes=5))
        # Need to add cookies manually for redirect response
        redirect_response = make_response(redirect(f"{app.config['FRONTEND_URL']}/login?mfa_required=true"))
        set_temp_redirect_cookies(redirect_response, temp_token)

        log_security_event("GOOGLE_CALLBACK", "MFA_REQUIRED", user.id, "MFA required", extra_data={"temporary_token": temp_token})
        return redirect_response, 302

    access_token = create_access_token(identity=user.id, additional_claims={ "mfa_enabled": user.mfa_enabled })
    refresh_token = create_refresh_token(identity=user.id)

    create_session(user.id, access_token, refresh_token)

    # Need to add cookies manually for redirect response
    redirect_response = make_response(redirect(app.config['FRONTEND_URL']))
    set_redirect_cookies(redirect_response, access_token, refresh_token)

    log_security_event("GOOGLE_CALLBACK", "SUCCESSFUL_LOGIN", user.id, "User successfully logged in", extra_data={'mfa_enabled': user.mfa_enabled})
    return redirect_response, 302

# Login with GitHub OAuth
@app.route('/api/login/github', methods=['GET'])
@limiter.limit("10 per minute")
def login_github():
    return oauth.github.authorize_redirect(redirect_uri=app.config['GITHUB_REDIRECT_URI'], prompt="select_account")

# Callback for GitHub OAuth
@app.route('/api/login/github/callback', methods=['GET'])
@limiter.limit("10 per minute")
def github_callback():
    token = oauth.github.authorize_access_token()
    if not token:
        log_security_event("GITHUB_CALLBACK", "INVALID_TOKEN", None, "Invalid token", extra_data={"token": token})
        return jsonify(message="Invalid token"), 400
    
    user_info = oauth.github.get("user").json()
    username = user_info.get('login')
    if not username:
        log_security_event("GITHUB_CALLBACK", "INVALID_USERNAME", None, "Invalid username", extra_data={"user_info": user_info})
        return jsonify(message="Invalid username"), 400
    
    user = User.query.filter_by(username=username).first()
    if not user: # Create new user if not found
        user = User(username=username, sso_provider="GitHub")
        db.session.add(user)
        db.session.commit()

    if user.mfa_enabled:
        temp_token = create_access_token(identity=user.id, additional_claims={"temporary_token": True }, expires_delta=timedelta(minutes=5))
        # Need to add cookies manually for redirect response
        redirect_response = make_response(redirect(f"{app.config['FRONTEND_URL']}/login?mfa_required=true"))
        set_temp_redirect_cookies(redirect_response, temp_token)

        log_security_event("GITHUB_CALLBACK", "MFA_REQUIRED", user.id, "MFA required", extra_data={"temporary_token": temp_token})

        return redirect_response, 302

    access_token = create_access_token(identity=user.id, additional_claims={ "mfa_enabled": user.mfa_enabled })
    refresh_token = create_refresh_token(identity=user.id)

    create_session(user.id, access_token, refresh_token)

    # Need to add cookies manually for redirect response
    redirect_response = make_response(redirect(app.config['FRONTEND_URL']))
    set_redirect_cookies(redirect_response, access_token, refresh_token)

    log_security_event("GITHUB_CALLBACK", "SUCCESSFUL_LOGIN", user.id, "User successfully logged in", extra_data={'mfa_enabled': user.mfa_enabled})
    return redirect_response, 302

# Logout, clear session and cookies. Allows for optional JWT to delete cookies if they are not correct
@app.route('/api/logout', methods=['POST'])
@limiter.limit("10 per minute")
@jwt_required(optional=True)
def logout():
    current_user = get_jwt_identity()
    if current_user:
        # Delete all sessions for the user
        delete_existing_sessions(current_user)

    response = jsonify({"message": "Logout successful"})
    response.delete_cookie('access_token_cookie')
    response.delete_cookie('refresh_token_cookie')
    response.delete_cookie('csrf_access_token')
    response.delete_cookie('csrf_refresh_token')
    response.delete_cookie('session')

    log_security_event("LOGOUT", "USER_LOGOUT", current_user, "User logged out")
    return response, 200

# Register new user
@app.route('/api/register', methods=['POST'])
@limiter.limit("10 per minute")
def register():
    data = request.json
    if not data or not isinstance(data, dict):
        log_security_event("REGISTER", "INVALID_REQUEST", None, "Invalid request format")
        return jsonify(message="Invalid request"), 400

    username = data.get('username', '').strip()
    password = data.get('password', '').strip()

    is_valid, message = check_login_input(username, password)
    if not is_valid:
        log_security_event("REGISTER", "INVALID_REGISTER_INPUT", username, message)
        return jsonify(message=message), 400

    if User.query.filter_by(username=username).first():
        log_security_event("REGISTER", "USERNAME_TAKEN", username, "Username already in use")
        return jsonify(message="Username/email already in use"), 400

    new_user = User(username=username, password=password)
    db.session.add(new_user)
    db.session.commit()

    log_security_event("REGISTER", "SUCCESSFUL_REGISTRATION", new_user.id, "User registered successfully")
    return jsonify(message="User registered successfully"), 201

# Verify MFA with TOTP code
@app.route('/api/login/verify', methods=['POST'])
@limiter.limit("10 per minute")
@jwt_required()
def verify_mfa():
    current_user = get_jwt_identity()
    temp_token = get_jwt().get('temporary_token', False)
    if not temp_token:
        log_security_event("VERIFY_MFA", "NO_TEMP_TOKEN", current_user, "No temporary token found")
        return jsonify(message="MFA required"), 403

    data = request.json
    if not data or not isinstance(data, dict):
        log_security_event("VERIFY_MFA", "INVALID_REQUEST", current_user, "Invalid request format")
        return jsonify(message="Invalid request"), 400
    
    totp_code = data.get("totp_code")
    is_valid, message = check_mfa_input(totp_code)
    if not is_valid:
        log_security_event("VERIFY_MFA", "INVALID_TOTP_CODE", current_user, message)
        return jsonify(message=message), 400
    
    if not current_user:
        log_security_event("VERIFY_MFA", "INVALID_USER", current_user, "Invalid user in token")
        return jsonify(message="Invalid user"), 403

    user = User.query.filter_by(id=current_user).first()
    if not user:
        log_security_event("VERIFY_MFA", "USER_NOT_FOUND", current_user, "User not found in database")
        return jsonify(message="User not found"), 404
    
    if not user.mfa_enabled or not user.mfa_secret_hash:
        log_security_event("VERIFY_MFA", "MFA_NOT_ENABLED", current_user, "MFA not enabled for user")
        return jsonify(message="MFA not enabled"), 400
    
    decrypted_secret = user.get_mfa_secret()
    totp = pyotp.TOTP(decrypted_secret)
    
    if not totp.verify(totp_code):
        log_security_event("VERIFY_MFA", "INVALID_TOTP_CODE", current_user, "Invalid TOTP code")
        return jsonify(message="Invalid MFA code"), 403
    
    access_token = create_access_token(identity=current_user, additional_claims={"mfa_enabled": True })
    refresh_token = create_refresh_token(identity=current_user)
    
    response = jsonify(user=user.username, mfa_enabled=True)
    set_access_cookies(response, access_token, 15*60)
    set_refresh_cookies(response, refresh_token, 7*24*60*60)

    log_security_event("VERIFY_MFA", "SUCCESSFUL_VERIFICATION", current_user, "MFA verification successful")
    return response, 200

# Enable MFA with setup, generate QR code
@app.route('/api/mfa/setup', methods=['GET'])
@limiter.limit("5 per minute")
@jwt_required()
def generate_mfa_qr():
    user_id = get_jwt_identity()
    user = User.query.filter_by(id=user_id).first()
    if not user:
        log_security_event("MFA_SETUP", "USER_NOT_FOUND", user_id, "User not found in database")
        return jsonify(message="User not found"), 404

    if user.mfa_enabled:
        log_security_event("MFA_SETUP", "MFA_ALREADY_ENABLED", user_id, "MFA already enabled for user")
        return jsonify(message="MFA already enabled"), 400

    totp = pyotp.TOTP(pyotp.random_base32())
    user.set_mfa_secret(totp.secret)
    db.session.commit()

    issuer = "Secure Programming Application"
    qr_uri = totp.provisioning_uri(name=user.username, issuer_name=issuer)

    qr = qrcode.make(qr_uri)
    img_io = io.BytesIO()
    qr.save(img_io, 'PNG')
    img_io.seek(0)

    log_security_event("MFA_SETUP", "QR_CODE_GENERATED", user_id, "QR code generated for MFA setup")
    return send_file(img_io, mimetype='image/png'), 200

# Verify MFA setup with TOTP code
@app.route('/api/mfa/setup/verify', methods=['POST'])
@limiter.limit("5 per minute")
@jwt_required()
def verify_mfa_setup():
    current_user = get_jwt_identity()
    user = User.query.filter_by(id=current_user).first()
    if not user:
        log_security_event("MFA_SETUP_VERIFY", "USER_NOT_FOUND", current_user, "User not found in database")
        return jsonify(message="User not found"), 404
    
    if not user.mfa_secret_hash:
        log_security_event("MFA_SETUP_VERIFY", "MFA_NOT_ENABLED", current_user, "MFA not enabled for user")
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
        access_token = create_access_token(identity=current_user, additional_claims={ "mfa_enabled": True })
        set_access_cookies(response, access_token, 15*60)
        log_security_event("MFA_SETUP_VERIFY", "SUCCESSFUL_VERIFICATION", current_user, "MFA setup verification successful")
        return response, 200
    
    log_security_event("MFA_SETUP_VERIFY", "INVALID_TOTP_CODE", current_user, "Invalid TOTP code")
    return jsonify(message="Invalid MFA code"), 401

# Remove MFA from this user
@app.route('/api/mfa/disable', methods=['POST'])
@limiter.limit("5 per minute")
@jwt_required()
def remove_mfa():
    current_user = get_jwt_identity()
    user = User.query.filter_by(id=current_user).first()
    if not user:
        log_security_event("MFA_DISABLE", "USER_NOT_FOUND", current_user, "User not found in database")
        return jsonify(message="User not found"), 404
    
    if not user.mfa_enabled or not user.mfa_secret_hash:
        log_security_event("MFA_DISABLE", "MFA_NOT_ENABLED", current_user, "MFA not enabled for user")
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
        access_token = create_access_token(identity=current_user, additional_claims={ "mfa_enabled": False })
        set_access_cookies(response, access_token, 15*60)
        
        log_security_event("MFA_DISABLE", "SUCCESSFUL_VERIFICATION", current_user, "MFA removal verification successful")
        return response, 200
    
    log_security_event("MFA_DISABLE", "INVALID_TOTP_CODE", current_user, "Invalid TOTP code")
    return jsonify(message="Invalid TOTP code"), 401

# Upload a file
@app.route('/api/file/upload', methods=['POST'])
@limiter.limit("30 per minute")
@jwt_required()
def upload_file():
    current_user_id = get_jwt_identity()
    if not current_user_id:
        log_security_event("FILE_UPLOAD", "INVALID_USER", current_user_id, "Invalid user in token")
        return jsonify(message="Invalid user"), 401

    # Fetch the user from the database
    user = User.query.filter_by(id=current_user_id).first()
    if not user:
        log_security_event("FILE_UPLOAD", "USER_NOT_FOUND", current_user_id, "User not found in database")
        return jsonify(message="User not found"), 404

    file = request.files.get('file')
    if not file:
        return jsonify(message="No file provided"), 400

    if not validate_file_type(file):
        log_security_event("FILE_UPLOAD", "INVALID_FILE_TYPE", current_user_id, "Invalid file type")
        return jsonify(message="Invalid file type"), 400
    
    file_bytes = file.read()
    if not file_bytes:
        return jsonify(message="Empty file"), 400

    file_size = len(file_bytes)
    if file_size > 100 * 1024 * 1024:  # Limit file size to 100 MB
        log_security_event("FILE_UPLOAD", "FILE_SIZE_EXCEEDED", current_user_id, "File size exceeds limit")
        return jsonify(message="File size exceeds limit"), 400
    
    # Encrypt the file using the user's key
    encrypted_data, encrypted_key, iv_file, iv_key = encrypt_file(file_bytes, user)

    # Save the encrypted data and metadata to the database
    uploaded_file = UploadedFile(
        user_id=current_user_id,
        filename=file.filename,
        mimetype=file.mimetype,
        file_size=file_size,
        encrypted_data=encrypted_data,
        encrypted_key=encrypted_key,
        iv_file=iv_file,
        iv_key=iv_key,
        uploaded_at=datetime.now(timezone.utc)
    )
    
    db.session.add(uploaded_file)
    db.session.commit()

    log_security_event("FILE_UPLOAD", "SUCCESSFUL_UPLOAD", current_user_id, "File uploaded successfully", extra_data={'filename': file.filename})
    return jsonify(message="File uploaded successfully"), 201

# Download a file
@app.route('/api/file/download/<file_id>', methods=['GET'])
@limiter.limit("30 per minute")
@jwt_required()
def download_file(file_id):
    current_user = get_jwt_identity()
    if not current_user:
        log_security_event("FILE_DOWNLOAD", "INVALID_USER", current_user, "Invalid user in token")
        return jsonify(message="Invalid user"), 401
    
    id_check = check_file_id(file_id)
    if not id_check:
        log_security_event("FILE_DOWNLOAD", "INVALID_FILE_ID", current_user, "Invalid file ID")
        return jsonify(message="Invalid file ID"), 400
    
    # Fetch the user from the database to get their encryption key
    user = User.query.filter_by(id=current_user).first()
    if not user:
        log_security_event("FILE_DOWNLOAD", "USER_NOT_FOUND", current_user, "User not found in database")
        return jsonify(message="User not found"), 404

    uploaded_file = UploadedFile.query.filter_by(id=file_id, user_id=current_user).first()
    if not uploaded_file:
        log_security_event("FILE_DOWNLOAD", "FILE_NOT_FOUND", current_user, "File not found in database")
        return jsonify(message="File not found"), 404

    # Decrypt the file data using the user's encryption key and the file's key and iv
    decrypted_data = decrypt_file(uploaded_file.encrypted_data, uploaded_file.encrypted_key, uploaded_file.iv_file, uploaded_file.iv_key, user)
    
    response = make_response()
    response.headers['Content-Disposition'] = f'attachment; filename={uploaded_file.filename}'
    response.headers['Content-Type'] = uploaded_file.mimetype
    response.data = decrypted_data

    log_security_event("FILE_DOWNLOAD", "SUCCESSFUL_DOWNLOAD", current_user, "File downloaded successfully", extra_data={'filename': uploaded_file.filename})
    return response, 200

# Download all files
@app.route('/api/file/download/all', methods=['GET'])
@limiter.limit("30 per minute")
@jwt_required()
def download_files():
    current_user = get_jwt_identity()
    if not current_user:
        log_security_event("FILE_DOWNLOAD_ALL", "INVALID_USER", current_user, "Invalid user in token")
        return jsonify(message="Invalid user"), 401
    
    # Fetch the user from the database to get their encryption key
    user = User.query.filter_by(id=current_user).first()
    if not user:
        log_security_event("FILE_DOWNLOAD_ALL", "USER_NOT_FOUND", current_user, "User not found in database")
        return jsonify(message="User not found"), 404

    uploaded_files = UploadedFile.query.filter_by(user_id=current_user).all()
    if not uploaded_files:
        log_security_event("FILE_DOWNLOAD_ALL", "FILES_NOT_FOUND", current_user, "Files not found in database")
        return jsonify(message="File not found"), 404
    
    # Create a zip file for all files 
    zip_buffer = io.BytesIO()
    with zipfile.ZipFile(zip_buffer, 'w', zipfile.ZIP_DEFLATED) as zip_file:
        for uploaded_file in uploaded_files:
            # Decrypt the file data using the user's encryption key and the file's key and iv
            decrypted_data = decrypt_file(uploaded_file.encrypted_data, uploaded_file.encrypted_key, uploaded_file.iv_file, uploaded_file.iv_key, user)
            zip_file.writestr(uploaded_file.filename, decrypted_data)

    zip_buffer.seek(0)    
    response = make_response(zip_buffer.read())
    response.headers['Content-Disposition'] = f'attachment; filename={user.username}_files.zip'
    response.headers['Content-Type'] = 'application/zip'

    log_security_event("FILE_DOWNLOAD_ALL", "SUCCESSFUL_DOWNLOAD", current_user, "File downloaded successfully", extra_data={'filename': uploaded_file.filename})
    return response, 200

# List all files uploaded by the user
@app.route('/api/file/list', methods=['GET'])
@limiter.limit("30 per minute")
@jwt_required()
def list_files():
    current_user_id = get_jwt_identity()
    if not current_user_id:
        log_security_event("FILE_LIST", "INVALID_USER", current_user_id, "Invalid user in token")
        return jsonify(message="Invalid user"), 401

    uploaded_files = UploadedFile.query.filter_by(user_id=current_user_id).order_by(UploadedFile.uploaded_at.desc()).all()
    files_list = [
        {
            'id': str(file.id),
            'filename': file.filename,
            'file_size': file.file_size,
            'uploaded_at': file.uploaded_at.isoformat()
        } for file in uploaded_files
    ]

    log_security_event("FILE_LIST", "SUCCESSFUL_LIST", current_user_id, "Files listed successfully")
    return jsonify(files=files_list), 200 

# Delete a file
@app.route('/api/file/delete/<file_id>', methods=['DELETE'])
@limiter.limit("30 per minute")
@jwt_required()
def delete_file(file_id):
    current_user = get_jwt_identity()
    if not current_user:
        log_security_event("FILE_DELETE", "INVALID_USER", current_user, "Invalid user in token")
        return jsonify(message="Invalid user"), 401
    
    id_check = check_file_id(file_id)
    if not id_check:
        log_security_event("FILE_DELETE", "INVALID_FILE_ID", current_user, "Invalid file ID")
        return jsonify(message="Invalid file ID"), 400
    
    uploaded_file = UploadedFile.query.filter_by(id=file_id, user_id=current_user).first()
    if not uploaded_file:
        log_security_event("FILE_DELETE", "FILE_NOT_FOUND", current_user, "File not found in database", extra_data={'file_id': file_id})
        return jsonify(message="File not found"), 404

    db.session.delete(uploaded_file)
    db.session.commit()

    log_security_event("FILE_DELETE", "SUCCESSFUL_DELETE", current_user, "File deleted successfully", extra_data={'file_id': file_id})
    return jsonify(message="File deleted successfully"), 200

# Delete all files uploaded by the user
@app.route('/api/file/delete/all', methods=['DELETE'])
@limiter.limit("30 per minute")
@jwt_required()
def delete_all_files():
    current_user = get_jwt_identity()
    if not current_user:
        log_security_event("FILE_DELETE_ALL", "INVALID_USER", current_user, "Invalid user in token")
        return jsonify(message="Invalid user"), 401

    uploaded_files = UploadedFile.query.filter_by(user_id=current_user).all()
    for file in uploaded_files:
        db.session.delete(file)
    
    db.session.commit()

    log_security_event("FILE_DELETE_ALL", "SUCCESSFUL_DELETE_ALL", current_user, "All files deleted successfully")
    return jsonify(message="All files deleted successfully"), 200

# Delete user account
@app.route('/api/user/delete', methods=['DELETE'])
@limiter.limit("5 per minute")
@jwt_required()
def delete_user():
    current_user = get_jwt_identity()
    if not current_user:
        log_security_event("USER_DELETE", "INVALID_USER", current_user, "Invalid user in token")
        return jsonify(message="Invalid user"), 401
    
    user = User.query.filter_by(id=current_user).first()
    if not user:
        log_security_event("USER_DELETE", "USER_NOT_FOUND", current_user, "User not found in database")
        return jsonify(message="User not found"), 404
    
    # Delete all data associated with the user including files and sessions
    db.session.delete(user)
    db.session.commit()

    log_security_event("USER_DELETE", "SUCCESSFUL_DELETE", current_user, "User deleted successfully")
    return jsonify(message="User deleted successfully"), 200

# Get the JTI from a refresh token
def get_jti_from_token(token):
    decoded_token = decode_token(token)
    return decoded_token['jti']

# Create a new session
def create_session(user_id, access_token, refresh_token=None):
    delete_existing_sessions(user_id) # Delete previous sessions

    expires_at = datetime.now(timezone.utc) + timedelta(days=7)
    refresh_token_jti = get_jti_from_token(refresh_token)
    session = UserSession(
        user_id=user_id,
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

# # Delete session on logout
def delete_session(session):
    db.session.delete(session)
    db.session.commit()

# Delete previous sessions. Shouldnt happen, but if it does, delete them
def delete_existing_sessions(user_id):
    sessions = UserSession.query.filter_by(user_id=user_id).all()
    for session in sessions:
        db.session.delete(session)
    db.session.commit()

# Create csrf token and set cookies for temporary access token (MFA) manually due to redirect
def set_temp_redirect_cookies(response, temp_token):
    csrf_temp_token = get_csrf_token(temp_token)

    # Set temporary access token cookie duration to 5 minutes
    response.set_cookie('access_token_cookie', temp_token, max_age=5*60, secure=True, httponly=True, samesite='Strict')
    response.set_cookie('csrf_access_token', csrf_temp_token, max_age=5*60, secure=True, httponly=False, samesite='Strict')

# Create csrf token and set cookies for access and refresh tokens manually due to redirect
def set_redirect_cookies(response, access_token, refresh_token):
    csrf_access_token = get_csrf_token(access_token)
    csrf_refresh_token = get_csrf_token(refresh_token)

    # Set access token cookie duration to 15 minutes and refresh token to 7 days
    response.set_cookie('access_token_cookie', access_token, max_age=15*60, secure=True, httponly=True, samesite='Strict')
    response.set_cookie('refresh_token_cookie', refresh_token, max_age=7*24*60*60, secure=True, httponly=True, samesite='Strict')
    response.set_cookie('csrf_access_token', csrf_access_token, max_age=15*60, secure=True, httponly=False, samesite='Strict')
    response.set_cookie('csrf_refresh_token', csrf_refresh_token, max_age=7*24*60*60, secure=True, httponly=False, samesite='Strict')

# Global error handler for exceptions
@app.errorhandler(Exception)
def handle_exception(e):
    # Get the user ID from the JWT if available
    user_id = None
    try:
        user_id = get_jwt_identity()
    except Exception:
        pass
    
    # Separate handling for rate limit to send a specific response
    if isinstance(e, RateLimitExceeded):
        log_security_event(
            route="GLOBAL",
            event="RATE_LIMIT_EXCEEDED",
            user_id=user_id,
            message="Rate limit exceeded",
            extra_data={"error": str(e)}
        )
        return jsonify(message="Rate limit exceeded. Please try again later."), 429
    
    log_security_event(
        route="GLOBAL",
        event="EXCEPTION",
        user_id=user_id,
        message="An exception occurred",
        extra_data={"error": str(e), "traceback": traceback.format_exc()}
    )
    # Generic error response
    return jsonify(message="An unexpected error occurred. Please try again later."), 500