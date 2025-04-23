import pytest
import http.cookies
from .. import app
from ..db import db
from app import limiter
from unittest.mock import patch

@pytest.fixture
def client():
    app.config['TESTING'] = True
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

    # Create a test client
    with app.test_client() as client:
        with app.app_context():
            # Create a new connection and transaction
            connection = db.engine.connect()
            transaction = connection.begin()

            # Bind the session to the connection
            db.session.remove()
            db.session.bind = connection

            db.session.commit = lambda: None  # Disable commits
            db.session.flush()

            yield client

            db.session.remove()
            transaction.rollback()
            connection.close()
            limiter.storage.reset()  # Clear the rate limiter storage

@pytest.fixture
def logged_in_client(client):
    # Log in the user to get the access token
    response = client.post("/api/login",
        json={
            "username": "MfaTestUser",
            "password": "Testpassword1"
        },
        follow_redirects=False
    )
    assert response.status_code == 403

    cookies = response.headers.getlist("Set-Cookie")

    # Set cookies on the client
    for cookie in cookies:
        cookie_obj = http.cookies.SimpleCookie()
        cookie_obj.load(cookie)
        for key, morsel in cookie_obj.items():
            client.set_cookie(key=key, value=morsel.value)

    return client

@pytest.fixture
def logged_in_client_no_mfa(client):
    # Log in the user to get the access token
    response = client.post("/api/login",
        json={
            "username": "Testuser",
            "password": "Testpassword1"
        },
        follow_redirects=False
    )
    assert response.status_code == 200

    cookies = response.headers.getlist("Set-Cookie")

    # Set cookies on the client
    for cookie in cookies:
        cookie_obj = http.cookies.SimpleCookie()
        cookie_obj.load(cookie)
        for key, morsel in cookie_obj.items():
            client.set_cookie(key=key, value=morsel.value)

    return client

# Test successful mfa login simulating TOTP verification
def test_mfa_login(logged_in_client):
    with patch("pyotp.TOTP.verify") as mock_verify:
        mock_verify.return_value = True  # Mock the TOTP verification to always return True

        csrf_access_token = None
        for cookie in logged_in_client._cookies.values():
            if cookie.key == "csrf_access_token":
                csrf_access_token = cookie.value
                break

        assert csrf_access_token is not None, "CSRF token should be present in cookies"
        headers = {
            "X-CSRF-Token": csrf_access_token,
        }

        # Simulate a valid TOTP code
        response = logged_in_client.post(
            "/api/login/verify",
            json={"totp_code": "123456"},  # Mocked code
            headers=headers
        )

        assert response.status_code == 200
        assert response.json["mfa_enabled"] is True
        assert "user" in response.json

# Test mfa login with expired access token
def test_mfa_login_no_token(logged_in_client):
    csrf_access_token = None
    for cookie in logged_in_client._cookies.values():
        if cookie.key == "csrf_access_token":
            csrf_access_token = cookie.value
            break

    assert csrf_access_token is not None, "CSRF token should be present in cookies"

    headers = {
        "X-CSRF-Token": csrf_access_token,
    }
    logged_in_client.delete_cookie("csrf_access_token")
    response = logged_in_client.post(
        "/api/login/verify",
        json={"totp_code": "654321"},
        headers=headers
    )
    assert response.status_code == 403 # Forbidden due to expired (non existent) access token

# Test mfa login with invalid TOTP code
def test_mfa_login_invalid_code(logged_in_client):
    with patch("pyotp.TOTP.verify") as mock_verify:
        mock_verify.return_value = False  # Mock the TOTP verification to always return False

        csrf_access_token = None
        for cookie in logged_in_client._cookies.values():
            if cookie.key == "csrf_access_token":
                csrf_access_token = cookie.value
                break

        assert csrf_access_token is not None, "CSRF token should be present in cookies"
        headers = {
            "X-CSRF-Token": csrf_access_token,
        }

        # Simulate an invalid TOTP code
        response = logged_in_client.post(
            "/api/login/verify",
            json={"totp_code": "654321"},  # Mocked code
            headers=headers
        )

        assert response.status_code == 403  # Forbidden due to invalid MFA code

# Test mfa setup to generate QR code
def test_generate_mfa_qrcode(logged_in_client_no_mfa):
    csrf_access_token = None
    for cookie in logged_in_client_no_mfa._cookies.values():
        if cookie.key == "csrf_access_token":
            csrf_access_token = cookie.value
            break

    assert csrf_access_token is not None, "CSRF token should be present in cookies"

    headers = {
        "X-CSRF-Token": csrf_access_token,
    }

    response = logged_in_client_no_mfa.get("/api/mfa/setup", headers=headers)
    assert response.status_code == 200  # MFA QR code generated successfully

# Test mfa setup to generate QR code when already set up
def test_generate_mfa_qrcode_exists(logged_in_client):
    csrf_access_token = None
    for cookie in logged_in_client._cookies.values():
        if cookie.key == "csrf_access_token":
            csrf_access_token = cookie.value
            break

    assert csrf_access_token is not None, "CSRF token should be present in cookies"

    headers = {
        "X-CSRF-Token": csrf_access_token,
    }

    response = logged_in_client.get("/api/mfa/setup", headers=headers)
    assert response.status_code == 400  # MFA already set up, cannot generate QR code again

# Test mfa removal with valid TOTP code
def test_remove_mfa_success(logged_in_client):
    with patch("pyotp.TOTP.verify") as mock_verify:
        mock_verify.return_value = True  # Mock TOTP verification to return True

        csrf_access_token = None
        for cookie in logged_in_client._cookies.values():
            if cookie.key == "csrf_access_token":
                csrf_access_token = cookie.value
                break

        assert csrf_access_token is not None, "CSRF token should be present in cookies"

        headers = {
            "X-CSRF-Token": csrf_access_token,
        }
        response = logged_in_client.post(
            "/api/mfa/disable",
            json={"totp_code": "123456"},  # Mocked TOTP code
            headers=headers
        )
        assert response.status_code == 200  # MFA removed successfully

# Test mfa removal with invalid TOTP code
def test_remove_mfa_invalid(logged_in_client):
    with patch("pyotp.TOTP.verify") as mock_verify:
        mock_verify.return_value = False  # Mock TOTP verification to return False

        csrf_access_token = None
        for cookie in logged_in_client._cookies.values():
            if cookie.key == "csrf_access_token":
                csrf_access_token = cookie.value
                break

        assert csrf_access_token is not None, "CSRF token should be present in cookies"

        headers = {
            "X-CSRF-Token": csrf_access_token,
        }
        response = logged_in_client.post(
            "/api/mfa/disable",
            json={"totp_code": "654321"},  # Mocked TOTP code
            headers=headers
        )
        assert response.status_code == 401  # MFA code invalid

# Test MFA setup verification with valid TOTP code
def test_verify_mfa_setup_success(logged_in_client):
    with patch("pyotp.TOTP.verify") as mock_verify:
        mock_verify.return_value = True  # Mock TOTP verification to return True

        csrf_access_token = None
        for cookie in logged_in_client._cookies.values():
            if cookie.key == "csrf_access_token":
                csrf_access_token = cookie.value
                break

        assert csrf_access_token is not None, "CSRF token should be present in cookies"

        headers = {
            "X-CSRF-Token": csrf_access_token,
        }

        response = logged_in_client.post(
            "/api/mfa/setup/verify",
            json={"totp_code": "123456"},  # Mocked TOTP code
            headers=headers
        )
        assert response.status_code == 200

# Test MFA setup verification with invalid TOTP code
def test_verify_mfa_setup_invalid_code(logged_in_client):
    with patch("pyotp.TOTP.verify") as mock_verify:
        mock_verify.return_value = False  # Mock TOTP verification to return False

        csrf_access_token = None
        for cookie in logged_in_client._cookies.values():
            if cookie.key == "csrf_access_token":
                csrf_access_token = cookie.value
                break

        assert csrf_access_token is not None, "CSRF token should be present in cookies"

        headers = {
            "X-CSRF-Token": csrf_access_token,
        }
        response = logged_in_client.post(
            "/api/mfa/setup/verify",
            json={"totp_code": "654321"},  # Mocked invalid TOTP code
            headers=headers
        )
        assert response.status_code == 401