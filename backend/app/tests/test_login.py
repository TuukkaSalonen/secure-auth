import pytest
from .. import app
from ..db import db
import http.cookies
from app import limiter

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

# Test successful login and cookies, login check and refresh endpoints
def test_login_success(client):
    response = client.post("/api/login",
        json={
            "username": "Testuser",
            "password": "Testpassword1"
        },
        follow_redirects=False
    )
    assert response.status_code == 200

    set_cookie_headers = response.headers.getlist('Set-Cookie')

    assert any("access_token_cookie" in cookie for cookie in set_cookie_headers), "access_token_cookie not found"
    assert any("refresh_token_cookie" in cookie for cookie in set_cookie_headers), "refresh_token_cookie not found"
    assert any("csrf_access_token" in cookie for cookie in set_cookie_headers), "csrf_access_token not found"
    assert any("csrf_refresh_token" in cookie for cookie in set_cookie_headers), "csrf_refresh_token not found"

# Test login check with logged in user
def test_check_login_authenticated(logged_in_client):
    response = logged_in_client.get("/api/check")
    assert response.status_code == 200

# Test token refresh with logged in user
def test_check_refresh_authenticated(logged_in_client):
    csrf_refresh_token = None
    for cookie in logged_in_client._cookies.values():
        if cookie.key == "csrf_refresh_token":
            csrf_refresh_token = cookie.value
            break

    assert csrf_refresh_token is not None, "CSRF token should be present in cookies"

    headers = {
        "X-CSRF-TOKEN": csrf_refresh_token
    }

    refresh_response = logged_in_client.post("/api/refresh", headers=headers)
    assert refresh_response.status_code == 200

# Test login with wrong password
def test_login_incorrect_password(client):
    response = client.post("/api/login",
        json={
            "username": "Testuser",
            "password": "Wrongpassword2"
        },
        follow_redirects=False
    )
    assert response.status_code == 401  # Unauthorized

# Test login with non-existent user
def test_login_incorrect_password(client):
    response = client.post("/api/login",
        json={
            "username": "NonExistentUser",
            "password": "Password123"
        },
        follow_redirects=False
    )
    assert response.status_code == 401  # Non-existent user

# Test login with bad password format
def test_login_bad_password(client):
    response = client.post("/api/login",
        json={
            "username": "Testuser",
            "password": "testpassword"
        },
        follow_redirects=False
    )
    assert response.status_code == 400  # Bad input, no uppercase, lowercase, or digit

    response = client.post("/api/login",
        json={
            "username": "Testuser",
            "password": "12345678902234567890123456789012345678901234567890123456789012345678901234567890"
        },
        follow_redirects=False
    )
    assert response.status_code == 400  # Bad input, too long password length

    response = client.post("/api/login",
        json={
            "username": "Testuser",
            "password": "Test   password123"
        },
        follow_redirects=False
    )
    assert response.status_code == 400  # Bad input, spaces in password

# Test login with user that has mfa enabled
def test_login_mfa_enabled(client):
    response = client.post("/api/login",
        json={
            "username": "MfaTestUser",
            "password": "Testpassword1",
        },
        follow_redirects=False
    )
    set_cookie_headers = response.headers.getlist("Set-Cookie")
    # Check for temporary short lived access token cookie for mfa login
    assert any("access_token_cookie" in cookie for cookie in set_cookie_headers), "temporary access_token_cookie not found"
    assert response.status_code == 403  # MFA required

# Test logout and cookie removal
def test_logout(client):
    logout_response = client.post("/api/logout", follow_redirects=False)

    set_cookie_headers = logout_response.headers.getlist('Set-Cookie')

    assert logout_response.status_code == 200
    assert any("access_token_cookie" not in cookie for cookie in set_cookie_headers), "access_token_cookie should be removed"
    assert any("refresh_token_cookie" not in cookie for cookie in set_cookie_headers), "refresh_token_cookie should be removed"
    assert any("csrf_access_token" not in cookie for cookie in set_cookie_headers), "csrf_access_token should be removed"
    assert any("csrf_refresh_token" not in cookie for cookie in set_cookie_headers), "csrf_refresh_token should be removed"

# Test login without token
def test_login_check(client):
    login_response = client.get("/api/check", follow_redirects=False)
    assert login_response.status_code == 401  # Unauthorized, no token provided

# Test refresh token without token and csrf token
def test_refresh(client):
    login_response = client.post("/api/refresh", follow_redirects=False)
    assert login_response.status_code == 401  # Unauthorized, no token provided