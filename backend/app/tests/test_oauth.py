import pytest
from unittest.mock import patch
from app import app, db
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

# Test Google OAuth login redirect
def test_login_google(client):
    with patch('app.routes.oauth.google.authorize_redirect') as mock_authorize_redirect:
        mock_authorize_redirect.return_value = "mock_redirect_url"
        response = client.get("/api/login/google")
        assert response.status_code == 200

# Test for Google OAuth callback success
def test_google_callback_success(client):
    with patch("app.routes.oauth.google.authorize_access_token") as mock_authorize_access_token, \
         patch("app.routes.oauth.google.get") as mock_google_get, \
         patch("app.routes.create_access_token") as mock_create_access_token, \
         patch("app.routes.create_refresh_token") as mock_create_refresh_token, \
         patch("app.routes.set_redirect_cookies") as mock_set_redirect_cookies, \
         patch("app.routes.create_session") as mock_create_session:

        # Mock the OAuth return values
        mock_authorize_access_token.return_value = {"access_token": "mock_token"}
        mock_google_get.return_value.json.return_value = {"email": "testuser@example.com"}
        mock_create_access_token.return_value = "mock_access_token"
        mock_create_refresh_token.return_value = "mock_refresh_token"

        response = client.get("/api/login/google/callback")

        # Check if the response is a redirect to the frontend URL
        assert response.status_code == 302
        assert response.headers["Location"] == app.config["FRONTEND_URL"]

# Test for Google OAuth callback failure with invalid token
def test_google_callback_invalid_token(client):
    with patch("app.routes.oauth.google.authorize_access_token") as mock_authorize_access_token:
        mock_authorize_access_token.return_value = None  # Simulate invalid token
        
        response = client.get("/api/login/google/callback")
        assert response.status_code == 400  # Bad request for invalid token

# Test GitHub OAuth login redirect
def test_login_github(client):
    with patch("app.routes.oauth.github.authorize_redirect") as mock_authorize_redirect:
        mock_authorize_redirect.return_value = "mock_redirect_url"
        
        response = client.get("/api/login/github")
        assert response.status_code == 200

# Test GitHub OAuth callback route with valid token
def test_github_callback_success(client):
    with patch("app.routes.oauth.github.authorize_access_token") as mock_authorize_access_token, \
         patch("app.routes.oauth.github.get") as mock_github_get, \
         patch("app.routes.create_access_token") as mock_create_access_token, \
         patch("app.routes.create_refresh_token") as mock_create_refresh_token, \
         patch("app.routes.set_redirect_cookies") as mock_set_redirect_cookies, \
         patch("app.routes.create_session") as mock_create_session:

        # Mock the token and user info
        mock_authorize_access_token.return_value = {"access_token": "mock_token"}
        mock_github_get.return_value.json.return_value = {"login": "testuser"}
        mock_create_access_token.return_value = "mock_access_token"
        mock_create_refresh_token.return_value = "mock_refresh_token"

        response = client.get("/api/login/github/callback")

        # Check if the response is a redirect to the frontend URL
        assert response.status_code == 302
        assert response.headers["Location"] == app.config["FRONTEND_URL"]

# Test GitHub OAuth callback route with invalid token
def test_github_callback_invalid_token(client):
    with patch("app.routes.oauth.github.authorize_access_token") as mock_authorize_access_token:
        mock_authorize_access_token.return_value = None  # Simulate invalid token
        
        response = client.get("/api/login/github/callback")
        assert response.status_code == 400 # Bad request for invalid token