import pytest
from .. import app
from ..db import db

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

# Test successful registration
def test_register_success(client):
    response = client.post("/api/register",
        json={
            "username": "Testuser2",
            "password": "Testpassword1"
        },
        follow_redirects=False
    )
    assert response.status_code == 201  # User created

# Test registration with bad password
def test_register_bad_password(client):
    response = client.post("/api/register",
        json={
            "username": "testuser",
            "password": "testpassword"
        },
        follow_redirects=False
    )
    assert response.status_code == 400  # Bad input, no uppercase, lowercase, or digit

    response = client.post("/api/register",
        json={
            "username": "testuser",
            "password": "12345678902234567890123456789012345678901234567890123456789012345678901234567890"
        },
        follow_redirects=False
    )
    assert response.status_code == 400  # Bad input, too long password length

    response = client.post("/api/register",
        json={
            "username": "testuser",
            "password": "123   456"
        },
        follow_redirects=False
    )
    assert response.status_code == 400  # Bad input, spaces in password

    response = client.post("/api/register",
        json={
            "username": "testuser",
            "password": "Testpassword"
        },
        follow_redirects=False
    )
    assert response.status_code == 400  # Bad input, no digit in password

    response = client.post("/api/register",
        json={
            "username": "testuser",
            "password": "testpassword"
        },
        follow_redirects=False
    )
    assert response.status_code == 400  # Bad input, no uppercase in password

    response = client.post("/api/register",
        json={
            "username": "testuser",
            "password": "Test1"
        },
        follow_redirects=False
    )
    assert response.status_code == 400  # Bad input, insufficient password length

# Test registration with bad username
def test_register_bad_username(client):
    response = client.post("/api/register",
        json={
            "username": "t",
            "password": "Testpassword1"
        },
        follow_redirects=False
    )
    assert response.status_code == 400  # Bad input, insufficient username length

    response = client.post("/api/register",
        json={
            "username": "user@@",
            "password": "Testpassword1"
        },
        follow_redirects=False
    )
    assert response.status_code == 400  # Bad input, invalid username characters

    response = client.post("/api/register",
        json={
            "username": "123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
            "password": "Testpassword1"
        },
        follow_redirects=False
    )
    assert response.status_code == 400  # Bad input, too long username length
