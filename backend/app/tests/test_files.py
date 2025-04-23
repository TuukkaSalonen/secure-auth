import pytest
from .. import app
from ..db import db
import http.cookies
from app import limiter
import io

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

# Test file list endpoint on logged in user
def test_get_filelist(logged_in_client):
    response = logged_in_client.get("/api/file/list")
    assert response.status_code == 200

# Test file list endpoint on unauthenticated user
def test_get_filelist_unauthenticated(client):
    response = client.get("/api/file/list")
    assert response.status_code == 401

# Test delete file endpoint on logged in user
def test_delete_file(logged_in_client):
    csrf_access_token = None
    for cookie in logged_in_client._cookies.values():
        if cookie.key == "csrf_access_token":
            csrf_access_token = cookie.value
            break

    assert csrf_access_token is not None, "CSRF token should be present in cookies"

    headers = {
        "X-CSRF-TOKEN": csrf_access_token
    }
    response = logged_in_client.delete("/api/file/delete/5af93446-6d8f-4330-afe8-378cd936af1c", headers=headers)
    assert response.status_code == 200  # File deleted successfully

    response = logged_in_client.delete("/api/file/delete/5af93446-6d8f-4330-afe8-378cd936af1d", headers=headers)
    assert response.status_code == 404  # Wrong file id

    response = logged_in_client.delete("/api/file/delete/123", headers=headers)
    assert response.status_code == 400  # Invalid file id format

# Test delete file endpoint on unauthenticated user
def test_delete_file_unauthenticated(client):
    response = client.delete("/api/file/delete/5af93446-6d8f-4330-afe8-378cd936af1c")
    assert response.status_code == 401

# Test download file endpoint on logged in user
def test_download_file(logged_in_client):
    response = logged_in_client.get("/api/file/download/5af93446-6d8f-4330-afe8-378cd936af1c")
    assert response.status_code == 200  # File downloaded successfully

    response = logged_in_client.get("/api/file/download/5af93446-6d8f-4330-afe8-378cd936af1d")
    assert response.status_code == 404  # File not found

    response = logged_in_client.get("/api/file/download/123")
    assert response.status_code == 400  # Invalid file id format

# Test download file endpoint on unauthenticated user
def test_download_file_unauthenticated(client):
    response = client.get("/api/file/download/5af93446-6d8f-4330-afe8-378cd936af1c")
    assert response.status_code == 401

# Test upload file endpoint on logged in user
def test_upload_file(logged_in_client):
    test_file_content = b"This is a test file."
    test_file = (io.BytesIO(test_file_content), "test_file.txt")
    
    csrf_access_token = None
    for cookie in logged_in_client._cookies.values():
        if cookie.key == "csrf_access_token":
            csrf_access_token = cookie.value
            break
    
    response = logged_in_client.post("/api/file/upload",
        headers={"X-CSRF-TOKEN": csrf_access_token},
        data={"file": test_file},
        content_type="multipart/form-data"
    )
    assert response.status_code == 201  # File uploaded successfully

    response = logged_in_client.post("/api/file/upload",
        headers={"X-CSRF-TOKEN": csrf_access_token},
        data={"file": ""},
        content_type="multipart/form-data"
    )
    assert response.status_code == 400  # Bad input, no file provided

    # File size edge case at exact limit
    max_size_file_content = b"A" * (100 * 1024 * 1024)
    max_size_file = (io.BytesIO(max_size_file_content), "max_size_file.txt")
    
    response = logged_in_client.post("/api/file/upload",
        headers={"X-CSRF-TOKEN": csrf_access_token},
        data={"file": max_size_file},
        content_type="multipart/form-data"
    )
    assert response.status_code == 201  # File uploaded successfully

    # File larger than 100 MB
    oversized_file_content = b"A" * (100 * 1024 * 1024 + 1)  # 100 MB + 1 byte
    oversized_file = (io.BytesIO(oversized_file_content), "oversized_file.txt")
    
    response = logged_in_client.post("/api/file/upload",
        headers={"X-CSRF-TOKEN": csrf_access_token},
        data={"file": oversized_file},
        content_type="multipart/form-data"
    )
    assert response.status_code == 400  # File size exceeds limit

# Test upload file endpoint on unauthenticated user
def test_upload_file_unauthenticated(client):
    test_file_content = b"This is a test file."
    test_file = (io.BytesIO(test_file_content), "test_file.txt")
    
    response = client.post("/api/file/upload",
        data={"file": test_file},
        content_type="multipart/form-data"
    )
    assert response.status_code == 401  # Unauthorized, user not logged in