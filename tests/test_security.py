import os, tempfile
import pytest
import app as trustvault

@pytest.fixture()
def client(tmp_path, monkeypatch):
    monkeypatch.setattr(trustvault, "DATA_DIR", tmp_path)
    monkeypatch.setattr(trustvault, "UPLOAD_DIR", tmp_path / "private_uploads")
    monkeypatch.setattr(trustvault, "DB_PATH", tmp_path / "test.sqlite3")
    trustvault.UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
    trustvault.init_db()
    trustvault.app.config.update(TESTING=True, WTF_CSRF_ENABLED=False, SECRET_KEY="test-secret")
    with trustvault.app.test_client() as client:
        yield client

def login(client, username, password):
    return client.post("/login", data={"username": username, "password": password}, follow_redirects=True)

def test_viewer_cannot_download_unshared_document(client):
    login(client, "owner", "OwnerDemo123!")
    response = client.post("/upload", data={"category":"HR", "file":( __import__("io").BytesIO(b"secret"), "salary.txt")}, content_type="multipart/form-data")
    assert response.status_code == 302
    with trustvault.connect_db() as con:
        doc_id = con.execute("SELECT id FROM documents").fetchone()["id"]
    client.post("/logout")
    login(client, "viewer", "ViewerDemo123!")
    response = client.get(f"/document/{doc_id}/download")
    assert response.status_code == 404

def test_grant_allows_and_revoke_denies_download(client):
    login(client, "owner", "OwnerDemo123!")
    client.post("/upload", data={"category":"HR", "file":(__import__("io").BytesIO(b"secret"), "salary.txt")}, content_type="multipart/form-data")
    with trustvault.connect_db() as con:
        doc_id = con.execute("SELECT id FROM documents").fetchone()["id"]
    client.post(f"/document/{doc_id}/share", data={"username":"viewer","permission":"read"})
    client.post("/logout")
    login(client, "viewer", "ViewerDemo123!")
    assert client.get(f"/document/{doc_id}/download").status_code == 200
    client.post("/logout")
    login(client, "owner", "OwnerDemo123!")
    client.post(f"/document/{doc_id}/revoke", data={"username":"viewer"})
    client.post("/logout")
    login(client, "viewer", "ViewerDemo123!")
    assert client.get(f"/document/{doc_id}/download").status_code == 404

def test_viewer_cannot_upload(client):
    login(client, "viewer", "ViewerDemo123!")
    response = client.post("/upload", data={"file":(__import__("io").BytesIO(b"x"), "test.txt")}, content_type="multipart/form-data")
    assert response.status_code == 403
