import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from fastapi.testclient import TestClient

from app.main import REPOS, app


client = TestClient(app)


def _configure_auth(monkeypatch, tmp_path):
    monkeypatch.setenv("CLANKER_AUTH_REQUIRED", "true")
    monkeypatch.setenv("CLANKER_DEV_AUTH_TOKENS", "true")
    monkeypatch.setenv("CLANKER_AUTH_SECRET", "test-only-secret")
    monkeypatch.setenv("CLANKER_AUTH_DATA_PATH", str(tmp_path / "auth.json"))
    REPOS.clear()
    client.cookies.clear()


def _signup_and_verify(email: str):
    created = client.post("/api/auth/signup", json={"email": email, "password": "a-secure-password", "password_confirmation": "a-secure-password"})
    assert created.status_code == 200
    token = created.json()["development_verification_token"]
    verified = client.post("/api/auth/verify-email", json={"token": token})
    assert verified.status_code == 200
    return verified.json()["user"]


def test_signup_verify_login_and_protected_repository(monkeypatch, tmp_path):
    _configure_auth(monkeypatch, tmp_path)
    user = _signup_and_verify("alice@example.com")
    assert user["email_verified"] is True
    repo = client.post("/api/repositories/demo")
    assert repo.status_code == 200
    assert client.get(f"/api/repositories/{repo.json()['id']}").status_code == 200
    client.post("/api/auth/logout")
    assert client.get(f"/api/repositories/{repo.json()['id']}").status_code == 401


def test_user_cannot_access_another_users_repository(monkeypatch, tmp_path):
    _configure_auth(monkeypatch, tmp_path)
    _signup_and_verify("alice@example.com")
    repo_id = client.post("/api/repositories/demo").json()["id"]
    client.post("/api/auth/logout")
    _signup_and_verify("bob@example.com")
    assert client.get(f"/api/repositories/{repo_id}").status_code == 404


def test_reset_flow_does_not_reveal_unknown_email(monkeypatch, tmp_path):
    _configure_auth(monkeypatch, tmp_path)
    response = client.post("/api/auth/forgot-password", json={"email": "nobody@example.com"})
    assert response.status_code == 200
    assert "development_reset_token" not in response.json()
    _signup_and_verify("alice@example.com")
    client.post("/api/auth/logout")
    client.post("/api/auth/forgot-password", json={"email": "alice@example.com"})
    # The public response shape stays the same whether the account exists.
    assert response.json()["status"] == "accepted"
