from fastapi.testclient import TestClient

from lab.target_api.app import main
from scanner.authz_intel.discovery import discover


def token(client: TestClient, username: str) -> str:
    return client.post("/api/v1/auth/login", json={"username": username, "password": f"{username}-password"}).json()["access_token"]


def test_vulnerable_mode_exposes_cross_user_document(monkeypatch):
    monkeypatch.setattr(main, "MODE", "vulnerable")
    client = TestClient(main.app)
    response = client.get("/api/v1/documents/1001", headers={"Authorization": f"Bearer {token(client, 'bob')}"})
    assert response.status_code == 200
    assert "ALICE_PRIVATE_DOCUMENT_MARKER_1001" in response.text


def test_secure_mode_blocks_cross_user_document(monkeypatch):
    monkeypatch.setattr(main, "MODE", "secure")
    client = TestClient(main.app)
    response = client.get("/api/v1/documents/1001", headers={"Authorization": f"Bearer {token(client, 'bob')}"})
    assert response.status_code == 403
    monkeypatch.setattr(main, "MODE", "vulnerable")


def test_discovery_identifies_object_parameters():
    endpoints = discover({
        "paths": {
            "/documents/{document_id}": {
                "get": {"parameters": [{"name": "document_id", "in": "path"}]}
            }
        }
    })
    assert endpoints[0].object_parameters == ("document_id",)
