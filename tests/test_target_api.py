from fastapi.testclient import TestClient

from lab.target_api.app import main


def authenticated_client(username: str) -> tuple[TestClient, dict[str, str]]:
    client = TestClient(main.app)
    response = client.post(
        "/api/v1/auth/login",
        json={"username": username, "password": f"{username}-password"},
    )
    assert response.status_code == 200
    return client, {"Authorization": f"Bearer {response.json()['access_token']}"}


def test_secure_mode_enforces_ownership_and_tenant_isolation(monkeypatch):
    monkeypatch.setattr(main, "MODE", "secure")
    client, bob_headers = authenticated_client("bob")
    _, charlie_headers = authenticated_client("charlie")

    assert client.get("/api/v1/documents/1001", headers=bob_headers).status_code == 403
    assert client.get("/api/v1/documents/1001", headers=charlie_headers).status_code == 403
    assert client.get("/api/v1/documents/2001", headers=bob_headers).status_code == 200
    monkeypatch.setattr(main, "MODE", "vulnerable")


def test_shared_document_is_allowed_only_to_configured_user(monkeypatch):
    monkeypatch.setattr(main, "MODE", "secure")
    client, bob_headers = authenticated_client("bob")
    _, charlie_headers = authenticated_client("charlie")

    assert client.get("/api/v1/documents/1002", headers=bob_headers).status_code == 200
    assert client.get("/api/v1/documents/1002", headers=charlie_headers).status_code == 403
    monkeypatch.setattr(main, "MODE", "vulnerable")


def test_secure_mode_rejects_unauthorized_write_and_delete(monkeypatch):
    monkeypatch.setattr(main, "MODE", "secure")
    client, bob_headers = authenticated_client("bob")

    update = client.patch(
        "/api/v1/documents/1001",
        json={"content": "UNAUTHORIZED_MARKER"},
        headers=bob_headers,
    )
    deletion = client.delete("/api/v1/documents/1001", headers=bob_headers)

    assert update.status_code == 403
    assert deletion.status_code == 403
    monkeypatch.setattr(main, "MODE", "vulnerable")


def test_vulnerable_mode_allows_controlled_write_but_reset_restores_state(monkeypatch):
    monkeypatch.setattr(main, "MODE", "vulnerable")
    client, bob_headers = authenticated_client("bob")
    update = client.patch(
        "/api/v1/documents/1001",
        json={"content": "BOB_UNAUTHORIZED_WRITE_MARKER"},
        headers=bob_headers,
    )
    assert update.status_code == 200
    assert client.get("/api/v1/documents/1001", headers=bob_headers).json()["content"] == (
        "BOB_UNAUTHORIZED_WRITE_MARKER"
    )

    _, admin_headers = authenticated_client("admin")
    reset = client.post("/api/v1/reset", headers=admin_headers)
    assert reset.status_code == 200
    assert client.get("/api/v1/documents/1001", headers=bob_headers).json()["content"] == (
        "ALICE_PRIVATE_DOCUMENT_MARKER_1001"
    )


def test_nested_resources_validate_parent_and_child_in_secure_mode(monkeypatch):
    monkeypatch.setattr(main, "MODE", "secure")
    client, alice_headers = authenticated_client("alice")
    _, charlie_headers = authenticated_client("charlie")

    assert client.get(
        "/api/v1/projects/10/tasks/5001", headers=alice_headers
    ).status_code == 200
    assert client.get(
        "/api/v1/projects/20/tasks/5002", headers=alice_headers
    ).status_code == 403
    assert client.get(
        "/api/v1/projects/10/tasks/5001", headers=charlie_headers
    ).status_code == 403
    monkeypatch.setattr(main, "MODE", "vulnerable")


def test_invalid_token_is_authentication_failure():
    client = TestClient(main.app)
    response = client.get(
        "/api/v1/documents/1001",
        headers={"Authorization": "Bearer not-a-token"},
    )
    assert response.status_code == 401
