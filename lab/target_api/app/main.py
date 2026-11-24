from __future__ import annotations

import hashlib
import hmac
import os
from copy import deepcopy
from dataclasses import dataclass
from typing import Annotated, Any

import jwt
from fastapi import Depends, FastAPI, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, ConfigDict

JWT_ALGORITHM = "HS256"
JWT_SECRET = os.getenv("JWT_SECRET", "development-only-change-me-32-bytes")
MODE = os.getenv("TARGET_AUTHZ_MODE", "vulnerable").lower()
if MODE not in {"vulnerable", "secure"}:
    raise RuntimeError("TARGET_AUTHZ_MODE must be 'vulnerable' or 'secure'")
if len(JWT_SECRET) < 32:
    raise RuntimeError("JWT_SECRET must contain at least 32 characters")


@dataclass(frozen=True)
class User:
    username: str
    password_hash: str
    role: str
    tenant: str


def _password_hash(password: str) -> str:
    return hashlib.pbkdf2_hmac(
        "sha256", password.encode(), b"bola-lab-password-salt", 120_000
    ).hex()


def _fixture_password(username: str) -> str:
    return os.getenv(f"LAB_{username.upper()}_PASSWORD", f"{username}-password")


def _build_users() -> dict[str, User]:
    return {
        username: User(username, _password_hash(_fixture_password(username)), role, tenant)
        for username, role, tenant in (
            ("alice", "user", "tenant-a"),
            ("bob", "user", "tenant-a"),
            ("charlie", "user", "tenant-b"),
            ("admin", "admin", "tenant-a"),
        )
    }


USERS = _build_users()


def _seed_documents() -> dict[int, dict[str, Any]]:
    return {
        1001: {
            "id": 1001,
            "owner": "alice",
            "tenant": "tenant-a",
            "title": "Alice private",
            "content": "ALICE_PRIVATE_DOCUMENT_MARKER_1001",
            "visibility": "private",
            "shared_with": [],
        },
        1002: {
            "id": 1002,
            "owner": "alice",
            "tenant": "tenant-a",
            "title": "Shared design",
            "content": "SHARED_DOCUMENT_MARKER_1002",
            "visibility": "shared",
            "shared_with": ["bob"],
        },
        2001: {
            "id": 2001,
            "owner": "bob",
            "tenant": "tenant-a",
            "title": "Bob private",
            "content": "BOB_PRIVATE_DOCUMENT_MARKER_2001",
            "visibility": "private",
            "shared_with": [],
        },
        3001: {
            "id": 3001,
            "owner": "charlie",
            "tenant": "tenant-b",
            "title": "Charlie private",
            "content": "CHARLIE_PRIVATE_DOCUMENT_MARKER_3001",
            "visibility": "private",
            "shared_with": [],
        },
    }


DOCUMENTS = _seed_documents()
PROJECTS = {
    10: {"id": 10, "owner": "alice", "tenant": "tenant-a", "name": "Alice project"},
    20: {"id": 20, "owner": "charlie", "tenant": "tenant-b", "name": "Charlie project"},
}
TASKS = {
    (10, 5001): {
        "project_id": 10,
        "task_id": 5001,
        "owner": "alice",
        "tenant": "tenant-a",
        "marker": "TASK_MARKER_5001",
    },
    (20, 5002): {
        "project_id": 20,
        "task_id": 5002,
        "owner": "charlie",
        "tenant": "tenant-b",
        "marker": "TASK_MARKER_5002",
    },
}


class Login(BaseModel):
    username: str
    password: str


class DocumentUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    title: str | None = None
    content: str | None = None


bearer = HTTPBearer(auto_error=False)
app = FastAPI(title="BOLA Lab API", version="1.0.0")


def _unauthorized(detail: str = "Authentication required") -> HTTPException:
    return HTTPException(status.HTTP_401_UNAUTHORIZED, detail)


def current_user(
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(bearer)],
) -> User:
    if credentials is None:
        raise _unauthorized()
    try:
        payload = jwt.decode(credentials.credentials, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        username = payload["sub"]
        user = USERS[username]
    except (jwt.PyJWTError, KeyError, TypeError) as exc:
        raise _unauthorized("Invalid or expired token") from exc
    return user


def _resource_allowed(user: User, resource: dict[str, Any], action: str) -> bool:
    """Apply the lab policy in one place so vulnerable behavior is intentional."""
    if MODE == "vulnerable" and action in {"read", "update", "delete"}:
        return resource.get("tenant") == user.tenant or action == "read"
    if user.role == "admin" and resource.get("tenant") == user.tenant:
        return True
    if resource.get("tenant") != user.tenant:
        return False
    if resource.get("owner") == user.username:
        return True
    return action == "read" and user.username in resource.get("shared_with", [])


def _require_resource(resources: dict[Any, dict[str, Any]], resource_id: Any, label: str) -> dict[str, Any]:
    resource = resources.get(resource_id)
    if resource is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, f"{label} not found")
    return resource


def _require_document(document_id: int) -> dict[str, Any]:
    return _require_resource(DOCUMENTS, document_id, "Document")


def _deny(action: str) -> HTTPException:
    return HTTPException(status.HTTP_403_FORBIDDEN, f"Document {action} denied")


@app.post("/api/v1/auth/login")
def login(credentials: Login) -> dict[str, str]:
    user = USERS.get(credentials.username)
    if user is None or not hmac.compare_digest(
        user.password_hash, _password_hash(credentials.password)
    ):
        raise _unauthorized("Invalid credentials")
    token = jwt.encode({"sub": user.username}, JWT_SECRET, algorithm=JWT_ALGORITHM)
    return {"access_token": token, "token_type": "bearer"}


@app.get("/api/v1/users/me")
def me(user: Annotated[User, Depends(current_user)]) -> dict[str, str]:
    return {"username": user.username, "role": user.role, "tenant": user.tenant}


@app.get("/api/v1/documents")
def list_documents(user: Annotated[User, Depends(current_user)]) -> list[dict[str, Any]]:
    return [
        deepcopy(document)
        for document in DOCUMENTS.values()
        if _resource_allowed(user, document, "read")
    ]


@app.get("/api/v1/documents/{document_id}")
def get_document(
    document_id: int, user: Annotated[User, Depends(current_user)]
) -> dict[str, Any]:
    document = _require_document(document_id)
    if not _resource_allowed(user, document, "read"):
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Document access denied")
    return deepcopy(document)


@app.post("/api/v1/documents", status_code=201)
def create_document(
    payload: DocumentUpdate, user: Annotated[User, Depends(current_user)]
) -> dict[str, Any]:
    next_id = max(DOCUMENTS) + 1
    document = {
        "id": next_id,
        "owner": user.username,
        "tenant": user.tenant,
        "title": payload.title or "",
        "content": payload.content or "",
        "visibility": "private",
        "shared_with": [],
    }
    DOCUMENTS[next_id] = document
    return deepcopy(document)


def _update_document(document_id: int, payload: DocumentUpdate, user: User) -> dict[str, Any]:
    document = _require_document(document_id)
    if not _resource_allowed(user, document, "update"):
        raise _deny("update")
    document.update(payload.model_dump(exclude_none=True))
    return deepcopy(document)


@app.put("/api/v1/documents/{document_id}")
def put_document(
    document_id: int,
    payload: DocumentUpdate,
    user: Annotated[User, Depends(current_user)],
) -> dict[str, Any]:
    return _update_document(document_id, payload, user)


@app.patch("/api/v1/documents/{document_id}")
def patch_document(
    document_id: int,
    payload: DocumentUpdate,
    user: Annotated[User, Depends(current_user)],
) -> dict[str, Any]:
    return _update_document(document_id, payload, user)


@app.delete("/api/v1/documents/{document_id}")
def delete_document(
    document_id: int, user: Annotated[User, Depends(current_user)]
) -> dict[str, int]:
    document = _require_document(document_id)
    if not _resource_allowed(user, document, "delete"):
        raise _deny("deletion")
    del DOCUMENTS[document_id]
    return {"deleted": document_id}


@app.get("/api/v1/projects")
def list_projects(user: Annotated[User, Depends(current_user)]) -> list[dict[str, Any]]:
    return [
        deepcopy(project)
        for project in PROJECTS.values()
        if _resource_allowed(user, project, "read")
    ]


@app.get("/api/v1/projects/{project_id}")
def get_project(
    project_id: int, user: Annotated[User, Depends(current_user)]
) -> dict[str, Any]:
    project = _require_resource(PROJECTS, project_id, "Project")
    if not _resource_allowed(user, project, "read"):
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Project access denied")
    return deepcopy(project)


@app.get("/api/v1/projects/{project_id}/tasks/{task_id}")
def get_task(
    project_id: int,
    task_id: int,
    user: Annotated[User, Depends(current_user)],
) -> dict[str, Any]:
    task = _require_resource(TASKS, (project_id, task_id), "Task")
    project = _require_resource(PROJECTS, project_id, "Project")
    if (
        MODE != "vulnerable"
        and not _resource_allowed(user, project, "read")
        or not _resource_allowed(user, task, "read")
    ):
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Task access denied")
    return deepcopy(task)


@app.get("/api/v1/invoices/{invoice_id}")
def get_invoice(
    invoice_id: int, user: Annotated[User, Depends(current_user)]
) -> dict[str, Any]:
    invoice = {"id": invoice_id, "tenant": "tenant-a", "owner": "admin", "marker": "INVOICE_MARKER_9001"}
    if MODE != "vulnerable" and not _resource_allowed(user, invoice, "read"):
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Invoice access denied")
    return invoice


@app.post("/api/v1/reset")
def reset(user: Annotated[User, Depends(current_user)]) -> dict[str, str]:
    if user.role != "admin":
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Only admins can reset the lab")
    DOCUMENTS.clear()
    DOCUMENTS.update(_seed_documents())
    return {"status": "reset"}
