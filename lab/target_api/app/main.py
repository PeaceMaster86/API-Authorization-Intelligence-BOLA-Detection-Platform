from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Annotated

import jwt
from fastapi import Depends, FastAPI, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel

SECRET = os.getenv("JWT_SECRET", "development-only-change-me")
MODE = os.getenv("TARGET_AUTHZ_MODE", "vulnerable").lower()


@dataclass(frozen=True)
class User:
    username: str
    password: str
    role: str
    tenant: str


USERS = {
    u.username: u
    for u in (
        User("alice", "alice-password", "user", "tenant-a"),
        User("bob", "bob-password", "user", "tenant-a"),
        User("charlie", "charlie-password", "user", "tenant-b"),
        User("admin", "admin-password", "admin", "tenant-a"),
    )
}
DOCUMENTS = {
    1001: {"id": 1001, "owner": "alice", "tenant": "tenant-a", "title": "Alice private", "content": "ALICE_PRIVATE_DOCUMENT_MARKER_1001"},
    1002: {"id": 1002, "owner": "alice", "tenant": "tenant-a", "title": "Shared design", "content": "SHARED_DOCUMENT_MARKER_1002", "shared_with": ["bob"]},
    2001: {"id": 2001, "owner": "bob", "tenant": "tenant-a", "title": "Bob private", "content": "BOB_PRIVATE_DOCUMENT_MARKER_2001"},
    3001: {"id": 3001, "owner": "charlie", "tenant": "tenant-b", "title": "Charlie private", "content": "CHARLIE_PRIVATE_DOCUMENT_MARKER_3001"},
}


class Login(BaseModel):
    username: str
    password: str


class DocumentUpdate(BaseModel):
    title: str | None = None
    content: str | None = None


bearer = HTTPBearer(auto_error=False)
app = FastAPI(title="BOLA Lab API", version="1.0.0")


def current_user(credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(bearer)]) -> User:
    if not credentials:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Authentication required")
    try:
        username = jwt.decode(credentials.credentials, SECRET, algorithms=["HS256"])["sub"]
        return USERS[username]
    except (jwt.PyJWTError, KeyError) as exc:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid token") from exc


def can_access(user: User, document: dict) -> bool:
    if MODE == "vulnerable":
        return True
    return user.role == "admin" or document["owner"] == user.username or user.username in document.get("shared_with", [])


def require_document(document_id: int) -> dict:
    document = DOCUMENTS.get(document_id)
    if not document:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Document not found")
    return document


@app.post("/api/v1/auth/login")
def login(credentials: Login) -> dict:
    user = USERS.get(credentials.username)
    if not user or user.password != credentials.password:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid credentials")
    return {"access_token": jwt.encode({"sub": user.username}, SECRET, algorithm="HS256"), "token_type": "bearer"}


@app.get("/api/v1/users/me")
def me(user: Annotated[User, Depends(current_user)]) -> dict:
    return {"username": user.username, "role": user.role, "tenant": user.tenant}


@app.get("/api/v1/documents")
def list_documents(user: Annotated[User, Depends(current_user)]) -> list[dict]:
    return [d for d in DOCUMENTS.values() if can_access(user, d)]


@app.get("/api/v1/documents/{document_id}")
def get_document(document_id: int, user: Annotated[User, Depends(current_user)]) -> dict:
    document = require_document(document_id)
    if not can_access(user, document):
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Document access denied")
    return document


@app.post("/api/v1/documents", status_code=201)
def create_document(payload: DocumentUpdate, user: Annotated[User, Depends(current_user)]) -> dict:
    next_id = max(DOCUMENTS) + 1
    document = {"id": next_id, "owner": user.username, "tenant": user.tenant, "title": payload.title or "", "content": payload.content or ""}
    DOCUMENTS[next_id] = document
    return document


def update_document(document_id: int, payload: DocumentUpdate, user: User) -> dict:
    document = require_document(document_id)
    if MODE != "vulnerable" and not can_access(user, document):
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Document update denied")
    document.update(payload.model_dump(exclude_none=True))
    return document


@app.put("/api/v1/documents/{document_id}")
def put_document(document_id: int, payload: DocumentUpdate, user: Annotated[User, Depends(current_user)]) -> dict:
    return update_document(document_id, payload, user)


@app.patch("/api/v1/documents/{document_id}")
def patch_document(document_id: int, payload: DocumentUpdate, user: Annotated[User, Depends(current_user)]) -> dict:
    return update_document(document_id, payload, user)


@app.delete("/api/v1/documents/{document_id}")
def delete_document(document_id: int, user: Annotated[User, Depends(current_user)]) -> dict:
    document = require_document(document_id)
    if MODE != "vulnerable" and (user.role != "admin" and document["owner"] != user.username):
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Document deletion denied")
    del DOCUMENTS[document_id]
    return {"deleted": document_id}


@app.get("/api/v1/projects/{project_id}/tasks/{task_id}")
def nested_task(project_id: int, task_id: int, user: Annotated[User, Depends(current_user)]) -> dict:
    if MODE != "vulnerable" and user.tenant != "tenant-a":
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Task access denied")
    return {"project_id": project_id, "task_id": task_id, "tenant": "tenant-a", "marker": "TASK_MARKER_5001"}


@app.get("/api/v1/invoices/{invoice_id}")
def invoice(invoice_id: int, user: Annotated[User, Depends(current_user)]) -> dict:
    if MODE != "vulnerable" and user.role != "admin":
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Invoice access denied")
    return {"id": invoice_id, "tenant": "tenant-a", "marker": "INVOICE_MARKER_9001"}


@app.post("/api/v1/reset")
def reset(_: Request) -> dict:
    DOCUMENTS.clear()
    DOCUMENTS.update({
        1001: {"id": 1001, "owner": "alice", "tenant": "tenant-a", "title": "Alice private", "content": "ALICE_PRIVATE_DOCUMENT_MARKER_1001"},
        1002: {"id": 1002, "owner": "alice", "tenant": "tenant-a", "title": "Shared design", "content": "SHARED_DOCUMENT_MARKER_1002", "shared_with": ["bob"]},
        2001: {"id": 2001, "owner": "bob", "tenant": "tenant-a", "title": "Bob private", "content": "BOB_PRIVATE_DOCUMENT_MARKER_2001"},
        3001: {"id": 3001, "owner": "charlie", "tenant": "tenant-b", "title": "Charlie private", "content": "CHARLIE_PRIVATE_DOCUMENT_MARKER_3001"},
    })
    return {"status": "reset"}
