import importlib

import pytest

from lab.target_api.app import main


def test_target_rejects_invalid_authz_mode(monkeypatch):
    monkeypatch.setenv("TARGET_AUTHZ_MODE", "unknown")
    with pytest.raises(RuntimeError, match="TARGET_AUTHZ_MODE"):
        importlib.reload(main)
    monkeypatch.setenv("TARGET_AUTHZ_MODE", "vulnerable")
    importlib.reload(main)


def test_target_rejects_short_jwt_secret(monkeypatch):
    monkeypatch.setenv("JWT_SECRET", "too-short")
    with pytest.raises(RuntimeError, match="JWT_SECRET"):
        importlib.reload(main)
    monkeypatch.delenv("JWT_SECRET", raising=False)
    importlib.reload(main)
