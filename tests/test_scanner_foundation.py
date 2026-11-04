import httpx
import pytest

from scanner.authz_intel.auth_provider import authenticate
from scanner.authz_intel.config import ConfigurationError, load_config
from scanner.authz_intel.request_executor import RequestExecutor


def test_load_config_requires_an_allowlisted_target(tmp_path):
    config_path = tmp_path / "lab.yaml"
    config_path.write_text(
        """
target:
  base_url: https://api.example.test
  allowed_hosts: [127.0.0.1]
principals:
  alice:
    type: bearer_env
    token_env: ALICE_TOKEN
""",
        encoding="utf-8",
    )

    with pytest.raises(ConfigurationError, match="not in allowed_hosts"):
        load_config(config_path)


def test_authentication_reads_secret_from_environment(tmp_path, monkeypatch):
    config_path = tmp_path / "lab.yaml"
    config_path.write_text(
        """
target:
  base_url: http://127.0.0.1:8000
  allowed_hosts: [127.0.0.1]
principals:
  alice:
    type: credentials
    username: alice
    password_env: LAB_PASSWORD
""",
        encoding="utf-8",
    )
    config = load_config(config_path)
    monkeypatch.setenv("LAB_PASSWORD", "not-written-to-reports")

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/api/v1/auth/login"
        assert request.read() == b'{"username":"alice","password":"not-written-to-reports"}'
        return httpx.Response(200, json={"access_token": "test-token"})

    with httpx.Client(
        base_url=config.base_url, transport=httpx.MockTransport(handler)
    ) as client:
        identity = authenticate(client, config, config.principals[0])

    assert identity.name == "alice"
    assert identity.headers == {"Authorization": "Bearer test-token"}


def test_request_executor_does_not_follow_external_redirect(tmp_path):
    config_path = tmp_path / "lab.yaml"
    config_path.write_text(
        """
target:
  base_url: http://127.0.0.1:8000
  allowed_hosts: [127.0.0.1]
principals:
  alice:
    type: bearer_env
    token_env: ALICE_TOKEN
""",
        encoding="utf-8",
    )
    config = load_config(config_path)

    def handler(_: httpx.Request) -> httpx.Response:
        return httpx.Response(302, headers={"location": "https://outside.example/"})

    with httpx.Client(
        base_url=config.base_url,
        transport=httpx.MockTransport(handler),
        follow_redirects=False,
    ) as client:
        with RequestExecutor(config, client) as executor:
            with pytest.raises(ConfigurationError, match="outside the allowed scope"):
                executor.execute("GET", "/api/v1/documents/1001")
