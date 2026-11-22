from pathlib import Path

from scanner.authz_intel.discovery import discover, load_spec


def test_load_spec_supports_json(tmp_path: Path):
    source = tmp_path / "openapi.json"
    source.write_text(
        '{"openapi":"3.0.0","paths":{"/documents/{document_id}":{"get":{}}}}',
        encoding="utf-8",
    )
    spec = load_spec(source)
    assert "paths" in spec


def test_load_spec_supports_yaml(tmp_path: Path):
    source = tmp_path / "openapi.yaml"
    source.write_text(
        "openapi: 3.0.0\npaths:\n  /projects/{project_id}/tasks/{task_id}:\n    get: {}\n",
        encoding="utf-8",
    )
    spec = load_spec(source)
    assert "/projects/{project_id}/tasks/{task_id}" in spec["paths"]


def test_discovery_combines_path_and_query_parameters():
    endpoints = discover(
        {
            "paths": {
                "/documents/{document_id}": {
                    "parameters": [
                        {"name": "document_id", "in": "path"},
                        {"name": "ignored", "in": "header"},
                    ],
                    "patch": {
                        "parameters": [{"name": "expand", "in": "query"}],
                        "requestBody": {
                            "content": {
                                "application/json": {
                                    "schema": {"$ref": "#/components/schemas/DocumentUpdate"}
                                }
                            }
                        },
                    },
                }
            }
        }
    )

    endpoint = endpoints[0]
    assert endpoint.object_parameters == ("document_id",)
    assert endpoint.path_parameters == ("document_id",)
    assert endpoint.query_parameters == ("expand",)
    assert endpoint.request_body_schema == "#/components/schemas/DocumentUpdate"
    assert endpoint.resource_type == "documents"
    assert endpoint.testing_capability == "bola_write"


def test_discovery_does_not_mark_collection_or_unrelated_parameters():
    endpoints = discover(
        {
            "paths": {
                "/documents": {"get": {"parameters": [{"name": "tenant", "in": "query"}]}},
                "/users/{user_id}/documents/{document_id}": {
                    "get": {"parameters": [
                        {"name": "user_id", "in": "path"},
                        {"name": "document_id", "in": "path"},
                    ]}
                },
            }
        }
    )

    collection, nested = endpoints
    assert collection.object_parameters == ()
    assert collection.testing_capability == "none"
    assert nested.object_parameters == ("user_id", "document_id")
    assert nested.testing_capability == "bola_read"
