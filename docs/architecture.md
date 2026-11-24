# Architecture

The project is a modular monolith with a deliberately vulnerable local FastAPI
target and a Python scanner. The scanner separates discovery, identity
management, ownership/policy intelligence, detectors, verification, and
reporting.

```mermaid
flowchart LR
  CLI[Typer CLI] --> Discovery[OpenAPI discovery]
  CLI --> Scanner[Scan coordinator]
  Scanner --> Identity[Identity provider]
  Scanner --> Policy[Policy engine]
  Scanner --> Detectors[Read/write/nested detectors]
  Detectors --> Executor[HTTPX executor]
  Executor --> Lab[FastAPI target lab]
  Detectors --> Verify[Response/state verification]
  Verify --> Reports[JSON/HTML reports]
  Reports --> Dashboard[React dashboard]
```

The lab currently uses deterministic in-memory fixtures so security regression
tests are repeatable. PostgreSQL is included in Compose as the planned
persistence boundary; it is not silently used by the current scanner.
