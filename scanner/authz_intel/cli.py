from __future__ import annotations

import json
import sys
import urllib.request
from pathlib import Path

import typer

from .config import ConfigurationError, load_config
from .discovery import discover, load_spec
from .reporting import write_html, write_json
from .scanner import scan

app = typer.Typer(help="Evidence-driven BOLA scanner")


@app.command()
def validate(config: Path = typer.Option(..., "--config", exists=True, readable=True)) -> None:
    """Validate scanner configuration without making API requests."""
    try:
        loaded = load_config(config)
    except ConfigurationError as exc:
        raise typer.BadParameter(str(exc)) from exc
    typer.echo(f"valid configuration for {loaded.base_url}")


@app.command("discover")
def discover_command(
    config: Path = typer.Option(..., "--config", exists=True, readable=True),
) -> None:
    """Discover resource-oriented endpoints from the configured OpenAPI document."""
    try:
        loaded = load_config(config)
        if not loaded.openapi_url:
            raise ConfigurationError("target.openapi_url is required for discovery")
        endpoints = discover(load_spec(loaded.openapi_url))
    except (ConfigurationError, OSError, ValueError, RuntimeError) as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(code=2) from exc
    typer.echo(f"discovered {len(endpoints)} endpoint(s)")
    for endpoint in endpoints:
        objects = ",".join(endpoint.object_parameters) or "-"
        typer.echo(
            f"{endpoint.method:6} {endpoint.path:<45} "
            f"objects={objects:<20} capability={endpoint.testing_capability}"
        )


@app.command("endpoints")
def endpoints_command(
    config: Path = typer.Option(..., "--config", exists=True, readable=True),
) -> None:
    """Display the endpoint inventory."""
    discover_command(config)


@app.command("scan")
def scan_command(
    config: Path = typer.Option(..., "--config", exists=True, readable=True),
    output: Path = typer.Option(Path("report.json"), "--output"),
) -> None:
    """Run a read-only BOLA scan."""
    try:
        loaded = load_config(config)
        if loaded.openapi_url:
            with urllib.request.urlopen(loaded.openapi_url, timeout=loaded.timeout) as response:
                json.load(response)
        findings = scan(loaded.base_url, config=loaded)
        write_json(findings, output)
        write_html(findings, output.with_suffix(".html"))
    except (ConfigurationError, OSError, ValueError, RuntimeError) as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(code=2) from exc
    typer.echo(f"wrote {len(findings)} finding(s) to {output}")


def main() -> None:
    app()


if __name__ == "__main__":
    main()
