from __future__ import annotations

import argparse
import json
import urllib.request

from .reporting import write_html, write_json
from .scanner import scan


def main() -> None:
    parser = argparse.ArgumentParser(description="Evidence-driven BOLA scanner")
    subparsers = parser.add_subparsers(dest="command", required=True)
    command = subparsers.add_parser("scan")
    command.add_argument("--spec", help="OpenAPI URL (validated for availability)")
    command.add_argument("--base-url", required=True)
    command.add_argument("--output", default="report.json")
    args = parser.parse_args()
    if args.spec:
        with urllib.request.urlopen(args.spec, timeout=10) as response:
            json.load(response)
    findings = scan(args.base_url)
    write_json(findings, args.output)
    write_html(findings, args.output.rsplit(".", 1)[0] + ".html")
    print(f"wrote {len(findings)} finding(s) to {args.output}")


if __name__ == "__main__":
    main()

