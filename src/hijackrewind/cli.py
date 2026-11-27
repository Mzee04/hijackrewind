"""Command line entrypoint. The dashboard and the library call the same pipeline."""

from __future__ import annotations

import argparse
import sys

from hijackrewind import __version__


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="hijackrewind",
        description=(
            "Verify a GitHub account-security alert and, when policy allows, "
            "revert only the unauthorized object. Sandbox mode is the default "
            "and needs no credentials."
        ),
    )
    parser.add_argument("--version", action="version", version=f"hijackrewind {__version__}")
    sub = parser.add_subparsers(dest="command")

    ingest = sub.add_parser("ingest", help="Read one alert (file or local URL) and triage it")
    ingest.add_argument("path", help="Path to an .eml, document, transcript, or http://127.0.0.1 URL")

    run = sub.add_parser("run", help="Ingest, verify, plan, and maybe execute")
    run.add_argument("path")

    sub.add_parser("demo", help="Plant an unknown SSH key on the stub and revert it")
    kill = sub.add_parser("kill", help="Trip the kill switch and cancel in-flight tool calls")
    kill.add_argument("--reason", default="operator")

    approve = sub.add_parser("approve", help="Approve one pending plan. Recorded in the audit log")
    approve.add_argument("plan_id")
    deny = sub.add_parser("deny", help="Deny one pending plan")
    deny.add_argument("plan_id")

    audit = sub.add_parser("audit", help="Print the append-only audit log")
    audit.add_argument("--verify", action="store_true", help="Check the hash chain and exit non-zero if it fails")

    sub.add_parser("dashboard", help="Local monitoring page, approvals, and the kill switch")
    sub.add_parser("trap-pack", help="Run the vendored Agentware Trap Pack inputs")
    sub.add_parser("doctor", help="Show mode, endpoints, and whether a token is set")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if not args.command:
        parser.print_help()
        return 0
    print(
        f"hijackrewind {__version__}: '{args.command}' is not wired yet.",
        file=sys.stderr,
    )
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
