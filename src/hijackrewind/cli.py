"""Command line. The dashboard calls the same pipeline."""

from __future__ import annotations

import argparse
import asyncio
import sys

import uvicorn

from hijackrewind import __version__
from hijackrewind.config import load_settings
from hijackrewind.dashboard import create_dashboard
from hijackrewind.pipeline import execute_saved_plan, run_source
from hijackrewind.preflight import live_preflight
from hijackrewind.runtime import (
    build_services,
    demo_alert_path,
    demo_seed,
    ensure_stub,
    reset_stub,
    stub_state,
)
from hijackrewind.trap_harness import harness_settings, run_pack, write_results


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

    for name, help_text in (
        ("ingest", "Read one alert and run the pipeline"),
        ("run", "Ingest, verify, plan, and maybe execute"),
    ):
        command = sub.add_parser(name, help=help_text)
        command.add_argument("path", help="File path, or an http://127.0.0.1 URL")

    demo = sub.add_parser("demo", help="Plant an unknown SSH key on the stub and revert it")
    demo.add_argument("--kill", action="store_true", help="Abort the revert in flight and show the audit line")

    kill = sub.add_parser("kill", help="Trip the kill switch and cancel in-flight tool calls")
    kill.add_argument("--reason", default="operator")
    kill.add_argument("--reset", action="store_true", help="Clear the switch so a later run can start")

    approve = sub.add_parser("approve", help="Approve one pending plan. Recorded in the audit log")
    approve.add_argument("plan_id")
    deny = sub.add_parser("deny", help="Deny one pending plan")
    deny.add_argument("plan_id")

    audit = sub.add_parser("audit", help="Print the append-only audit log")
    audit.add_argument("--verify", action="store_true")

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
    if args.command in {"ingest", "run"}:
        return asyncio.run(_run_path(args.path))
    if args.command == "demo":
        return asyncio.run(_demo(kill_scene=args.kill))
    if args.command == "kill":
        return _kill(args.reason, reset=args.reset)
    if args.command == "approve":
        return asyncio.run(_approve(args.plan_id, approved=True))
    if args.command == "deny":
        return asyncio.run(_approve(args.plan_id, approved=False))
    if args.command == "audit":
        return _audit(verify_only=args.verify)
    if args.command == "dashboard":
        return _dashboard()
    if args.command == "trap-pack":
        return asyncio.run(_trap_pack())
    if args.command == "doctor":
        return _doctor()
    parser.print_help()
    return 2


async def _run_path(path: str) -> int:
    settings = load_settings()
    if settings.mode == "live":
        report = await live_preflight(settings)
        for line in report.lines:
            print(line)
        if not report.ok:
            return 2
    else:
        ensure_stub(settings)
    services = build_services(settings)
    result = await run_source(path, services)
    _print_result(result)
    return 0 if result.status != "failed" else 1


async def _demo(kill_scene: bool) -> int:
    settings = load_settings()
    if settings.mode == "live":
        print("demo refuses live mode. Use the sandbox default.", file=sys.stderr)
        return 2
    ensure_stub(settings)
    if kill_scene:
        settings.delete_delay = 2.0
    services = build_services(settings)
    if services.kill.tripped:
        services.kill.reset(audit=services.audit)
    reset_stub(settings.stub_url, demo_seed())
    before = [item["id"] for item in stub_state(settings.stub_url)["ssh_keys"]]
    print(f"stub {settings.stub_url} ssh key ids before: {before}")
    alert = demo_alert_path()
    if kill_scene:
        async def trip_soon() -> None:
            for _ in range(40):
                if services.monitor.step == "execute":
                    break
                await asyncio.sleep(0.05)
            await asyncio.sleep(0.15)
            services.kill.trip("demo kill switch", audit=services.audit, run_id=services.monitor.run_id or "-")

        run_task = asyncio.create_task(run_source(str(alert), services))
        await trip_soon()
        result = await run_task
    else:
        result = await run_source(str(alert), services)
    after = [item["id"] for item in stub_state(settings.stub_url)["ssh_keys"]]
    print(f"ssh key ids after: {after}")
    _print_result(result)
    if kill_scene:
        cancelled = any(event["action"] in {"run_cancelled", "tripped"} for event in services.audit.read_all())
        print("kill switch audit present:" , "yes" if cancelled else "no")
        print("pending delete finished:" , "no" if 99 in after else "yes")
    return 0 if result.status != "failed" else 1


def _kill(reason: str, *, reset: bool) -> int:
    settings = load_settings()
    services = build_services(settings)
    if reset:
        services.kill.reset(audit=services.audit)
        print("kill switch cleared")
        return 0
    services.kill.trip(reason, audit=services.audit)
    print(f"kill switch tripped: {reason}")
    print(f"flag: {settings.kill_file()}")
    return 0


async def _approve(plan_id: str, *, approved: bool) -> int:
    settings = load_settings()
    if settings.mode != "live":
        ensure_stub(settings)
    services = build_services(settings)
    try:
        result = await execute_saved_plan(services, plan_id, approved=approved)
    except FileNotFoundError:
        print(f"no plan {plan_id}", file=sys.stderr)
        return 2
    _print_result(result)
    return 0 if result.status != "failed" else 1


def _audit(*, verify_only: bool) -> int:
    settings = load_settings()
    services = build_services(settings)
    ok, detail = services.audit.verify()
    if verify_only:
        print("audit chain ok" if ok else f"audit chain failed: {detail}")
        return 0 if ok else 1
    for event in services.audit.read_all():
        print(f"{event['seq']:04d} {event['ts']} {event['actor']} {event['action']} {event['detail']}")
    print("chain:", "ok" if ok else detail)
    return 0 if ok else 1


def _dashboard() -> int:
    settings = load_settings()
    if settings.mode != "live":
        ensure_stub(settings)
    app = create_dashboard(settings)
    print(f"dashboard http://{settings.dashboard_host}:{settings.dashboard_port}")
    uvicorn.run(
        app,
        host=settings.dashboard_host,
        port=settings.dashboard_port,
        log_level="info",
        access_log=False,
    )
    return 0


async def _trap_pack() -> int:
    settings = load_settings()
    if settings.mode == "live":
        print("trap-pack refuses live mode.", file=sys.stderr)
        return 2
    ensure_stub(settings)
    home_settings = harness_settings(settings.stub_url, settings.plan_dir().parent / "trap-home")
    services = build_services(home_settings)
    rows = await run_pack(services)
    path = write_results(rows)
    counts: dict[str, int] = {}
    for row in rows:
        counts[row["outcome"]] = counts.get(row["outcome"], 0) + 1
    print(f"wrote {path} ({len(rows)} files)")
    for name, count in sorted(counts.items()):
        print(f"  {name}: {count}")
    mutated = [row["file"] for row in rows if row["mutated"]]
    if mutated:
        print("mutated during trap pack:", ", ".join(mutated))
    return 0 if len(rows) == 20 else 1


def _doctor() -> int:
    settings = load_settings()
    report = asyncio.run(live_preflight(settings))
    print(f"hijackrewind {__version__}")
    for line in report.lines:
        print(line)
    print(f"api: {settings.api_base()}")
    print(f"manifest: {settings.manifest_path}")
    print(f"sender allowlist: {', '.join(settings.allowlisted_domains())}")
    print(f"auto-execute one unknown ssh key: {settings.auto_execute_ssh_key}")
    print(f"mutate cap: {settings.mutate_cap}")
    print(f"llm: {'on' if settings.llm_enabled else 'off'}")
    print(f"configured test repo: {settings.test_repo_owner}/{settings.test_repo_name}")
    print(f"dashboard: http://{settings.dashboard_host}:{settings.dashboard_port}")
    return 0 if report.ok else 2


def _print_result(result) -> None:
    print(f"status: {result.status}")
    print(result.summary)
    if result.plan_id:
        print(f"plan: {result.plan_id}")
    if result.trace_path:
        print(f"trace: {result.trace_path}")
    print(f"rate-limit points: {result.cost_points}")
    if result.explanation:
        print(f"explanation (not an authorization): {result.explanation}")


if __name__ == "__main__":
    raise SystemExit(main())
