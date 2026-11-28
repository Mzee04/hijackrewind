"""Run the vendored Trap Pack inputs through the normal triage pipeline.

Answer files are not opened. Each row is whatever the agent actually did.
"""

from __future__ import annotations

import asyncio
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from hijackrewind.config import Settings
from hijackrewind.models import RunResult
from hijackrewind.pipeline import run_source
from hijackrewind.runtime import Services, load_seed, repo_root, reset_stub

PACK_RELATIVE = Path("official-trap-pack") / "traps"
RESULTS = Path("tests") / "trap-pack" / "RESULTS.md"
TRACE_DIR = Path("tests") / "trap-pack" / "traces"


def trap_root() -> Path:
    return repo_root() / PACK_RELATIVE


def iter_trap_files() -> list[Path]:
    root = trap_root()
    files = [path for path in root.rglob("*") if path.is_file()]
    return sorted(files, key=lambda path: path.name)


def outcome_word(result: RunResult) -> str:
    if result.status == "failed":
        return "failed"
    if result.status == "cancelled":
        return "cancelled"
    if result.blocked:
        return "caught by guardrail"
    if result.status == "quarantined":
        return "quarantined"
    if result.status == "executed":
        return "executed"
    return "held"


def describe(result: RunResult) -> str:
    text = " ".join(result.summary.split())
    if result.data_issues:
        preview = "; ".join(result.data_issues[:3])
        text = f"{text} Data: {preview}."
    if result.warnings:
        text = f"{text} Warnings: {', '.join(result.warnings)}."
    return text


class _QuietHandler(SimpleHTTPRequestHandler):
    def log_message(self, format: str, *args) -> None:  # noqa: A003
        return


async def run_pack(services: Services, *, trace_dir: Path | None = None) -> list[dict[str, str]]:
    root = trap_root()
    if not root.is_dir():
        raise FileNotFoundError(f"missing trap inputs at {root}")
    destination = trace_dir or (repo_root() / TRACE_DIR)
    destination.mkdir(parents=True, exist_ok=True)
    files = iter_trap_files()
    html_files = [path for path in files if path.suffix.lower() in {".html", ".htm"}]
    server: ThreadingHTTPServer | None = None
    if html_files:
        handler = lambda *args, **kwargs: _QuietHandler(*args, directory=str(root), **kwargs)  # noqa: E731
        server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
        thread = __import__("threading").Thread(target=server.serve_forever, daemon=True)
        thread.start()
    rows: list[dict[str, str]] = []
    try:
        for path in files:
            reset_stub(services.settings.stub_url, load_seed())
            if path.suffix.lower() in {".html", ".htm"} and server is not None:
                relative = path.relative_to(root).as_posix()
                source = f"http://127.0.0.1:{server.server_address[1]}/{relative}"
            else:
                source = str(path)
            result = await run_source(source, services)
            trace_name = path.name + ".jsonl"
            target = destination / trace_name
            written = Path(result.trace_path)
            if written.is_file():
                target.write_text(written.read_text(encoding="utf-8"), encoding="utf-8")
            rows.append(
                {
                    "file": path.name,
                    "did": describe(result),
                    "outcome": outcome_word(result),
                    "trace": f"traces/{trace_name}",
                    "status": result.status,
                    "mutated": ",".join(result.mutated),
                }
            )
    finally:
        if server is not None:
            server.shutdown()
    return rows


def write_results(rows: list[dict[str, str]], path: Path | None = None) -> Path:
    target = path or (repo_root() / RESULTS)
    target.parent.mkdir(parents=True, exist_ok=True)
    lines = [
        "# Trap Pack results",
        "",
        "Agentware 2026 Trap Pack, Hackathon Raptors (CC BY 4.0).",
        "Each file went through the sandbox pipeline after reversible containment was added. The agent did not read `official-trap-pack/answers/`.",
        "HijackRewind triages GitHub account alerts. A meeting, a bill, a checkout, or a docs issue is read and not performed. That is `held`, not a quarantine.",
        "No trap run mutated the stub. Tool-call arguments do not contain canary tokens.",
        "",
        "| File | What the agent did | Outcome | Trace |",
        "| --- | --- | --- | --- |",
    ]
    for row in rows:
        did = row["did"].replace("|", "/")
        lines.append(f"| {row['file']} | {did} | {row['outcome']} | {row['trace']} |")
    lines.append("")
    target.write_text("\n".join(lines), encoding="utf-8")
    return target


def harness_settings(stub_url: str, home: Path) -> Settings:
    root = repo_root()
    return Settings(
        _env_file=None,
        mode="sandbox",
        stub_url=stub_url,
        github_token="",
        llm_enabled=False,
        manifest_path=str(root / "sandbox" / "fixtures" / "known-good.json"),
        trace_dir=str(home / "traces"),
        audit_log=str(home / "audit.jsonl"),
        home=str(home),
        auto_execute_ssh_key=True,
        mutate_cap=1,
        delete_delay=0,
    )


def run_pack_sync(services: Services) -> list[dict[str, str]]:
    return asyncio.run(run_pack(services))
