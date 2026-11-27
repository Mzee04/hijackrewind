"""Process services: audit, kill switch, stub, and the GitHub client."""

from __future__ import annotations

import json
import socket
import threading
import time
from dataclasses import dataclass
from pathlib import Path

import httpx
import uvicorn

from hijackrewind.audit import AuditLog
from hijackrewind.config import Settings
from hijackrewind.egress import EgressLog
from hijackrewind.github_client import CostMeter, GitHubClient
from hijackrewind.killswitch import KillSwitch
from hijackrewind.manifest import Manifest, load_manifest
from hijackrewind.monitor import Monitor
from hijackrewind.stub_app import create_stub
from hijackrewind.trace import TraceWriter

_STUBS: list["StubServer"] = []


@dataclass
class Services:
    settings: Settings
    audit: AuditLog
    kill: KillSwitch
    monitor: Monitor
    egress: EgressLog
    manifest: Manifest
    github: GitHubClient
    meter: CostMeter

    def trace_for(self, run_id: str) -> TraceWriter:
        return TraceWriter(self.settings.trace_dir, run_id, self.settings.secret_values())

    def reset_meter(self) -> None:
        self.meter.points = 0
        self.meter.mutates = 0
        self.egress.blocked.clear()


def build_services(
    settings: Settings,
    *,
    kill: KillSwitch | None = None,
    monitor: Monitor | None = None,
    audit: AuditLog | None = None,
) -> Services:
    audit_log = audit or AuditLog(settings.audit_log, settings.secret_values())
    switch = kill or KillSwitch(settings.kill_file())
    screen = monitor or Monitor()
    meter = CostMeter(settings.mutate_cap)
    egress = EgressLog(audit=audit_log, api_host=settings.api_host())
    manifest = load_manifest(settings.manifest_path)
    github = GitHubClient(settings, switch, egress, meter, screen)
    return Services(
        settings=settings,
        audit=audit_log,
        kill=switch,
        monitor=screen,
        egress=egress,
        manifest=manifest,
        github=github,
        meter=meter,
    )


class StubServer:
    """In-process GitHub stub. Docker compose runs the same app under uvicorn."""

    def __init__(self, host: str = "127.0.0.1", port: int = 0) -> None:
        sock = socket.socket()
        sock.bind((host, port))
        self.host = host
        self.port = sock.getsockname()[1]
        sock.close()
        self.app = create_stub()
        config = uvicorn.Config(self.app, host=host, port=self.port, log_level="warning", access_log=False)
        self.server = uvicorn.Server(config)
        self.server.install_signal_handlers = lambda: None  # type: ignore[method-assign]
        self.thread = threading.Thread(target=self.server.run, daemon=True)

    @property
    def url(self) -> str:
        return f"http://{self.host}:{self.port}"

    def start(self) -> None:
        self.thread.start()
        deadline = time.time() + 8
        while time.time() < deadline:
            try:
                response = httpx.get(self.url + "/health", timeout=0.3)
                if response.status_code == 200:
                    return
            except httpx.HTTPError:
                time.sleep(0.05)
        raise RuntimeError("GitHub stub did not start")

    def stop(self) -> None:
        self.server.should_exit = True
        self.thread.join(timeout=3)


def ensure_stub(settings: Settings) -> str:
    """Use a stub that is already up, or start one in this process."""
    health = settings.stub_url.rstrip("/") + "/health"
    try:
        response = httpx.get(health, timeout=0.5)
        if response.status_code == 200 and response.json().get("service") == "hijackrewind-github-stub":
            return settings.stub_url.rstrip("/")
    except httpx.HTTPError:
        pass
    server = StubServer()
    server.start()
    _STUBS.append(server)
    settings.stub_url = server.url
    return server.url


def reset_stub(base_url: str, payload: dict) -> None:
    response = httpx.post(base_url.rstrip("/") + "/_admin/reset", json=payload, timeout=5)
    response.raise_for_status()


def stub_state(base_url: str) -> dict:
    response = httpx.get(base_url.rstrip("/") + "/_admin/state", timeout=5)
    response.raise_for_status()
    return response.json()


def repo_root() -> Path:
    here = Path(__file__).resolve()
    for parent in here.parents:
        if (parent / "sandbox" / "fixtures").is_dir():
            return parent
    return Path.cwd()


def load_seed() -> dict:
    path = repo_root() / "sandbox" / "fixtures" / "stub-seed.json"
    return json.loads(path.read_text(encoding="utf-8"))


def demo_seed() -> dict:
    seed = load_seed()
    seed["ssh_keys"].append(
        {
            "id": 99,
            "title": "attacker-laptop",
            "fingerprint": "SHA256:attacker-laptop-demo",
            "key": "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAttackerLaptopDemoKeyOnly99",
        }
    )
    return seed


def demo_alert_path() -> Path:
    return repo_root() / "sandbox" / "fixtures" / "genuine-new-ssh-key.eml"
