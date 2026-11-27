"""Local monitoring page. Same process as the kill switch and the pipeline."""

from __future__ import annotations

import asyncio
from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse
from pydantic import BaseModel

from hijackrewind.config import Settings, load_settings
from hijackrewind.pipeline import execute_saved_plan, run_source
from hijackrewind.runtime import Services, build_services, demo_alert_path, demo_seed, ensure_stub, reset_stub

_TASKS: set[asyncio.Task] = set()


class SourceBody(BaseModel):
    source: str


class KillBody(BaseModel):
    reason: str = "dashboard button"


def create_dashboard(settings: Settings | None = None, services: Services | None = None) -> FastAPI:
    settings = settings or load_settings()
    services = services or build_services(settings)
    app = FastAPI(title="HijackRewind", docs_url=None, redoc_url=None)
    app.state.services = services
    html = Path(__file__).with_name("dashboard.html").read_text(encoding="utf-8")

    def current() -> Services:
        return app.state.services

    @app.get("/", response_class=HTMLResponse)
    async def index() -> str:
        return html

    @app.get("/api/health")
    async def health() -> dict:
        return {"ok": True}

    @app.get("/api/state")
    async def state() -> dict:
        services_now = current()
        snap = services_now.monitor.snapshot()
        return {
            "mode": services_now.settings.mode,
            "kill": {"tripped": services_now.kill.tripped, "reason": services_now.kill.reason},
            "run": snap,
        }

    @app.get("/api/audit")
    async def audit() -> dict:
        events = current().audit.read_all()[-12:]
        ok, detail = current().audit.verify()
        return {"ok": ok, "detail": detail, "events": events}

    @app.post("/api/kill")
    async def kill(body: KillBody) -> dict:
        services_now = current()
        run_id = services_now.monitor.run_id or "-"
        services_now.kill.trip(body.reason, audit=services_now.audit, run_id=run_id)
        services_now.monitor.update(decision="kill switch tripped", step="killed")
        return {"tripped": True}

    @app.post("/api/kill/reset")
    async def kill_reset() -> dict:
        current().kill.reset(audit=current().audit)
        return {"tripped": False}

    @app.post("/api/runs")
    async def start_run(body: SourceBody) -> dict:
        return await _spawn(current(), body.source)

    @app.post("/api/demo")
    async def start_demo() -> dict:
        services_now = current()
        if services_now.settings.mode == "live":
            raise HTTPException(status_code=409, detail="the dashboard demo button stays on the sandbox")
        ensure_stub(services_now.settings)
        services_now.github.base = services_now.settings.api_base()
        services_now.egress.api_host = services_now.settings.api_host()
        reset_stub(services_now.settings.stub_url, demo_seed())
        return await _spawn(services_now, str(demo_alert_path()))

    @app.post("/api/plans/{plan_id}/approve")
    async def approve(plan_id: str) -> dict:
        _track(asyncio.create_task(execute_saved_plan(current(), plan_id, approved=True)))
        return {"plan_id": plan_id, "approved": True}

    @app.post("/api/plans/{plan_id}/deny")
    async def deny(plan_id: str) -> dict:
        _track(asyncio.create_task(execute_saved_plan(current(), plan_id, approved=False)))
        return {"plan_id": plan_id, "approved": False}

    return app


async def _spawn(services: Services, source: str) -> dict:
    if services.kill.tripped:
        raise HTTPException(status_code=409, detail="kill switch is tripped; reset it before another run")
    if services.monitor.active:
        raise HTTPException(status_code=409, detail="a run is already in progress")
    _track(asyncio.create_task(run_source(source, services)))
    return {"started": True, "source": source}


def _track(task: asyncio.Task) -> None:
    _TASKS.add(task)
    task.add_done_callback(_TASKS.discard)
