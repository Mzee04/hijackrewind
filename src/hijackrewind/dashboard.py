"""Local monitoring page. Same process as the kill switch and the pipeline."""

from __future__ import annotations

import asyncio
import secrets
from pathlib import Path
from urllib.parse import urlparse

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse
from pydantic import BaseModel

from hijackrewind.config import Settings, load_settings, reveal
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
    app.state.csrf = secrets.token_urlsafe(24)
    app.state.task_error = ""
    html = Path(__file__).with_name("dashboard.html").read_text(encoding="utf-8")
    html = html.replace("<!--CSRF-->", app.state.csrf)

    def _guard(request: Request, *, mutate: bool) -> None:
        host = (request.headers.get("host") or "").split(":")[0]
        if host not in {"127.0.0.1", "localhost"}:
            raise HTTPException(status_code=403, detail="dashboard host is not local")
        origin = request.headers.get("origin")
        if origin:
            origin_host = (urlparse(origin).hostname or "").lower()
            if origin_host not in {"127.0.0.1", "localhost"}:
                raise HTTPException(status_code=403, detail="dashboard origin is not local")
        if not mutate:
            return
        token = reveal(current().settings.dashboard_token)
        if not token:
            raise HTTPException(status_code=401, detail="dashboard token is not configured")
        if request.headers.get("x-hijackrewind-token") != token:
            raise HTTPException(status_code=401, detail="dashboard token was rejected")
        if request.headers.get("x-csrf-token") != app.state.csrf:
            raise HTTPException(status_code=403, detail="csrf token was rejected")
        if current().settings.mode == "live" and not token:
            raise HTTPException(status_code=403, detail="live dashboard requires a configured token")

    def current() -> Services:
        return app.state.services

    @app.get("/", response_class=HTMLResponse)
    async def index() -> HTMLResponse:
        response = HTMLResponse(html)
        response.set_cookie("hijackrewind_csrf", app.state.csrf, httponly=False, samesite="strict")
        return response

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
            "task_error": app.state.task_error,
            "csrf": app.state.csrf,
        }

    @app.get("/api/audit")
    async def audit() -> dict:
        events = current().audit.read_all()[-40:]
        ok, detail = current().audit.verify()
        return {"ok": ok, "detail": detail, "events": events}

    @app.post("/api/kill")
    async def kill(body: KillBody, request: Request) -> dict:
        _guard(request, mutate=True)
        services_now = current()
        run_id = services_now.monitor.run_id or "-"
        services_now.kill.trip(body.reason, audit=services_now.audit, run_id=run_id)
        services_now.monitor.update(decision="kill switch tripped", step="killed")
        return {"tripped": True}

    @app.post("/api/kill/reset")
    async def kill_reset(request: Request) -> dict:
        _guard(request, mutate=True)
        current().kill.reset(audit=current().audit)
        return {"tripped": False}

    @app.post("/api/runs")
    async def start_run(body: SourceBody, request: Request) -> dict:
        _guard(request, mutate=True)
        return await _spawn(app, current(), body.source)

    @app.post("/api/demo")
    async def start_demo(request: Request) -> dict:
        _guard(request, mutate=True)
        services_now = current()
        if services_now.settings.mode == "live":
            raise HTTPException(status_code=409, detail="the dashboard demo button stays on the sandbox")
        ensure_stub(services_now.settings)
        services_now.github.base = services_now.settings.api_base()
        services_now.egress.api_host = services_now.settings.api_host()
        reset_stub(services_now.settings.stub_url, demo_seed())
        return await _spawn(app, services_now, str(demo_alert_path()))

    @app.post("/api/plans/{plan_id}/approve")
    async def approve(plan_id: str, request: Request) -> dict:
        _guard(request, mutate=True)
        _track(asyncio.create_task(execute_saved_plan(current(), plan_id, approved=True)), app)
        return {"plan_id": plan_id, "approved": True}

    @app.post("/api/plans/{plan_id}/deny")
    async def deny(plan_id: str, request: Request) -> dict:
        _guard(request, mutate=True)
        _track(asyncio.create_task(execute_saved_plan(current(), plan_id, approved=False)), app)
        return {"plan_id": plan_id, "approved": False}

    return app


async def _spawn(app: FastAPI, services: Services, source: str) -> dict:
    if services.kill.tripped:
        raise HTTPException(status_code=409, detail="kill switch is tripped; reset it before another run")
    if services.monitor.active:
        raise HTTPException(status_code=409, detail="a run is already in progress")
    _track(asyncio.create_task(run_source(source, services)), app)
    return {"started": True, "source": source}


def _track(task: asyncio.Task, app: FastAPI | None = None) -> None:
    _TASKS.add(task)

    def _done(finished: asyncio.Task) -> None:
        _TASKS.discard(finished)
        if finished.cancelled():
            return
        error = finished.exception()
        if error is not None and app is not None:
            app.state.task_error = type(error).__name__

    task.add_done_callback(_done)
