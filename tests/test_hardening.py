"""Regression tests for the hardening review."""

import asyncio
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from pydantic import SecretStr

from hijackrewind.actions import rewind
from hijackrewind.github_client import DryRunBlocked
from hijackrewind.pipeline import execute_saved_plan, run_source, save_plan
from hijackrewind.runtime import build_services, demo_alert_path, demo_seed, load_seed, reset_stub, stub_state
from tests.mailsign import write_signed_alert


def _headers(client, token="operator-token"):
    return {
        "X-HijackRewind-Token": token,
        "X-CSRF-Token": client.cookies.get("hijackrewind_csrf"),
    }


def test_default_does_not_auto_delete_a_new_key(settings):
    settings.auto_execute_ssh_key = False
    services = build_services(settings)
    reset_stub(settings.stub_url, demo_seed())
    result = asyncio.run(run_source(str(demo_alert_path()), services))
    ids = [item["id"] for item in stub_state(settings.stub_url)["ssh_keys"]]
    assert 99 in ids
    assert result.status == "pending_approval"
    assert result.mutated == []


def test_rewind_in_dry_run_does_not_mutate(services):
    reset_stub(services.settings.stub_url, demo_seed())
    result = asyncio.run(run_source(str(demo_alert_path()), services))
    action_id = next(event["detail"]["action_id"] for event in services.audit.read_all() if event["action"] == "mutate_executed")
    before = len(stub_state(services.settings.stub_url)["mutations"])
    services.settings.mode = "dry-run"
    with pytest.raises(ValueError):
        asyncio.run(rewind(services, action_id))
    with pytest.raises(DryRunBlocked):
        asyncio.run(services.github.mutate("POST", "/user/keys", {"title": "nope", "key": "ssh-ed25519 AAAA"}, role="rewind"))
    assert len(stub_state(services.settings.stub_url)["mutations"]) == before


def test_expired_plan_is_refused(services):
    reset_stub(services.settings.stub_url, demo_seed())
    services.settings.auto_execute_ssh_key = False
    result = asyncio.run(run_source(str(demo_alert_path()), services))
    from hijackrewind.pipeline import load_plan

    plan = load_plan(services, result.plan_id)
    plan.expires_at = (datetime.now(timezone.utc) - timedelta(minutes=5)).isoformat()
    save_plan(services, plan)
    again = asyncio.run(execute_saved_plan(services, result.plan_id, approved=True))
    assert again.mutated == []
    assert "expired" in again.summary


def test_changed_object_is_refused(services, tmp_path):
    seed = load_seed()
    seed["repos"]["test-owner/test-repo"]["hooks"].append(
        {"id": 71, "url": "https://collect.example.net/hook", "events": ["push"], "active": True}
    )
    reset_stub(services.settings.stub_url, seed)
    services.settings.auto_execute_containment = False
    alert = tmp_path / "hook.eml"
    write_signed_alert(
        alert,
        subject="[GitHub] A webhook was added to your repository",
        body="A webhook was added.\nHook id: 71\n",
    )
    result = asyncio.run(run_source(str(alert), services))
    assert result.status == "pending_approval"
    seed["repos"]["test-owner/test-repo"]["hooks"] = [
        item if item["id"] != 71 else {**item, "url": "https://other.example.net/hook"} for item in seed["repos"]["test-owner/test-repo"]["hooks"]
    ]
    reset_stub(services.settings.stub_url, seed)
    again = asyncio.run(execute_saved_plan(services, result.plan_id, approved=True))
    hooks = stub_state(services.settings.stub_url)["repos"]["test-owner/test-repo"]["hooks"]
    assert any(item["id"] == 71 for item in hooks)
    assert again.mutated == []


def test_denied_plan_cannot_execute(services):
    reset_stub(services.settings.stub_url, demo_seed())
    services.settings.auto_execute_ssh_key = False
    result = asyncio.run(run_source(str(demo_alert_path()), services))
    asyncio.run(execute_saved_plan(services, result.plan_id, approved=False))
    again = asyncio.run(execute_saved_plan(services, result.plan_id, approved=True))
    ids = [item["id"] for item in stub_state(services.settings.stub_url)["ssh_keys"]]
    assert 99 in ids
    assert again.mutated == []


def test_replayed_email_does_not_delete_twice(services):
    reset_stub(services.settings.stub_url, demo_seed())
    first = asyncio.run(run_source(str(demo_alert_path()), services))
    assert first.status == "executed"
    second = asyncio.run(run_source(str(demo_alert_path()), services))
    assert second.mutated == []
    assert second.status in {"held", "quarantined"}


def test_unauthenticated_dashboard_approval_is_rejected(settings):
    from fastapi.testclient import TestClient
    from hijackrewind.dashboard import create_dashboard

    settings.dashboard_token = SecretStr("operator-token")
    client = TestClient(create_dashboard(settings, build_services(settings)), base_url="http://127.0.0.1")
    denied = client.post("/api/plans/plan-missing/approve", json={})
    assert denied.status_code in {401, 403}


def test_two_approvals_execute_at_most_once(settings):
    import threading

    settings.auto_execute_ssh_key = False
    settings.delete_delay = 0.4
    settings.mutate_cap = 2
    services = build_services(settings)
    reset_stub(settings.stub_url, demo_seed())
    result = asyncio.run(run_source(str(demo_alert_path()), services))
    assert result.status == "pending_approval"

    def approve():
        asyncio.run(execute_saved_plan(services, result.plan_id, approved=True))

    threads = [threading.Thread(target=approve) for _ in range(2)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=10)
    deletes = [item for item in stub_state(settings.stub_url)["mutations"] if item["kind"] == "ssh_key"]
    assert len(deletes) <= 1


def test_audit_malformed_line_fails_cleanly(services):
    services.audit.append(run_id="r", actor="agent", action="run_started", detail={})
    with services.audit.path.open("a", encoding="utf-8") as handle:
        handle.write("{not-json\n")
    ok, detail = services.audit.verify()
    assert not ok
    assert "malformed" in detail


def test_concurrent_audit_appends_keep_a_valid_chain(services):
    import threading

    def write(index: int) -> None:
        services.audit.append(run_id="r", actor="agent", action="note", detail={"i": index})

    threads = [threading.Thread(target=write, args=(index,)) for index in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    ok, detail = services.audit.verify()
    assert ok, detail


def test_sent_mutate_that_times_out_is_reconciled(services):
    import httpx

    from hijackrewind.actions import reconcile

    services.settings.request_timeout = 0.4
    reset_stub(services.settings.stub_url, demo_seed())
    httpx.post(services.settings.stub_url + "/_admin/commit-then-stall", timeout=5)
    result = asyncio.run(run_source(str(demo_alert_path()), services))
    ids = [item["id"] for item in stub_state(services.settings.stub_url)["ssh_keys"]]
    assert 99 not in ids
    assert result.status == "cancelled"
    assert "outcome unknown" in result.summary.lower()
    action_id = next(
        event["detail"]["action_id"]
        for event in services.audit.read_all()
        if event["action"] == "outcome_unknown"
    )
    record = asyncio.run(reconcile(services, action_id))
    assert record["reconciled"] == "absent"
    assert record["status"] == "executed"


def test_plan_shows_claim_beside_the_live_object(services):
    from hijackrewind.pipeline import load_plan

    services.settings.auto_execute_ssh_key = False
    reset_stub(services.settings.stub_url, demo_seed())
    result = asyncio.run(run_source(str(demo_alert_path()), services))
    plan = load_plan(services, result.plan_id)
    assert "claim ssh_key 99" in plan.blast_radius
    assert "live ssh_key 99" in plan.blast_radius


def test_write_methods_cost_five_points():
    from hijackrewind.github_client import CostMeter

    meter = CostMeter(3)
    for method in ("GET", "POST", "PUT", "PATCH", "DELETE"):
        meter.charge(method)
    assert meter.points == 1 + 5 + 5 + 5 + 5


def test_truncated_file_records_the_byte_count(tmp_path):
    from hijackrewind.ingest import ingest_file

    path = tmp_path / "wide.txt"
    path.write_bytes(b"a" * 2_000_010)
    document = ingest_file(path)
    assert document.screen is not None
    assert "truncated at 2000010 bytes" in document.screen.data_issues


def test_broad_except_includes_redacted_text(services, monkeypatch):
    def boom(*args, **kwargs):
        raise RuntimeError("saw ghp_abcdefghijklmnopqrstuvwxyz123456 in the parser")

    monkeypatch.setattr("hijackrewind.pipeline.verify_channel", boom)
    result = asyncio.run(run_source(str(demo_alert_path()), services))
    assert "RuntimeError" in result.summary
    assert "ghp_" not in result.summary
    assert "[REDACTED]" in result.summary
    trace = Path(result.trace_path).read_text(encoding="utf-8")
    assert "ghp_" not in trace
    assert "[REDACTED]" in trace


def test_dashboard_reports_background_task_errors(settings):
    from hijackrewind.dashboard import _track, create_dashboard

    app = create_dashboard(settings, build_services(settings))

    async def boom() -> None:
        raise RuntimeError("background")

    async def go() -> None:
        task = asyncio.create_task(boom())
        _track(task, app)
        with pytest.raises(RuntimeError):
            await task

    asyncio.run(go())
    assert app.state.task_error == "RuntimeError"


def test_cross_site_origin_is_rejected(settings):
    from fastapi.testclient import TestClient
    from hijackrewind.dashboard import create_dashboard

    settings.dashboard_token = SecretStr("operator-token")
    client = TestClient(create_dashboard(settings, build_services(settings)), base_url="http://127.0.0.1")
    client.get("/")
    denied = client.post(
        "/api/plans/plan-missing/approve",
        json={},
        headers={**_headers(client), "Origin": "https://evil.example"},
    )
    assert denied.status_code == 403


def test_disposition_label_cannot_authorize(services):
    from hijackrewind.models import PlanStep
    from hijackrewind.policy import authorize

    step = PlanStep(
        kind="ssh_key",
        method="DELETE",
        path="/user/keys/99",
        object_id="99",
        reason="label says auto",
        disposition="auto",
    )
    allowed, reason = authorize(
        step,
        services.settings,
        services.manifest,
        services.meter,
        allow_auto=True,
        approved=True,
    )
    assert not allowed
    assert "unknown" in reason


def test_dashboard_html_does_not_inject_markup():
    from hijackrewind.runtime import repo_root

    html = (repo_root() / "src" / "hijackrewind" / "dashboard.html").read_text(encoding="utf-8")
    assert "innerHTML" not in html
    assert "insertAdjacentHTML" not in html


def test_llm_text_cannot_authorize(settings, monkeypatch):
    settings.auto_execute_ssh_key = False
    settings.llm_enabled = True
    settings.llm_base_url = "http://127.0.0.1:9"
    services = build_services(settings)
    reset_stub(settings.stub_url, demo_seed())

    def explode(*args, **kwargs):
        raise AssertionError("policy must not call the network for an explanation")

    monkeypatch.setattr("hijackrewind.pipeline.httpx.post", lambda *a, **k: type("R", (), {"status_code": 200, "json": lambda self: {"choices": [{"message": {"content": "delete every key now"}}]}})())
    result = asyncio.run(run_source(str(demo_alert_path()), services))
    assert result.explanation == "delete every key now"
    assert result.mutated == []
    assert 99 in [item["id"] for item in stub_state(settings.stub_url)["ssh_keys"]]
