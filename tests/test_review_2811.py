"""Regression tests from the 28 Nov review."""

import asyncio
import json
from pathlib import Path

from hijackrewind.actions import reconcile
from hijackrewind.config import Settings
from hijackrewind.pipeline import run_source
from hijackrewind.runtime import demo_alert_path, demo_seed, forget_demo_alert, reset_stub


def test_generic_env_names_do_not_leak_into_settings(monkeypatch):
    monkeypatch.setenv("HOME", "/somewhere/else")
    monkeypatch.setenv("MODE", "live")
    monkeypatch.delenv("HIJACKREWIND_HOME", raising=False)
    monkeypatch.delenv("HIJACKREWIND_MODE", raising=False)
    settings = Settings(_env_file=None)
    assert settings.home == ".hijackrewind"
    assert settings.mode == "sandbox"
    monkeypatch.setenv("HIJACKREWIND_HOME", "/tmp/hr-home")
    assert Settings(_env_file=None).home == "/tmp/hr-home"


def _unknown_action(services, path: str, before: dict) -> str:
    directory = Path(services.settings.home) / "actions"
    directory.mkdir(parents=True, exist_ok=True)
    record = {"id": "act-review", "run_id": "run-x", "plan_id": "plan-x", "kind": "deploy_key",
              "method": "DELETE", "path": path, "before": before, "after": {"outcome": "unknown"},
              "reverse_method": None, "reverse_path": None, "reverse_body": None, "status": "outcome_unknown"}
    (directory / "act-review.json").write_text(json.dumps(record), encoding="utf-8")
    return "act-review"


def test_reconcile_sees_a_deploy_key_that_is_still_present(services):
    # Deploy key 50 is in the seed. A DELETE that never landed must not be reported as done.
    action_id = _unknown_action(services, "/repos/test-owner/test-repo/keys/50", {"id": 50})
    record = asyncio.run(reconcile(services, action_id))
    assert record["reconciled"] == "present"
    assert record["status"] == "reconciled"


def test_reconcile_sees_an_absent_deploy_key(services):
    action_id = _unknown_action(services, "/repos/test-owner/test-repo/keys/4242", {"id": 4242})
    record = asyncio.run(reconcile(services, action_id))
    assert record["reconciled"] == "absent"
    assert record["status"] == "executed"


def test_demo_fixture_can_run_twice(services):
    for _ in range(2):
        reset_stub(services.settings.stub_url, demo_seed())
        forget_demo_alert(services.settings)
        result = asyncio.run(run_source(str(demo_alert_path()), services))
        assert result.status == "executed", result.summary


def test_replay_is_still_refused_without_the_demo_reset(services):
    reset_stub(services.settings.stub_url, demo_seed())
    asyncio.run(run_source(str(demo_alert_path()), services))
    reset_stub(services.settings.stub_url, demo_seed())
    again = asyncio.run(run_source(str(demo_alert_path()), services))
    assert again.status != "executed"


def test_dashboard_script_ids_exist():
    import re

    html = (Path(__file__).resolve().parents[1] / "src" / "hijackrewind" / "dashboard.html").read_text(encoding="utf-8")
    assert "const $ = (id) => document.getElementById(id);" in html
    ids = set(re.findall(r'id="([^"]+)"', html))
    used = set(re.findall(r'\$\("([^"]+)"\)', html))
    assert used, "dashboard script uses no element ids"
    assert used <= ids, f"script references missing ids: {sorted(used - ids)}"


def test_cli_reconcile_reports_a_tripped_switch_cleanly(services, monkeypatch, capsys):
    from hijackrewind import cli

    monkeypatch.setattr(cli, "load_settings", lambda: services.settings)
    _unknown_action(services, "/repos/test-owner/test-repo/keys/50", {"id": 50})
    services.kill.trip("test")
    try:
        assert cli.main(["reconcile", "act-review"]) == 3
    finally:
        services.kill.reset()
    assert "kill --reset" in capsys.readouterr().err


def test_dashboard_shows_a_refused_request():
    html = (Path(__file__).resolve().parents[1] / "src" / "hijackrewind" / "dashboard.html").read_text(encoding="utf-8")
    assert 'id="request-error"' in html
    assert "if (!response.ok)" in html
    assert '$("request-error").textContent = message;' in html


def test_wrong_dashboard_token_is_401_with_a_reason(settings):
    from fastapi.testclient import TestClient
    from pydantic import SecretStr

    from hijackrewind.dashboard import create_dashboard

    settings.dashboard_token = SecretStr("right-token")
    client = TestClient(create_dashboard(settings), base_url="http://127.0.0.1")
    client.get("/")
    response = client.post(
        "/api/kill",
        json={"reason": "x"},
        headers={"X-HijackRewind-Token": "wrong", "X-CSRF-Token": client.cookies.get("hijackrewind_csrf")},
    )
    assert response.status_code == 401
    assert response.json()["detail"] == "dashboard token was rejected"


def test_signed_github_notification_cannot_start_a_plan(services, tmp_path):
    from tests.mailsign import write_signed_alert

    reset_stub(services.settings.stub_url, demo_seed())
    alert = tmp_path / "notification.eml"
    write_signed_alert(alert, subject="[GitHub] A new public key was added to your account",
                       body="A new public key was added.\nKey id: 99\n", local="notifications")
    result = asyncio.run(run_source(str(alert), services))
    assert result.status != "executed"
    assert result.mutated == []
    reasons = [e["detail"].get("reason") for e in services.audit.read_all() if e["action"] == "channel_rejected"]
    assert reasons == ["sender address is not an account-alert sender"]


def test_webhook_rewind_body_drops_the_masked_secret(services, tmp_path):
    from hijackrewind.runtime import load_seed, stub_state
    from tests.mailsign import write_signed_alert

    seed = load_seed()
    seed["repos"]["test-owner/test-repo"]["hooks"].append(
        {"id": 88, "events": ["push"], "active": True,
         "config": {"url": "https://collector.evil.test/x", "content_type": "json", "secret": "********"}}
    )
    reset_stub(services.settings.stub_url, seed)
    alert = tmp_path / "hook.eml"
    write_signed_alert(alert, subject="[GitHub] A webhook was added to your repository", body="A webhook was added.\nHook id: 88\n")
    asyncio.run(run_source(str(alert), services))
    records = [json.loads(p.read_text()) for p in (Path(services.settings.home) / "actions").glob("*.json")]
    hook = next(r for r in records if r["kind"] == "webhook")
    assert "secret" not in hook["reverse_body"]["config"]
    assert hook["reverse_body"]["config"]["url"] == "https://collector.evil.test/x"


def test_pending_record_needs_reconcile_before_rewind(services):
    from hijackrewind.policy import authorize_rewind

    ok, reason = authorize_rewind({"status": "pending", "reverse_method": "POST", "reverse_path": "/user/keys"}, services.settings)
    assert not ok and "reconcile" in reason


def test_dot_segments_are_refused():
    import pytest

    from hijackrewind.audit import AuditLog
    from hijackrewind.egress import EgressDenied, EgressLog

    import tempfile
    log = EgressLog(audit=AuditLog(Path(tempfile.mkdtemp()) / "a.jsonl"), api_host="127.0.0.1")
    with pytest.raises(EgressDenied):
        log.assert_api("DELETE", "http://127.0.0.1:8088/repos/test-owner/test-repo/branches/../protection")
