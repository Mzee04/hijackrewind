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
