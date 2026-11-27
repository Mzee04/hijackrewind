import asyncio

import httpx
import pytest

from hijackrewind.pipeline import run_source
from hijackrewind.runtime import demo_alert_path, demo_seed, reset_stub


def test_retries_5xx_then_succeeds(services):
    httpx.post(
        services.settings.stub_url + "/_admin/fail-next",
        json={"path": "/user/keys", "status": 503, "retry_after": "0", "times": 2},
        timeout=5,
    ).raise_for_status()
    reset_stub(services.settings.stub_url, demo_seed())
    # fail-next is cleared by reset; set it after seeding.
    httpx.post(
        services.settings.stub_url + "/_admin/fail-next",
        json={"path": "/user/keys", "status": 503, "retry_after": "0", "times": 2},
        timeout=5,
    ).raise_for_status()
    result = asyncio.run(run_source(str(demo_alert_path()), services))
    assert result.status == "executed"


def test_request_timeout_stops_the_call(services):
    reset_stub(services.settings.stub_url, demo_seed())
    services.settings.request_timeout = 0.2
    services.settings.delete_delay = 2

    async def attempt():
        from hijackrewind.github_client import OutcomeUnknown

        with pytest.raises(OutcomeUnknown):
            await services.github.delete("/user/keys/99")

    asyncio.run(attempt())


def test_kill_records_an_in_flight_cancellation(settings):
    from hijackrewind.runtime import build_services

    reset_stub(settings.stub_url, demo_seed())
    settings.delete_delay = 2
    services = build_services(settings)

    async def scenario():
        task = asyncio.create_task(run_source(str(demo_alert_path()), services))
        for _ in range(80):
            if services.monitor.step == "execute":
                break
            await asyncio.sleep(0.05)
        await asyncio.sleep(0.3)
        services.kill.trip("reliability", audit=services.audit, run_id=services.monitor.run_id or "-")
        return await task

    result = asyncio.run(scenario())
    assert result.status == "cancelled"
    actions = [event["action"] for event in services.audit.read_all()]
    assert "tool_cancelled" in actions
    cancelled = next(event for event in services.audit.read_all() if event["action"] == "tool_cancelled")
    assert cancelled["detail"]["state"] == "in_flight"
    assert cancelled["detail"]["method"] == "DELETE"


def test_missing_from_field_does_not_mutate(services, tmp_path):
    path = tmp_path / "nofrom.eml"
    path.write_text("Subject: hello\n\nNo sender\n", encoding="utf-8")
    result = asyncio.run(run_source(str(path), services))
    assert result.mutated == []
