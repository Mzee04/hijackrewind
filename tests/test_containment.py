import asyncio

from hijackrewind.actions import rewind
from hijackrewind.email_auth import is_lookalike
from hijackrewind.ingest import ingest_file
from hijackrewind.pipeline import execute_saved_plan, run_source
from hijackrewind.runtime import load_seed, reset_stub, stub_state
from tests.mailsign import write_signed_alert


def test_unicode_lookalike_domain():
    assert is_lookalike("gith\u043eb.com", ["github.com"])
    assert not is_lookalike("github.com", ["github.com"])


def test_malformed_email_and_huge_header_do_not_crash(services, tmp_path):
    broken = tmp_path / "broken.eml"
    broken.write_bytes(b"\xff\xfe not an email \x00")
    result = asyncio.run(run_source(str(broken), services))
    assert result.status in {"held", "failed", "quarantined"}
    assert result.mutated == []

    huge = tmp_path / "huge.eml"
    huge.write_text(
        "From: person@example.com\nSubject: " + ("A" * 200_000) + "\n\nHello\n",
        encoding="utf-8",
    )
    document = ingest_file(huge)
    assert len(document.subject) <= 300
    result = asyncio.run(run_source(str(huge), services))
    assert result.mutated == []


def test_deploy_key_auto_then_rewind(services, tmp_path):
    seed = load_seed()
    seed["repos"]["test-owner/test-repo"]["deploy_keys"].append(
        {"id": 77, "title": "stranger", "key": "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIStrangerDeployKey", "read_only": True}
    )
    reset_stub(services.settings.stub_url, seed)
    alert = tmp_path / "deploy.eml"
    write_signed_alert(
        alert,
        subject="[GitHub] A deploy key was added to your repository",
        body="A deploy key was added.\nKey id: 77\n",
    )
    result = asyncio.run(run_source(str(alert), services))
    ids = [item["id"] for item in stub_state(services.settings.stub_url)["repos"]["test-owner/test-repo"]["deploy_keys"]]
    assert result.status == "executed"
    assert 77 not in ids
    assert 50 in ids
    action_id = next(
        event["detail"]["action_id"]
        for event in services.audit.read_all()
        if event["action"] == "mutate_executed"
    )
    asyncio.run(rewind(services, action_id))
    titles = [item["title"] for item in stub_state(services.settings.stub_url)["repos"]["test-owner/test-repo"]["deploy_keys"]]
    assert "stranger" in titles
    record = asyncio.run(rewind(services, action_id))
    assert record["status"] == "rolled_back"


def test_unknown_webhook_is_removed(services, tmp_path):
    seed = load_seed()
    seed["repos"]["test-owner/test-repo"]["hooks"].append(
        {"id": 71, "url": "https://collect.example.net/hook", "events": ["push"]}
    )
    reset_stub(services.settings.stub_url, seed)
    alert = tmp_path / "hook.eml"
    write_signed_alert(
        alert,
        subject="[GitHub] A webhook was added to your repository",
        body="A webhook was added.\nHook id: 71\n",
    )
    result = asyncio.run(run_source(str(alert), services))
    hooks = stub_state(services.settings.stub_url)["repos"]["test-owner/test-repo"]["hooks"]
    assert result.status == "executed"
    assert all(item["id"] != 71 for item in hooks)
    assert any(item["id"] == 70 for item in hooks)


def test_branch_protection_downgrade_is_restored(services, tmp_path):
    seed = load_seed()
    seed["repos"]["test-owner/test-repo"]["protections"] = {}
    reset_stub(services.settings.stub_url, seed)
    alert = tmp_path / "prot.eml"
    write_signed_alert(
        alert,
        subject="[GitHub] Branch protection changed",
        body="Branch protection was removed on branch main.\n",
    )
    result = asyncio.run(run_source(str(alert), services))
    protection = stub_state(services.settings.stub_url)["repos"]["test-owner/test-repo"]["protections"]["main"]
    assert result.status == "executed"
    assert protection["required_pull_request_reviews"]["required_approving_review_count"] == 1


def test_oauth_grant_is_planned_and_not_sent(services, tmp_path):
    alert = tmp_path / "oauth.eml"
    write_signed_alert(
        alert,
        subject="[GitHub] An OAuth app grant was added",
        body="An authorized OAuth grant was added to your account.\n",
    )
    result = asyncio.run(run_source(str(alert), services))
    assert result.mutated == []
    assert result.status == "held"
    assert any(event["action"] == "action_planned" for event in services.audit.read_all())
    assert stub_state(services.settings.stub_url)["mutations"] == []


def test_rerunning_a_plan_does_not_delete_twice(services):
    from hijackrewind.runtime import demo_alert_path, demo_seed

    reset_stub(services.settings.stub_url, demo_seed())
    result = asyncio.run(run_source(str(demo_alert_path()), services))
    assert result.status == "executed"
    before = len(stub_state(services.settings.stub_url)["mutations"])
    again = asyncio.run(execute_saved_plan(services, result.plan_id, approved=True))
    assert again.status == "executed"
    assert len(stub_state(services.settings.stub_url)["mutations"]) == before
