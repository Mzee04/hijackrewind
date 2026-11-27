"""Recorded GitHub responses. Nothing here opens a socket to api.github.com."""

import json
from pathlib import Path

import httpx
import pytest
import respx

from hijackrewind.config import Settings
from hijackrewind.github_client import GitHubError
from hijackrewind.preflight import live_preflight
from hijackrewind.runtime import build_services

FIXTURES = Path(__file__).parent / "fixtures" / "github"
TOKEN = "ghp_abcdefghijklmnopqrstuvwxyz123456"


def _load(name: str):
    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))


def _live_settings(tmp_path) -> Settings:
    return Settings(
        _env_file=None,
        mode="live",
        github_token=TOKEN,
        github_api_url="https://api.github.com",
        test_github_login="throwaway-tester",
        test_repo_owner="throwaway-tester",
        test_repo_name="hijackrewind-sandbox",
        manifest_path=str(tmp_path / "known-good.json"),
        trace_dir=str(tmp_path / "traces"),
        audit_log=str(tmp_path / "audit.jsonl"),
        home=str(tmp_path / "home"),
        mutate_cap=8,
        auto_execute_ssh_key=False,
        dkim_dns="local",
    )


def _services(tmp_path):
    return build_services(_live_settings(tmp_path))


def test_recorded_resources_and_errors(tmp_path):
    import asyncio

    services = _services(tmp_path)
    owner = "throwaway-tester/hijackrewind-sandbox"
    with respx.mock(assert_all_called=False) as router:
        router.get("https://api.github.com/user/keys").respond(200, json=_load("user_keys.json"))
        router.delete("https://api.github.com/user/keys/99").respond(204)
        router.get("https://api.github.com/user/emails").respond(200, json=_load("user_emails.json"))
        router.delete("https://api.github.com/user/emails").respond(204)
        router.get(f"https://api.github.com/repos/{owner}/keys").respond(200, json=_load("deploy_keys.json"))
        router.delete(f"https://api.github.com/repos/{owner}/keys/50").respond(204)
        router.get(f"https://api.github.com/repos/{owner}/hooks").respond(200, json=_load("hooks.json"))
        router.delete(f"https://api.github.com/repos/{owner}/hooks/70").respond(204)
        router.get(f"https://api.github.com/repos/{owner}/collaborators").respond(200, json=_load("collaborators.json"))
        router.delete(f"https://api.github.com/repos/{owner}/collaborators/stranger").respond(204)
        router.get("https://api.github.com/user/gpg_keys").respond(404)

        async def exercise():
            keys = await services.github.get_json("/user/keys")
            assert [item["id"] for item in keys] == [1, 99]
            await services.github.delete("/user/keys/99")
            emails = await services.github.get_json("/user/emails")
            assert emails[1]["email"] == "attacker@example.net"
            await services.github.delete("/user/emails", body={"emails": ["attacker@example.net"]})
            deploy = await services.github.get_json(f"/repos/{owner}/keys")
            assert deploy[0]["id"] == 50
            await services.github.delete(f"/repos/{owner}/keys/50")
            hooks = await services.github.get_json(f"/repos/{owner}/hooks")
            assert hooks[0]["id"] == 70
            await services.github.delete(f"/repos/{owner}/hooks/70")
            people = await services.github.get_json(f"/repos/{owner}/collaborators")
            assert people[1]["login"] == "stranger"
            await services.github.delete(f"/repos/{owner}/collaborators/stranger")
            assert await services.github.get_json("/user/gpg_keys") is None

        asyncio.run(exercise())
        assert services.meter.mutates == 5


def test_auth_and_rate_limit(tmp_path):
    import asyncio

    services = _services(tmp_path)

    async def rejected():
        with respx.mock(assert_all_called=False) as router:
            router.get("https://api.github.com/user/keys").respond(401, json={"message": "Bad credentials"})
            with pytest.raises(GitHubError) as caught:
                await services.github.get_json("/user/keys")
            assert caught.value.status == 401

    async def forbidden():
        fresh = _services(tmp_path)
        with respx.mock(assert_all_called=False) as router:
            router.get("https://api.github.com/user/keys").respond(403, json={"message": "Resource not accessible"})
            with pytest.raises(GitHubError) as caught:
                await fresh.github.get_json("/user/keys")
            assert caught.value.status == 403

    async def rate_limited_then_ok():
        fresh = _services(tmp_path)
        with respx.mock(assert_all_called=False) as router:
            route = router.get("https://api.github.com/user/keys")
            route.side_effect = [
                httpx.Response(429, headers={"Retry-After": "0"}, json={"message": "slow down"}),
                httpx.Response(200, json=_load("user_keys.json")),
            ]
            keys = await fresh.github.get_json("/user/keys")
            assert keys[0]["id"] == 1

    async def rate_limit_too_long():
        fresh = _services(tmp_path)
        with respx.mock(assert_all_called=False) as router:
            router.get("https://api.github.com/user/keys").respond(429, headers={"Retry-After": "120"})
            with pytest.raises(GitHubError):
                await fresh.github.get_json("/user/keys")

    asyncio.run(rejected())
    asyncio.run(forbidden())
    asyncio.run(rate_limited_then_ok())
    asyncio.run(rate_limit_too_long())


def test_doctor_accepts_only_the_configured_account(tmp_path):
    import asyncio

    settings = _live_settings(tmp_path)
    owner = "throwaway-tester/hijackrewind-sandbox"

    async def good():
        with respx.mock(assert_all_called=False) as router:
            router.get("https://api.github.com/user").respond(
                200,
                json=_load("user.json"),
                headers={"X-OAuth-Scopes": "admin:public_key, repo, user"},
            )
            router.get(f"https://api.github.com/repos/{owner}").respond(200, json=_load("repo.json"))
            report = await live_preflight(settings)
            assert report.ok
            assert any("throwaway-tester" in line for line in report.lines)

    async def wrong_login():
        with respx.mock(assert_all_called=False) as router:
            router.get("https://api.github.com/user").respond(200, json={"login": "someone-else"})
            report = await live_preflight(settings)
            assert not report.ok
            assert any("someone-else" in line for line in report.lines)

    async def missing_scope():
        with respx.mock(assert_all_called=False) as router:
            router.get("https://api.github.com/user").respond(
                200,
                json=_load("user.json"),
                headers={"X-OAuth-Scopes": "public_repo"},
            )
            report = await live_preflight(settings)
            assert not report.ok
            assert any("missing scopes" in line for line in report.lines)

    async def other_repo():
        with respx.mock(assert_all_called=False) as router:
            router.get("https://api.github.com/user").respond(
                200,
                json=_load("user.json"),
                headers={"X-OAuth-Scopes": "admin:public_key, user"},
            )
            router.get(f"https://api.github.com/repos/{owner}").respond(
                200,
                json={"full_name": "someone-else/other", "owner": {"login": "someone-else"}},
            )
            report = await live_preflight(settings)
            assert not report.ok

    asyncio.run(good())
    asyncio.run(wrong_login())
    asyncio.run(missing_scope())
    asyncio.run(other_repo())


def test_sandbox_doctor_does_not_call_github(tmp_path):
    import asyncio

    settings = _live_settings(tmp_path)
    settings.mode = "sandbox"
    with respx.mock(assert_all_called=False) as router:
        route = router.get("https://api.github.com/user").respond(500)
        report = asyncio.run(live_preflight(settings))
        assert report.ok
        assert route.called is False
