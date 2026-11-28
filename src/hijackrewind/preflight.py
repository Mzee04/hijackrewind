"""Live-mode checks. They never run in the sandbox default.

The token is sent only to api.github.com. The login and the repository must
match the operator's configured test account. This module does not list the
token's other repositories.
"""

from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import urlparse

import httpx

from hijackrewind.config import Settings, reveal

_REQUIRED_SCOPES = ("admin:public_key", "user")


@dataclass(frozen=True)
class PreflightReport:
    ok: bool
    lines: tuple[str, ...]


async def live_preflight(settings: Settings) -> PreflightReport:
    if settings.mode != "live":
        return PreflightReport(
            True,
            (
                f"mode: {settings.mode}",
                "live preflight skipped",
                f"dkim: {settings.dkim_mode()}",
                "github token: " + ("set" if reveal(settings.github_token) else "unset"),
            ),
        )
    host = (urlparse(settings.github_api_url).hostname or "").lower()
    if host != "api.github.com":
        return PreflightReport(False, ("live mode only calls api.github.com",))
    if not reveal(settings.github_token):
        return PreflightReport(False, ("GITHUB_TOKEN is unset",))
    if not settings.test_github_login:
        return PreflightReport(False, ("TEST_GITHUB_LOGIN is unset",))
    if not settings.test_repo_owner or not settings.test_repo_name:
        return PreflightReport(False, ("TEST_REPO_OWNER and TEST_REPO_NAME are required",))
    headers = {
        "Accept": "application/vnd.github+json",
        "Authorization": f"Bearer {reveal(settings.github_token)}",
        "User-Agent": "HijackRewind",
    }
    base = settings.github_api_url.rstrip("/")
    async with httpx.AsyncClient(timeout=httpx.Timeout(10.0, connect=5.0), follow_redirects=False) as client:
        user = await client.get(f"{base}/user", headers=headers)
        if user.status_code == 401:
            return PreflightReport(False, ("token was rejected (HTTP 401)",))
        if user.status_code != 200:
            return PreflightReport(False, (f"/user returned HTTP {user.status_code}",))
        login = str(user.json().get("login", ""))
        if login.lower() != settings.test_github_login.lower():
            return PreflightReport(
                False,
                (f"token login {login} is not the configured test account {settings.test_github_login}",),
            )
        scope_header = user.headers.get("x-oauth-scopes", "")
        scope_line = "scope header absent; confirm the fine-grained token only covers this account and test repo"
        if scope_header.strip():
            have = {part.strip() for part in scope_header.split(",") if part.strip()}
            missing = [scope for scope in _REQUIRED_SCOPES if scope not in have]
            if missing:
                return PreflightReport(False, (f"token is missing scopes: {', '.join(missing)}",))
            scope_line = "scopes: " + ", ".join(sorted(have))
        expected = f"{settings.test_repo_owner}/{settings.test_repo_name}"
        repo = await client.get(f"{base}/repos/{expected}", headers=headers)
        if repo.status_code == 404:
            return PreflightReport(False, (f"test repo {expected} was not found for this token",))
        if repo.status_code != 200:
            return PreflightReport(False, (f"test repo returned HTTP {repo.status_code}",))
        body = repo.json()
        full_name = str(body.get("full_name", ""))
        owner = str((body.get("owner") or {}).get("login", ""))
        if full_name.lower() != expected.lower() or owner.lower() != settings.test_repo_owner.lower():
            return PreflightReport(False, (f"repository {full_name or owner} is outside the configured test repo",))
    return PreflightReport(
        True,
        (
            "mode: live",
            f"account: {login}",
            f"repo: {full_name}",
            scope_line,
            f"dkim: {settings.dkim_mode()}",
        ),
    )
