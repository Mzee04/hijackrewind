"""Outbound gate.

GitHub calls may go only to the configured API host, and only on allowlisted
paths. Lure URLs found in untrusted content are recorded and never opened.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from urllib.parse import urlparse

from hijackrewind.audit import AuditLog


class EgressDenied(Exception):
    def __init__(self, host: str, reason: str) -> None:
        super().__init__(reason)
        self.host = host
        self.reason = reason


_ALLOWED_PATHS: list[tuple[str, re.Pattern[str]]] = [
    ("GET", re.compile(r"^/user/keys$")),
    ("DELETE", re.compile(r"^/user/keys/\d+$")),
    ("GET", re.compile(r"^/user/emails$")),
    ("DELETE", re.compile(r"^/user/emails$")),
    ("GET", re.compile(r"^/user/gpg_keys$")),
    ("DELETE", re.compile(r"^/user/gpg_keys/\d+$")),
    ("GET", re.compile(r"^/user/ssh_signing_keys$")),
    ("DELETE", re.compile(r"^/user/ssh_signing_keys/\d+$")),
    ("GET", re.compile(r"^/repos/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+/keys$")),
    ("DELETE", re.compile(r"^/repos/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+/keys/\d+$")),
    ("GET", re.compile(r"^/repos/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+/hooks$")),
    ("DELETE", re.compile(r"^/repos/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+/hooks/\d+$")),
    ("GET", re.compile(r"^/repos/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+/collaborators$")),
    ("DELETE", re.compile(r"^/repos/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+/collaborators/[A-Za-z0-9-]{1,39}$")),
    ("GET", re.compile(r"^/repos/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+/branches/[^/]+/protection$")),
    ("DELETE", re.compile(r"^/repos/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+/branches/[^/]+/protection$")),
    ("PUT", re.compile(r"^/repos/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+/branches/[^/]+/protection$")),
    ("POST", re.compile(r"^/user/keys$")),
    ("POST", re.compile(r"^/repos/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+/keys$")),
    ("POST", re.compile(r"^/repos/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+/hooks$")),
    ("GET", re.compile(r"^/health$")),
]


@dataclass
class EgressLog:
    audit: AuditLog
    api_host: str
    run_id: str = "-"
    blocked: list[dict] = field(default_factory=list)

    def set_run(self, run_id: str) -> None:
        self.run_id = run_id

    def refuse(self, host: str, path: str, reason: str) -> None:
        self._block(host, path, reason)

    def assert_api(self, method: str, url: str) -> None:
        parsed = urlparse(url)
        host = (parsed.hostname or "").lower()
        if parsed.scheme not in {"http", "https"} or host != self.api_host:
            self._block(host or "unknown", parsed.path or "/", "api host is not the configured mutate host")
            raise EgressDenied(host or "unknown", "host is not the configured API")
        path = parsed.path or "/"
        if parsed.query:
            self._block(host, path, "refusing a query string on an API call")
            raise EgressDenied(host, "query string is not allowed on API calls")
        for allowed_method, pattern in _ALLOWED_PATHS:
            if method.upper() == allowed_method and pattern.match(path):
                return
        self._block(host, path, "path is outside the revert allowlist")
        raise EgressDenied(host, "path is outside the revert allowlist")

    def assert_operator_fetch(self, url: str) -> None:
        """GET of a page the operator named. Localhost only. No redirects later."""
        parsed = urlparse(url)
        host = (parsed.hostname or "").lower()
        if parsed.scheme not in {"http", "https"} or host not in {"127.0.0.1", "localhost"}:
            self._block(host or "unknown", parsed.path or "/", "ingest URL is not local")
            raise EgressDenied(host or "unknown", "only a local page can be fetched")

    def block_lure(self, *, kind: str, host: str, path: str = "/", recipient: str = "") -> dict:
        """Record an outbound attempt from untrusted content and do not open a socket."""
        detail = {
            "kind": kind,
            "host": host,
            "path": path if kind == "http" else "",
            "recipient_domain": recipient.split("@")[-1] if "@" in recipient else recipient,
        }
        self._block(host or detail["recipient_domain"] or "mail", path, f"untrusted {kind} lure")
        return detail

    def _block(self, host: str, path: str, reason: str) -> None:
        detail = {"host": host, "path": path, "reason": reason}
        self.blocked.append(detail)
        self.audit.append(
            run_id=self.run_id,
            actor="agent",
            action="egress_blocked",
            detail=detail,
        )


def repo_is_configured(path: str, owner: str, repo: str) -> bool:
    if "/repos/" not in path:
        return True
    if not owner or not repo:
        return False
    return path.startswith(f"/repos/{owner}/{repo}/")
