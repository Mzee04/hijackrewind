"""GitHub-shaped list/delete stub for the sandbox.

Admin routes are for the operator and the tests. The agent's client refuses
any path that is not on the revert allowlist, including these.
"""

from __future__ import annotations

import asyncio
from typing import Any

from fastapi import FastAPI, Request, Response
from fastapi.responses import JSONResponse

CREATED = "2026-01-15T12:00:00Z"


class Box:
    def __init__(self) -> None:
        self.ssh_keys: dict[int, dict[str, Any]] = {}
        self.emails: dict[str, dict[str, Any]] = {}
        self.gpg_keys: dict[int, dict[str, Any]] = {}
        self.ssh_signing_keys: dict[int, dict[str, Any]] = {}
        self.repos: dict[str, dict[str, Any]] = {}
        self.mutations: list[dict[str, Any]] = []
        self.aborted: list[dict[str, Any]] = []
        self.fail_next: dict[str, Any] | None = None
        self.commit_then_stall: bool = False

    def reset(self, payload: dict[str, Any]) -> None:
        self.__init__()
        for item in payload.get("ssh_keys", []):
            self.ssh_keys[int(item["id"])] = _ssh(item)
        for item in payload.get("emails", []):
            self.emails[item["email"].lower()] = _email(item)
        for item in payload.get("gpg_keys", []):
            self.gpg_keys[int(item["id"])] = _ssh(item)
        for item in payload.get("ssh_signing_keys", []):
            self.ssh_signing_keys[int(item["id"])] = _ssh(item)
        for name, repo in payload.get("repos", {}).items():
            self.repos[name] = {
                "deploy_keys": {int(item["id"]): _ssh(item) for item in repo.get("deploy_keys", [])},
                "hooks": {int(item["id"]): _hook(item) for item in repo.get("hooks", [])},
                "collaborators": {item["login"]: _collab(item) for item in repo.get("collaborators", [])},
                "protections": dict(repo.get("protections", {})),
            }


def _ssh(item: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": int(item["id"]),
        "key": item.get("key", "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHijackRewindStubKeyOnly"),
        "title": item.get("title", ""),
        "created_at": item.get("created_at", CREATED),
        "verified": True,
        "read_only": bool(item.get("read_only", False)),
        "fingerprint": item.get("fingerprint", ""),
    }


def _email(item: dict[str, Any]) -> dict[str, Any]:
    return {
        "email": item["email"],
        "primary": bool(item.get("primary", False)),
        "verified": bool(item.get("verified", True)),
        "visibility": item.get("visibility", "private"),
    }


def _hook(item: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": int(item["id"]),
        "name": "web",
        "active": bool(item.get("active", True)),
        "events": item.get("events", ["push"]),
        "config": item.get("config") or {"url": item.get("url", ""), "content_type": "json"},
    }


def _collab(item: dict[str, Any]) -> dict[str, Any]:
    return {"login": item["login"], "role_name": item.get("role", "write")}


def _repo(box: Box, owner: str, repo: str) -> dict[str, Any]:
    return box.repos.setdefault(
        f"{owner}/{repo}",
        {"deploy_keys": {}, "hooks": {}, "collaborators": {}, "protections": {}},
    )


def create_stub() -> FastAPI:
    app = FastAPI(title="HijackRewind GitHub stub", docs_url=None, redoc_url=None)
    app.state.box = Box()

    def box() -> Box:
        return app.state.box

    def rate_headers() -> dict[str, str]:
        return {
            "X-RateLimit-Limit": "5000",
            "X-RateLimit-Remaining": "4999",
            "X-RateLimit-Resource": "core",
        }

    async def maybe_fail(path: str) -> Response | None:
        pending = box().fail_next
        if not pending or pending.get("path") != path:
            return None
        pending["times"] = int(pending.get("times", 1)) - 1
        if pending["times"] <= 0:
            box().fail_next = None
        headers = rate_headers()
        if pending.get("retry_after") is not None:
            headers["Retry-After"] = str(pending["retry_after"])
        return JSONResponse(
            {"message": "stub failure"},
            status_code=int(pending.get("status", 503)),
            headers=headers,
        )

    async def wait_or_abort(request: Request, kind: str, object_id: str) -> Response | None:
        raw = request.headers.get("x-hijackrewind-delay", "0")
        try:
            delay = float(raw)
        except ValueError:
            delay = 0.0

        def note_abort() -> None:
            box().aborted.append({"kind": kind, "id": object_id})

        # A zero delay must not touch the request body. is_disconnected()
        # can consume it, and a later request.json() would wait forever.
        if delay <= 0:
            return None
        try:
            elapsed = 0.0
            while elapsed < delay:
                if await request.is_disconnected():
                    note_abort()
                    return Response(status_code=499)
                await asyncio.sleep(0.05)
                elapsed += 0.05
            if await request.is_disconnected():
                note_abort()
                return Response(status_code=499)
        except asyncio.CancelledError:
            note_abort()
            raise
        return None

    @app.get("/health")
    async def health() -> dict[str, Any]:
        return {"ok": True, "service": "hijackrewind-github-stub"}

    @app.post("/_admin/reset")
    async def reset(payload: dict[str, Any]) -> dict[str, str]:
        box().reset(payload)
        return {"ok": "true"}

    @app.post("/_admin/fail-next")
    async def fail_next(payload: dict[str, Any]) -> dict[str, str]:
        box().fail_next = payload
        return {"ok": "true"}

    @app.post("/_admin/commit-then-stall")
    async def arm_commit_then_stall() -> dict[str, str]:
        """Apply the next SSH-key delete, then stall so the client can time out."""
        box().commit_then_stall = True
        return {"ok": "true"}

    @app.get("/_admin/state")
    async def admin_state() -> dict[str, Any]:
        current = box()
        return {
            "ssh_keys": list(current.ssh_keys.values()),
            "emails": list(current.emails.values()),
            "gpg_keys": list(current.gpg_keys.values()),
            "ssh_signing_keys": list(current.ssh_signing_keys.values()),
            "repos": {
                name: {
                    "deploy_keys": list(repo["deploy_keys"].values()),
                    "hooks": list(repo["hooks"].values()),
                    "collaborators": list(repo["collaborators"].values()),
                    "protections": repo["protections"],
                }
                for name, repo in current.repos.items()
            },
            "mutations": current.mutations,
            "aborted": current.aborted,
        }

    @app.get("/user/keys")
    async def list_keys() -> Response:
        failed = await maybe_fail("/user/keys")
        if failed:
            return failed
        return JSONResponse(list(box().ssh_keys.values()), headers=rate_headers())

    @app.delete("/user/keys/{key_id}")
    async def delete_key(key_id: int, request: Request) -> Response:
        if box().commit_then_stall:
            box().commit_then_stall = False
            box().ssh_keys.pop(key_id, None)
            box().mutations.append({"kind": "ssh_key", "id": key_id})
            try:
                await asyncio.sleep(30)
            except asyncio.CancelledError:
                raise
            return Response(status_code=499, headers=rate_headers())
        aborted = await wait_or_abort(request, "ssh_key", str(key_id))
        if aborted:
            return aborted
        box().ssh_keys.pop(key_id, None)
        box().mutations.append({"kind": "ssh_key", "id": key_id})
        return Response(status_code=204, headers=rate_headers())

    @app.get("/user/emails")
    async def list_emails() -> JSONResponse:
        return JSONResponse(list(box().emails.values()), headers=rate_headers())

    @app.delete("/user/emails")
    async def delete_emails(request: Request) -> Response:
        aborted = await wait_or_abort(request, "email", "batch")
        if aborted:
            return aborted
        payload = await request.json()
        for address in payload.get("emails", []):
            box().emails.pop(address.lower(), None)
            box().mutations.append({"kind": "email", "id": address})
        return Response(status_code=204, headers=rate_headers())

    @app.get("/user/gpg_keys")
    async def list_gpg() -> JSONResponse:
        return JSONResponse(list(box().gpg_keys.values()), headers=rate_headers())

    @app.delete("/user/gpg_keys/{key_id}")
    async def delete_gpg(key_id: int, request: Request) -> Response:
        aborted = await wait_or_abort(request, "gpg_key", str(key_id))
        if aborted:
            return aborted
        box().gpg_keys.pop(key_id, None)
        box().mutations.append({"kind": "gpg_key", "id": key_id})
        return Response(status_code=204, headers=rate_headers())

    @app.get("/user/ssh_signing_keys")
    async def list_signing() -> JSONResponse:
        return JSONResponse(list(box().ssh_signing_keys.values()), headers=rate_headers())

    @app.delete("/user/ssh_signing_keys/{key_id}")
    async def delete_signing(key_id: int, request: Request) -> Response:
        aborted = await wait_or_abort(request, "ssh_signing_key", str(key_id))
        if aborted:
            return aborted
        box().ssh_signing_keys.pop(key_id, None)
        box().mutations.append({"kind": "ssh_signing_key", "id": key_id})
        return Response(status_code=204, headers=rate_headers())

    @app.get("/repos/{owner}/{repo}/keys")
    async def list_deploy(owner: str, repo: str) -> JSONResponse:
        return JSONResponse(list(_repo(box(), owner, repo)["deploy_keys"].values()), headers=rate_headers())

    @app.delete("/repos/{owner}/{repo}/keys/{key_id}")
    async def delete_deploy(owner: str, repo: str, key_id: int, request: Request) -> Response:
        aborted = await wait_or_abort(request, "deploy_key", str(key_id))
        if aborted:
            return aborted
        _repo(box(), owner, repo)["deploy_keys"].pop(key_id, None)
        box().mutations.append({"kind": "deploy_key", "id": key_id})
        return Response(status_code=204, headers=rate_headers())

    @app.get("/repos/{owner}/{repo}/hooks")
    async def list_hooks(owner: str, repo: str) -> JSONResponse:
        return JSONResponse(list(_repo(box(), owner, repo)["hooks"].values()), headers=rate_headers())

    @app.delete("/repos/{owner}/{repo}/hooks/{hook_id}")
    async def delete_hook(owner: str, repo: str, hook_id: int, request: Request) -> Response:
        aborted = await wait_or_abort(request, "webhook", str(hook_id))
        if aborted:
            return aborted
        _repo(box(), owner, repo)["hooks"].pop(hook_id, None)
        box().mutations.append({"kind": "webhook", "id": hook_id})
        return Response(status_code=204, headers=rate_headers())

    @app.get("/repos/{owner}/{repo}/collaborators")
    async def list_collab(owner: str, repo: str) -> JSONResponse:
        return JSONResponse(list(_repo(box(), owner, repo)["collaborators"].values()), headers=rate_headers())

    @app.delete("/repos/{owner}/{repo}/collaborators/{login}")
    async def delete_collab(owner: str, repo: str, login: str, request: Request) -> Response:
        aborted = await wait_or_abort(request, "collaborator", login)
        if aborted:
            return aborted
        _repo(box(), owner, repo)["collaborators"].pop(login, None)
        box().mutations.append({"kind": "collaborator", "id": login})
        return Response(status_code=204, headers=rate_headers())

    @app.get("/repos/{owner}/{repo}/branches/{branch}/protection")
    async def get_protection(owner: str, repo: str, branch: str) -> Response:
        protection = _repo(box(), owner, repo)["protections"].get(branch)
        if protection is None:
            return JSONResponse({"message": "Not Found"}, status_code=404, headers=rate_headers())
        return JSONResponse(protection, headers=rate_headers())

    @app.post("/user/keys")
    async def create_key(payload: dict) -> JSONResponse:
        new_id = int(payload.get("id") or (max(box().ssh_keys) + 1 if box().ssh_keys else 1))
        item = _ssh({"id": new_id, "title": payload.get("title", ""), "key": payload.get("key", "")})
        box().ssh_keys[new_id] = item
        box().mutations.append({"kind": "ssh_key_restore", "id": new_id})
        return JSONResponse(item, status_code=201, headers=rate_headers())

    @app.post("/repos/{owner}/{repo}/keys")
    async def create_deploy(owner: str, repo: str, payload: dict) -> JSONResponse:
        store = _repo(box(), owner, repo)["deploy_keys"]
        new_id = int(payload.get("id") or (max(store) + 1 if store else 1))
        item = _ssh({"id": new_id, "title": payload.get("title", ""), "key": payload.get("key", ""), "read_only": payload.get("read_only", True)})
        store[new_id] = item
        box().mutations.append({"kind": "deploy_key_restore", "id": new_id})
        return JSONResponse(item, status_code=201, headers=rate_headers())

    @app.post("/repos/{owner}/{repo}/hooks")
    async def create_hook(owner: str, repo: str, payload: dict) -> JSONResponse:
        store = _repo(box(), owner, repo)["hooks"]
        new_id = int(payload.get("id") or (max(store) + 1 if store else 1))
        item = _hook({"id": new_id, "events": payload.get("events", ["push"]), "config": payload.get("config") or {}, "active": payload.get("active", True)})
        store[new_id] = item
        box().mutations.append({"kind": "webhook_restore", "id": new_id})
        return JSONResponse(item, status_code=201, headers=rate_headers())

    @app.put("/repos/{owner}/{repo}/branches/{branch}/protection")
    async def put_protection(owner: str, repo: str, branch: str, payload: dict) -> JSONResponse:
        _repo(box(), owner, repo)["protections"][branch] = payload
        box().mutations.append({"kind": "branch_protection_restore", "id": branch})
        return JSONResponse(payload, headers=rate_headers())

    @app.delete("/repos/{owner}/{repo}/branches/{branch}/protection")
    async def delete_protection(owner: str, repo: str, branch: str, request: Request) -> Response:
        aborted = await wait_or_abort(request, "branch_protection", branch)
        if aborted:
            return aborted
        _repo(box(), owner, repo)["protections"].pop(branch, None)
        box().mutations.append({"kind": "branch_protection", "id": branch})
        return Response(status_code=204, headers=rate_headers())

    return app


app = create_stub()
