"""One HTTP client for GitHub or the local stub.

Timeouts, a kill-switch race, rate-limit handling, and the path allowlist
all live here. A DELETE that loses the race is cancelled, not completed.
"""

from __future__ import annotations

import asyncio
import random
from typing import Any

import httpx

from hijackrewind.config import Settings
from hijackrewind.egress import EgressDenied, EgressLog, repo_is_configured
from hijackrewind.killswitch import KillSwitch, ToolCancelled
from hijackrewind.monitor import Monitor


class GitHubError(Exception):
    def __init__(self, message: str, status: int | None = None) -> None:
        super().__init__(message)
        self.status = status


class MutateCapExceeded(GitHubError):
    pass


class CostMeter:
    def __init__(self, cap: int) -> None:
        self.cap = cap
        self.points = 0
        self.mutates = 0
        self.remaining: int | None = None

    def charge(self, method: str) -> None:
        self.points += 5 if method.upper() == "DELETE" else 1

    def can_mutate(self) -> bool:
        return self.mutates < self.cap

    def mark_mutate(self) -> None:
        if not self.can_mutate():
            raise MutateCapExceeded("per-run mutate cap reached")
        self.mutates += 1


class GitHubClient:
    def __init__(
        self,
        settings: Settings,
        kill: KillSwitch,
        egress: EgressLog,
        meter: CostMeter,
        monitor: Monitor | None = None,
    ) -> None:
        self.settings = settings
        self.kill = kill
        self.egress = egress
        self.meter = meter
        self.monitor = monitor
        self.base = settings.api_base()

    async def get_json(self, path: str) -> Any:
        response = await self._request("GET", path, mutate=False)
        if response.status_code == 404:
            return None
        return response.json()

    async def delete(self, path: str, body: dict | None = None) -> str:
        return await self.mutate("DELETE", path, body)

    async def mutate(self, method: str, path: str, body: dict | None = None, *, count_cap: bool = True) -> str:
        if method not in {"DELETE", "PUT", "POST"}:
            raise GitHubError(f"{method} is not a mutate this client will send")
        if count_cap:
            if not self.meter.can_mutate():
                raise MutateCapExceeded("per-run mutate cap reached")
            self.meter.mark_mutate()
        response = await self._request(method, path, mutate=True, json_body=body)
        if method == "DELETE" and response.status_code == 404:
            return "absent"
        if response.status_code not in {200, 201, 204}:
            raise GitHubError(f"{method} failed with HTTP {response.status_code}", response.status_code)
        return "done"

    async def _request(
        self,
        method: str,
        path: str,
        *,
        mutate: bool,
        json_body: dict | None = None,
        _retried: bool = False,
    ) -> httpx.Response:
        self.kill.raise_if_tripped()
        if not repo_is_configured(path, self.settings.test_repo_owner, self.settings.test_repo_name):
            self.egress.refuse(self.settings.api_host(), path, "repo is outside the configured test repository")
            raise EgressDenied(self.settings.api_host(), "repo is outside the configured test repository")
        url = self.base + path
        self.egress.assert_api(method, url)
        headers = {"Accept": "application/vnd.github+json", "User-Agent": "HijackRewind"}
        if self.settings.mode == "live":
            if not self.settings.github_token:
                raise GitHubError("live mode needs GITHUB_TOKEN in the environment")
            headers["Authorization"] = f"Bearer {self.settings.github_token}"
        if mutate and self.settings.uses_stub() and self.settings.delete_delay > 0:
            headers["X-HijackRewind-Delay"] = str(self.settings.delete_delay)
        attempt = 0
        while True:
            try:
                response = await self._send(method, url, headers=headers, json_body=json_body)
            except ToolCancelled:
                if self.monitor:
                    self.monitor.tool(f"{method} {path}", "cancelled")
                self.egress.audit.append(
                    run_id=self.egress.run_id,
                    actor="kill_switch",
                    action="tool_cancelled",
                    detail={"method": method, "path": path, "state": "in_flight"},
                )
                raise
            self._read_rate(response)
            self.meter.charge(method)
            if self.monitor:
                self.monitor.cost_points = self.meter.points
                self.monitor.tool(f"{method} {path}", str(response.status_code))
            if response.status_code == 401:
                raise GitHubError("GitHub rejected the token", 401)
            retryable = response.status_code in {429, 500, 502, 503}
            if retryable and not mutate and attempt < 2 and not _retried:
                delay = self._retry_delay(response, attempt)
                if delay is None:
                    raise GitHubError("GitHub rate limit or upstream error; failing closed", response.status_code)
                await asyncio.sleep(delay)
                self.kill.raise_if_tripped()
                attempt += 1
                continue
            if response.status_code >= 400 and response.status_code != 404:
                raise GitHubError(f"HTTP {response.status_code} from the API", response.status_code)
            return response

    def _retry_delay(self, response: httpx.Response, attempt: int) -> float | None:
        header = response.headers.get("retry-after")
        if header is not None:
            try:
                delay = float(header)
            except ValueError:
                return None
        else:
            delay = 0.05 * (2**attempt) + random.uniform(0, 0.02)
        if delay < 0 or delay > self.settings.max_retry_wait:
            return None
        return delay

    def _read_rate(self, response: httpx.Response) -> None:
        remaining = response.headers.get("x-ratelimit-remaining")
        if remaining is not None and remaining.isdigit():
            self.meter.remaining = int(remaining)

    async def _send(self, method: str, url: str, *, headers: dict[str, str], json_body: dict | None) -> httpx.Response:
        self.kill.raise_if_tripped()
        timeout = httpx.Timeout(self.settings.request_timeout, connect=min(5.0, self.settings.request_timeout))
        client = httpx.AsyncClient(timeout=timeout, follow_redirects=False)
        try:
            send_task = asyncio.create_task(client.request(method, url, headers=headers, json=json_body))
            kill_task = asyncio.create_task(self.kill.wait())
            done, _pending = await asyncio.wait({send_task, kill_task}, return_when=asyncio.FIRST_COMPLETED)
            if self.kill.tripped and not send_task.done():
                send_task.cancel()
                try:
                    await send_task
                except (asyncio.CancelledError, httpx.HTTPError):
                    pass
                raise ToolCancelled(self.kill.reason or "in-flight HTTP cancelled")
            kill_task.cancel()
            try:
                await kill_task
            except asyncio.CancelledError:
                pass
            if send_task.cancelled():
                raise ToolCancelled(self.kill.reason or "in-flight HTTP cancelled")
            response = send_task.result()
            if self.kill.tripped or response.status_code == 499:
                raise ToolCancelled(self.kill.reason or "in-flight HTTP cancelled")
            if response.status_code in {301, 302, 303, 307, 308}:
                location = response.headers.get("location", "")
                raise GitHubError(f"refusing redirect to {location.split('?')[0]}")
            return response
        finally:
            await client.aclose()
