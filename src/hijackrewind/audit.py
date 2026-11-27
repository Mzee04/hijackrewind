"""Append-only hash-chained audit log.

The public API can append and verify. It cannot edit or delete events.
"""

from __future__ import annotations

import fcntl
import hashlib
import hmac
import json
import os
from pathlib import Path
from typing import Any

from hijackrewind.redact import redact_obj

GENESIS = "0" * 64


def utcnow() -> str:
    from datetime import datetime, timezone

    return datetime.now(timezone.utc).isoformat()


def _canon(body: dict[str, Any]) -> str:
    return json.dumps(body, sort_keys=True, separators=(",", ":"), default=str)


class AuditLog:
    """Tamper-evident append-only log. A checkpoint remembers the latest hash."""

    def __init__(self, path: Path | str, secrets: list[str] | None = None, hmac_key: str = "") -> None:
        self.path = Path(path)
        self.secrets = secrets or []
        self.hmac_key = hmac_key
        self.path.parent.mkdir(parents=True, exist_ok=True)
        if not self.path.exists():
            self.path.touch()

    def append(self, *, run_id: str, actor: str, action: str, detail: dict[str, Any] | None = None) -> dict[str, Any]:
        fd = os.open(self.path, os.O_RDWR | os.O_CREAT, 0o644)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX)
            last = self._last_unlocked()
            prev = last["hash"] if last else GENESIS
            seq = (int(last["seq"]) + 1) if last else 1
            body: dict[str, Any] = {
                "seq": seq,
                "ts": utcnow(),
                "run_id": run_id,
                "actor": actor,
                "action": action,
                "detail": redact_obj(detail or {}, self.secrets, outbound=True),
                "prev_hash": prev,
            }
            digest = hashlib.sha256((prev + _canon(body)).encode("utf-8")).hexdigest()
            body["hash"] = digest
            line = json.dumps(body, sort_keys=True, default=str) + "\n"
            os.lseek(fd, 0, os.SEEK_END)
            os.write(fd, line.encode("utf-8"))
            os.fsync(fd)
            self._write_checkpoint(digest)
            return body
        finally:
            fcntl.flock(fd, fcntl.LOCK_UN)
            os.close(fd)

    def read_all(self) -> list[dict[str, Any]]:
        events = []
        if not self.path.exists():
            return events
        for index, line in enumerate(self.path.read_text(encoding="utf-8").splitlines(), start=1):
            if not line.strip():
                continue
            try:
                events.append(json.loads(line))
            except json.JSONDecodeError:
                events.append({"_malformed": True, "_line": index})
        return events

    def verify(self) -> tuple[bool, str]:
        prev = GENESIS
        events = self.read_all()
        for index, event in enumerate(events, start=1):
            if event.get("_malformed"):
                return False, f"malformed json at line {event.get('_line', index)}"
            body = dict(event)
            digest = str(body.pop("hash", ""))
            if body.get("seq") != index:
                return False, f"sequence broke at line {index}"
            if body.get("prev_hash") != prev:
                return False, f"prev_hash broke at seq {index}"
            calc = hashlib.sha256((prev + _canon(body)).encode("utf-8")).hexdigest()
            if calc != digest:
                return False, f"hash mismatch at seq {index}"
            prev = digest
        checkpoint = self._read_checkpoint()
        if checkpoint and events:
            if checkpoint != events[-1].get("hash"):
                return False, "checkpoint does not match the log tail"
        elif checkpoint and not events:
            return False, "checkpoint exists but the log tail is missing"
        return True, f"{len(events)} events"

    def _checkpoint_path(self) -> Path:
        return self.path.with_suffix(self.path.suffix + ".checkpoint")

    def _write_checkpoint(self, digest: str) -> None:
        payload = digest
        if self.hmac_key:
            payload = hmac.new(self.hmac_key.encode(), digest.encode(), hashlib.sha256).hexdigest() + " " + digest
        self._checkpoint_path().write_text(payload + "\n", encoding="utf-8")

    def _read_checkpoint(self) -> str:
        path = self._checkpoint_path()
        if not path.is_file():
            return ""
        text = path.read_text(encoding="utf-8").strip()
        if " " in text and self.hmac_key:
            mac, digest = text.split(" ", 1)
            expected = hmac.new(self.hmac_key.encode(), digest.encode(), hashlib.sha256).hexdigest()
            if not hmac.compare_digest(mac, expected):
                return "invalid-hmac"
            return digest
        if " " in text:
            return text.split(" ", 1)[1]
        return text

    def _last_unlocked(self) -> dict[str, Any] | None:
        events = [event for event in self.read_all() if not event.get("_malformed")]
        return events[-1] if events else None

    def _last(self) -> dict[str, Any] | None:
        return self._last_unlocked()
