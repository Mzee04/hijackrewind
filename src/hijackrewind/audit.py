"""Append-only hash-chained audit log.

The public API can append and verify. It cannot edit or delete events.
"""

from __future__ import annotations

import hashlib
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
    def __init__(self, path: Path | str, secrets: list[str] | None = None) -> None:
        self.path = Path(path)
        self.secrets = secrets or []
        self.path.parent.mkdir(parents=True, exist_ok=True)
        if not self.path.exists():
            self.path.touch()

    def append(self, *, run_id: str, actor: str, action: str, detail: dict[str, Any] | None = None) -> dict[str, Any]:
        last = self._last()
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
        fd = os.open(self.path, os.O_APPEND | os.O_WRONLY | os.O_CREAT, 0o644)
        try:
            os.write(fd, line.encode("utf-8"))
            os.fsync(fd)
        finally:
            os.close(fd)
        return body

    def read_all(self) -> list[dict[str, Any]]:
        events = []
        if not self.path.exists():
            return events
        for line in self.path.read_text(encoding="utf-8").splitlines():
            if line.strip():
                events.append(json.loads(line))
        return events

    def verify(self) -> tuple[bool, str]:
        prev = GENESIS
        events = self.read_all()
        for index, event in enumerate(events, start=1):
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
        return True, f"{len(events)} events"

    def _last(self) -> dict[str, Any] | None:
        events = self.read_all()
        return events[-1] if events else None
