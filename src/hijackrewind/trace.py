"""JSONL traces. One line per step. Secrets are redacted before the write."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from hijackrewind.audit import utcnow
from hijackrewind.redact import redact_obj


class TraceWriter:
    def __init__(self, directory: Path | str, run_id: str, secrets: list[str] | None = None) -> None:
        self.run_id = run_id
        self.secrets = secrets or []
        self.directory = Path(directory)
        self.directory.mkdir(parents=True, exist_ok=True)
        self.path = self.directory / f"{run_id}.jsonl"

    def event(
        self,
        *,
        step: str,
        decision: str = "",
        outcome: str = "",
        tool: str = "",
        request: dict[str, Any] | None = None,
        response: dict[str, Any] | None = None,
        input_summary: str = "",
        extra: dict[str, Any] | None = None,
    ) -> None:
        record = {
            "ts": utcnow(),
            "run_id": self.run_id,
            "step": step,
            "input_summary": input_summary,
            "decision": decision,
            "tool": tool,
            "request": request or {},
            "response": response or {},
            "outcome": outcome,
        }
        if extra:
            record["extra"] = extra
        safe = redact_obj(record, self.secrets, outbound=False)
        # Tool arguments are outbound actions. Strip queries and canary tokens there.
        safe["request"] = redact_obj(safe.get("request") or {}, self.secrets, outbound=True)
        safe["response"] = redact_obj(safe.get("response") or {}, self.secrets, outbound=True)
        with self.path.open("a", encoding="utf-8") as handle:
            import json

            handle.write(json.dumps(safe, sort_keys=True, default=str) + "\n")
