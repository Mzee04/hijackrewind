"""Live run view shared by the CLI and the dashboard."""

from __future__ import annotations

import threading
from typing import Any


class Monitor:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self.active = False
        self.run_id = ""
        self.source = ""
        self.step = "idle"
        self.decision = ""
        self.outcome = ""
        self.summary = ""
        self.cost_points = 0
        self.tools: list[dict[str, Any]] = []
        self.blocked: list[dict[str, Any]] = []
        self.plan: dict[str, Any] | None = None
        self.warnings: list[str] = []
        self.finished = False

    def start(self, run_id: str, source: str) -> None:
        with self._lock:
            self.active = True
            self.finished = False
            self.run_id = run_id
            self.source = source
            self.step = "ingest"
            self.decision = ""
            self.outcome = ""
            self.summary = ""
            self.cost_points = 0
            self.tools = []
            self.blocked = []
            self.plan = None
            self.warnings = []

    def update(self, **fields: Any) -> None:
        with self._lock:
            for key, value in fields.items():
                setattr(self, key, value)

    def tool(self, name: str, outcome: str, detail: dict[str, Any] | None = None) -> None:
        with self._lock:
            self.tools.append({"name": name, "outcome": outcome, "detail": detail or {}})

    def finish(self, outcome: str, summary: str) -> None:
        with self._lock:
            self.active = False
            self.finished = True
            self.step = "done"
            self.outcome = outcome
            self.summary = summary

    def snapshot(self) -> dict[str, Any]:
        with self._lock:
            return {
                "active": self.active,
                "finished": self.finished,
                "run_id": self.run_id,
                "source": self.source,
                "step": self.step,
                "decision": self.decision,
                "outcome": self.outcome,
                "summary": self.summary,
                "cost_points": self.cost_points,
                "tools": list(self.tools),
                "blocked": list(self.blocked),
                "plan": self.plan,
                "warnings": list(self.warnings),
            }
