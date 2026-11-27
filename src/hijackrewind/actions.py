"""Saved before/after state for a reversible containment action."""

from __future__ import annotations

import json
import uuid
from pathlib import Path

from hijackrewind.models import PlanStep
from hijackrewind.runtime import Services


def save_action(services: Services, *, run_id: str, plan_id: str, step: PlanStep, outcome: str) -> str:
    action_id = "act-" + uuid.uuid4().hex[:12]
    record = {
        "id": action_id,
        "run_id": run_id,
        "plan_id": plan_id,
        "kind": step.kind,
        "method": step.method,
        "path": step.path,
        "before": step.before or {},
        "after": {"outcome": outcome, "object_id": step.object_id},
        "reverse_method": step.reverse_method,
        "reverse_path": step.reverse_path,
        "reverse_body": step.reverse_body,
        "status": "executed" if outcome == "done" else "noop",
    }
    directory = Path(services.settings.home) / "actions"
    directory.mkdir(parents=True, exist_ok=True)
    (directory / f"{action_id}.json").write_text(json.dumps(record, sort_keys=True), encoding="utf-8")
    return action_id


def load_action(services: Services, action_id: str) -> dict:
    path = Path(services.settings.home) / "actions" / f"{action_id}.json"
    if not path.is_file():
        raise FileNotFoundError(action_id)
    return json.loads(path.read_text(encoding="utf-8"))


def write_action(services: Services, record: dict) -> None:
    path = Path(services.settings.home) / "actions" / f"{record['id']}.json"
    path.write_text(json.dumps(record, sort_keys=True), encoding="utf-8")


async def rewind(services: Services, action_id: str) -> dict:
    record = load_action(services, action_id)
    if record.get("status") == "rolled_back":
        return record
    method = record.get("reverse_method")
    path = record.get("reverse_path")
    if not method or not path:
        raise ValueError("this action has no reversible API call")
    await services.github.mutate(method, path, record.get("reverse_body"), count_cap=False)
    record["status"] = "rolled_back"
    write_action(services, record)
    services.audit.append(
        run_id=record.get("run_id") or "-",
        actor="operator",
        action="rolled_back",
        detail={"action_id": action_id, "path": path, "method": method},
    )
    return record
