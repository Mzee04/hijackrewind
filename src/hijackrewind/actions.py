"""Saved before/after state for a reversible containment action."""

from __future__ import annotations

import json
import uuid
from pathlib import Path

from hijackrewind.models import PlanStep
from hijackrewind.policy import authorize_rewind
from hijackrewind.runtime import Services


def save_action(services: Services, *, run_id: str, plan_id: str, step: PlanStep, outcome: str = "pending") -> str:
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
        "status": "pending" if outcome == "pending" else ("executed" if outcome == "done" else outcome),
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
    allowed, reason = authorize_rewind(record, services.settings)
    if record.get("status") == "rolled_back" and allowed:
        return record
    if not allowed:
        raise ValueError(reason)
    method = record["reverse_method"]
    path = record["reverse_path"]
    await services.github.mutate(method, path, record.get("reverse_body"), role="rewind")
    present = await _restored(services, record)
    record["status"] = "rolled_back" if present else "restore_unconfirmed"
    record["after"] = {"restored": present}
    write_action(services, record)
    services.audit.append(
        run_id=record.get("run_id") or "-",
        actor="operator",
        action="rolled_back",
        detail={"action_id": action_id, "path": path, "method": method, "restored": present},
    )
    if not present:
        raise ValueError("rewind was sent but the restored object was not found")
    return record


async def reconcile(services: Services, action_id: str) -> dict:
    record = load_action(services, action_id)
    present = await _object_present(services, record.get("path") or "", record.get("before") or {})
    record["reconciled"] = "present" if present else "absent"
    if record.get("status") == "outcome_unknown":
        record["status"] = "executed" if not present and record.get("method") == "DELETE" else "reconciled"
    write_action(services, record)
    services.audit.append(
        run_id=record.get("run_id") or "-",
        actor="operator",
        action="reconciled",
        detail={"action_id": action_id, "remote": record["reconciled"]},
    )
    return record


async def _restored(services: Services, record: dict) -> bool:
    return await _object_present(services, record.get("reverse_path") or "", record.get("reverse_body") or {})


async def _object_present(services: Services, path: str, body: dict) -> bool:
    if path.endswith("/keys") or path == "/user/keys":
        rows = await services.github.get_json(path) or []
        title = (body or {}).get("title")
        key = (body or {}).get("key")
        return any(item.get("title") == title or (key and item.get("key") == key) for item in rows)
    if path.endswith("/hooks"):
        rows = await services.github.get_json(path) or []
        url = ((body or {}).get("config") or {}).get("url")
        return any(((item.get("config") or {}).get("url") == url) for item in rows)
    if "/protection" in path:
        current = await services.github.get_json(path)
        return current is not None
    if path == "/user/emails":
        wanted = {str(item).lower() for item in (body or {}).get("emails", [])}
        if not wanted and (body or {}).get("email"):
            wanted = {str(body["email"]).lower()}
        rows = await services.github.get_json(path) or []
        return any(str(item.get("email", "")).lower() in wanted for item in rows)
    # DELETE of one object: /user/keys/1, /repos/o/r/keys/7, /repos/o/r/hooks/9,
    # /user/gpg_keys/3, /repos/o/r/collaborators/login. Read the parent list.
    parent, _, wanted = path.rpartition("/")
    if parent and wanted:
        rows = await services.github.get_json(parent) or []
        return any(
            str(item.get("id")) == wanted or str(item.get("login", "")).lower() == wanted.lower()
            for item in rows
        )
    return False
