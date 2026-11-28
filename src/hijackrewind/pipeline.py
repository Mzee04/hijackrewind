"""State machine: ingest, verify, cross-check, plan, maybe execute.

The optional explainer runs after the decision and cannot change it.
"""

from __future__ import annotations

import uuid
from pathlib import Path
from typing import Any

import httpx

from hijackrewind.actions import load_action, save_action, write_action
from hijackrewind.config import reveal
from hijackrewind.github_client import OutcomeUnknown
from hijackrewind.claims import extract_claims
from hijackrewind.email_auth import verify_channel
from hijackrewind.github_client import GitHubError
from hijackrewind.ingest import ingest_file, ingest_url
from hijackrewind.killswitch import ToolCancelled
from hijackrewind.models import Claim, Document, Plan, PlanStep, RunResult
from hijackrewind.policy import UNAVAILABLE_REASONS, authorize, classify, object_is_known
from hijackrewind.runtime import Services


def new_id(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex[:12]}"


def save_plan(services: Services, plan: Plan) -> None:
    from datetime import datetime, timedelta, timezone

    directory = services.settings.plan_dir()
    directory.mkdir(parents=True, exist_ok=True)
    if not plan.created_at:
        now = datetime.now(timezone.utc)
        plan.created_at = now.isoformat()
        plan.expires_at = (now + timedelta(seconds=services.settings.plan_ttl_seconds)).isoformat()
    (directory / f"{plan.id}.json").write_text(plan.model_dump_json(indent=2), encoding="utf-8")


def load_plan(services: Services, plan_id: str) -> Plan:
    path = services.settings.plan_dir() / f"{plan_id}.json"
    if not path.is_file():
        raise FileNotFoundError(plan_id)
    return Plan.model_validate_json(path.read_text(encoding="utf-8"))


async def run_source(source: str, services: Services) -> RunResult:
    if source.startswith(("http://", "https://")):
        document = await ingest_url(source, services.egress)
    else:
        document = ingest_file(Path(source))
    return await run_document(document, services)


async def run_document(document: Document, services: Services) -> RunResult:
    run_id = new_id("run")
    services.egress.set_run(run_id)
    services.reset_meter()
    services.monitor.start(run_id, _source_label(document.source))
    trace = services.trace_for(run_id)
    screen = document.screen
    warnings = list(screen.warnings) if screen else []
    data_issues = list(screen.data_issues) if screen else []
    blocked: list[dict] = []
    try:
        services.kill.raise_if_tripped()
        services.audit.append(
            run_id=run_id,
            actor="agent",
            action="run_started",
            detail={"source": _source_label(document.source), "modality": document.modality, "mode": services.settings.mode},
        )
        services.monitor.update(step="screen", warnings=warnings)
        trace.event(
            step="screen",
            decision="warnings" if warnings else "clean",
            outcome="ok",
            input_summary=(screen.summary if screen else "")[:280],
            extra={"warnings": warnings, "data_issues": data_issues},
        )
        for lure in screen.lures if screen else []:
            services.kill.raise_if_tripped()
            detail = services.egress.block_lure(
                kind=lure.kind,
                host=lure.host,
                path=lure.path or "/",
                recipient=lure.recipient,
            )
            blocked.append(detail)
            services.monitor.blocked = list(blocked)
            trace.event(
                step="egress",
                tool="outbound",
                decision="blocked",
                outcome="caught by guardrail",
                request={"kind": lure.kind, "host": lure.host, "path": lure.path or "/"},
            )
        services.monitor.update(step="verify")
        channel = verify_channel(
            document,
            services.settings.allowlisted_domains(),
            dns=services.settings.dkim_mode(),
        )
        if channel.verified and (document.from_address or "").lower() not in services.settings.alert_sender_addresses():
            # A signed GitHub notification (an issue comment, for example) carries text
            # a stranger wrote. Only the account-alert sender can start a plan.
            channel.verified = False
            channel.reason = "sender address is not an account-alert sender"
        if channel.verified and document.raw_bytes:
            from hijackrewind.dkim_verify import remember_message

            if not remember_message(services.settings.home, document.raw_bytes):
                channel.verified = False
                channel.reason = "replayed message"
        trace.event(
            step="verify",
            decision="verified" if channel.verified else "rejected",
            outcome=channel.reason,
            extra={"lookalike": channel.lookalike, "pretends_github": channel.pretends_github},
        )
        services.audit.append(
            run_id=run_id,
            actor="agent",
            action="channel_verified" if channel.verified else "channel_rejected",
            detail={"reason": channel.reason, "from_domain": channel.from_domain},
        )
        if channel.pretends_github and not channel.verified:
            summary = (
                f"Quarantined the message. It presents as a GitHub account alert but the "
                f"channel check failed ({channel.reason}). No mutate."
            )
            return _finish(
                services, trace, run_id, "quarantined", summary, warnings, data_issues, blocked, None, []
            )
        if not channel.verified:
            summary = _triage_summary(document, channel.reason, warnings, data_issues, blocked)
            return _finish(services, trace, run_id, "held", summary, warnings, data_issues, blocked, None, [])

        services.monitor.update(step="extract", decision="channel verified")
        from hijackrewind.dkim_verify import claim_text

        claim_source = claim_text(document.raw_bytes) if document.raw_bytes else ""
        claims = extract_claims(claim_source or (screen.visible_text if screen else document.visible_text))
        trace.event(
            step="extract",
            decision=f"{len(claims)} claim(s)",
            outcome="ok" if claims else "no concrete object",
            extra={"kinds": [claim.kind for claim in claims]},
        )
        if not claims:
            summary = (
                "The channel is aligned, and the message does not name a concrete "
                "account object. No revert was planned."
            )
            return _finish(services, trace, run_id, "held", summary, warnings, data_issues, blocked, None, [])

        services.monitor.update(step="cross_check")
        steps, notes = await _cross_check(claims, services)
        trace.event(
            step="cross_check",
            decision="; ".join(notes) or ("matched live state" if steps else "no matching live object"),
            outcome="ok",
            extra={"steps": len(steps)},
        )
        if not steps:
            summary = "Verified the channel. " + " ".join(notes) + " No mutate."
            return _finish(services, trace, run_id, "held", summary, warnings, data_issues, blocked, None, [])

        plan = Plan(
            id=new_id("plan"),
            run_id=run_id,
            steps=steps,
            blast_radius=_blast(steps),
            status="draft",
        )
        save_plan(services, plan)
        services.monitor.update(step="plan", plan=plan.model_dump())
        services.audit.append(
            run_id=run_id,
            actor="agent",
            action="plan_created",
            detail={"plan_id": plan.id, "blast_radius": plan.blast_radius, "paths": [step.path for step in steps]},
        )
        trace.event(
            step="plan",
            decision=plan.blast_radius,
            outcome="draft",
            request={"plan_id": plan.id, "paths": [step.path for step in steps]},
        )
        return await _execute(services, trace, plan, document, warnings, data_issues, blocked, allow_auto=True, approved=False)
    except ToolCancelled as exc:
        summary = f"Kill switch cancelled the run ({exc}). Pending tool calls were not finished."
        services.audit.append(run_id=run_id, actor="kill_switch", action="run_cancelled", detail={"reason": str(exc)})
        trace.event(step="kill", decision="cancelled", outcome="cancelled")
        return _finish(services, trace, run_id, "cancelled", summary, warnings, data_issues, blocked, None, [])
    except GitHubError as exc:
        summary = f"API error ({exc}). Failing closed. No further mutate."
        services.audit.append(run_id=run_id, actor="agent", action="api_error", detail={"error": str(exc)})
        trace.event(step="api", decision="fail closed", outcome="held")
        return _finish(services, trace, run_id, "held", summary, warnings, data_issues, blocked, None, [])
    except Exception as exc:  # noqa: BLE001 - fail closed into a trace instead of a stack on the operator
        from hijackrewind.redact import redact_text

        redacted = redact_text(str(exc), services.settings.secret_values())
        summary = f"Stopped cleanly after {type(exc).__name__}: {redacted}. No further mutate."
        services.audit.append(
            run_id=run_id,
            actor="agent",
            action="run_failed",
            detail={"error": type(exc).__name__, "message": redacted},
        )
        trace.event(step="error", decision=redacted[:280], outcome="failed", extra={"error": type(exc).__name__})
        return _finish(
            services,
            trace,
            run_id,
            "failed",
            summary,
            warnings,
            data_issues,
            blocked,
            None,
            [],
            error=type(exc).__name__,
        )


async def execute_saved_plan(services: Services, plan_id: str, *, approved: bool) -> RunResult:
    plan = load_plan(services, plan_id)
    run_id = plan.run_id
    services.egress.set_run(run_id)
    trace = services.trace_for(run_id)
    services.reset_meter()
    services.monitor.start(run_id, f"plan {plan.id}")
    services.monitor.update(plan=plan.model_dump(), step="execute")
    if plan.status == "denied":
        summary = f"Denied plan {plan.id} cannot execute."
        return _finish(services, trace, run_id, "held", summary, [], [], [], plan.id, [])
    if not approved:
        services.audit.append(run_id=run_id, actor="operator", action="plan_denied", detail={"plan_id": plan.id})
        plan.status = "denied"
        save_plan(services, plan)
        summary = f"Denied plan {plan.id}. No mutate."
        return _finish(services, trace, run_id, "held", summary, [], [], [], plan.id, [])
    services.audit.append(
        run_id=run_id,
        actor="operator",
        action="plan_approved",
        detail={"plan_id": plan.id},
    )
    plan.approved = True
    try:
        return await _execute(
            services,
            trace,
            plan,
            document=None,
            warnings=[],
            data_issues=[],
            blocked=[],
            allow_auto=False,
            approved=True,
        )
    except ToolCancelled as exc:
        summary = f"Kill switch cancelled plan {plan.id} ({exc})."
        services.audit.append(run_id=run_id, actor="kill_switch", action="run_cancelled", detail={"reason": str(exc)})
        plan.status = "cancelled"
        save_plan(services, plan)
        return _finish(services, trace, run_id, "cancelled", summary, [], [], [], plan.id, [])


def _plan_refusal(plan: Plan) -> str:
    from datetime import datetime, timezone

    if plan.status == "denied":
        return "denied plans cannot execute"
    if plan.approval_used and plan.status != "executing":
        return "approval was already used"
    if plan.expires_at:
        try:
            expiry = datetime.fromisoformat(plan.expires_at)
        except ValueError:
            return "plan expiry is unreadable"
        if expiry.tzinfo is None:
            expiry = expiry.replace(tzinfo=timezone.utc)
        if datetime.now(timezone.utc) > expiry:
            return "plan has expired"
    return ""


async def _revalidate(step: PlanStep, services: Services) -> tuple[bool, str]:
    if step.method == "PUT" and step.kind == "branch_protection":
        saved = services.manifest.repo(step.owner, step.repo).protections.get(step.object_id)
        if not saved or step.body != saved:
            return False, "restore body is not the known-good document"
        return True, ""
    if step.method != "DELETE":
        return True, ""
    current = await _live_object(step, services)
    if current is None:
        return True, "already absent"
    if str(current.get("id", current.get("email", ""))) != str(step.object_id) and step.kind != "email":
        return False, "live object changed after the plan"
    if step.kind == "webhook":
        old = ((step.before or {}).get("config") or {}).get("url")
        new = ((current.get("config") or {}).get("url"))
        if old and new and old != new:
            return False, "live object changed after the plan"
    if object_is_known(step, services.manifest):
        return False, "object is on the known-good manifest"
    return True, ""


async def _live_object(step: PlanStep, services: Services) -> dict | None:
    if step.kind == "ssh_key":
        rows = await services.github.get_json("/user/keys") or []
        return next((item for item in rows if str(item.get("id")) == step.object_id), None)
    if step.kind == "deploy_key":
        rows = await services.github.get_json(f"/repos/{step.owner}/{step.repo}/keys") or []
        return next((item for item in rows if str(item.get("id")) == step.object_id), None)
    if step.kind == "webhook":
        rows = await services.github.get_json(f"/repos/{step.owner}/{step.repo}/hooks") or []
        return next((item for item in rows if str(item.get("id")) == step.object_id), None)
    if step.kind == "email":
        rows = await services.github.get_json("/user/emails") or []
        return next((item for item in rows if str(item.get("email", "")).lower() == step.object_id.lower()), None)
    return step.before


async def _execute(
    services: Services,
    trace: Any,
    plan: Plan,
    document: Document | None,
    warnings: list[str],
    data_issues: list[str],
    blocked: list[dict],
    *,
    allow_auto: bool,
    approved: bool,
) -> RunResult:
    from hijackrewind.runtime import execution_lock

    with execution_lock(services.settings):
        if approved:
            current = load_plan(services, plan.id) if (services.settings.plan_dir() / f"{plan.id}.json").is_file() else plan
            if current.status == "executed":
                summary = f"Plan {current.id} already ran. No second mutate."
                return _finish(services, trace, plan.run_id, "executed", summary, warnings, data_issues, blocked, plan.id, [])
            if current.approval_used or current.status in {"executing", "denied"}:
                summary = "approval was already used" if current.approval_used else "plan cannot be approved"
                return _finish(services, trace, plan.run_id, "held", summary, warnings, data_issues, blocked, plan.id, [])
            current.approval_used = True
            current.approved = True
            current.status = "executing"
            save_plan(services, current)
            plan = current
        return await _execute_body(
            services, trace, plan, document, warnings, data_issues, blocked, allow_auto=allow_auto, approved=approved
        )


async def _execute_body(
    services: Services,
    trace: Any,
    plan: Plan,
    document: Document | None,
    warnings: list[str],
    data_issues: list[str],
    blocked: list[dict],
    *,
    allow_auto: bool,
    approved: bool,
) -> RunResult:
    del document
    refusal = _plan_refusal(plan)
    if refusal:
        if plan.status == "executing":
            # Approval was consumed above. Do not leave the plan stuck as executing.
            plan.status = "blocked"
            save_plan(services, plan)
        services.audit.append(
            run_id=plan.run_id,
            actor="agent",
            action="mutate_denied",
            detail={"plan_id": plan.id, "reason": refusal},
        )
        return _finish(services, trace, plan.run_id, "held", refusal, warnings, data_issues, blocked, plan.id, [])
    if plan.status == "executed":
        summary = f"Plan {plan.id} already ran. No second mutate."
        trace.event(step="policy", decision="idempotent skip", outcome="executed", request={"plan_id": plan.id})
        return _finish(services, trace, plan.run_id, "executed", summary, warnings, data_issues, blocked, plan.id, [])
    if services.settings.mode == "dry-run":
        plan.status = "dry_run"
        save_plan(services, plan)
        summary = f"Dry-run plan {plan.id}. {plan.blast_radius} Nothing was changed."
        services.audit.append(
            run_id=plan.run_id,
            actor="agent",
            action="mutate_denied",
            detail={"plan_id": plan.id, "reason": "mode is dry-run"},
        )
        return _finish(services, trace, plan.run_id, "dry_run", summary, warnings, data_issues, blocked, plan.id, [])

    mutated: list[str] = []
    held: list[str] = []
    services.monitor.update(step="execute")
    for step in plan.steps:
        services.kill.raise_if_tripped()
        if step.disposition == "unavailable" or step.method == "NONE":
            services.audit.append(
                run_id=plan.run_id,
                actor="agent",
                action="action_planned",
                detail={"kind": step.kind, "status": "unavailable", "reason": step.reason},
            )
            trace.event(step="policy", decision=step.reason, outcome="unavailable", request={"kind": step.kind})
            continue
        allowed, reason = authorize(
            step,
            services.settings,
            services.manifest,
            services.meter,
            allow_auto=allow_auto,
            approved=approved,
        )
        if not allowed:
            if "approval" in reason:
                held.append(reason)
            services.audit.append(
                run_id=plan.run_id,
                actor="agent",
                action="mutate_denied",
                detail={"plan_id": plan.id, "path": step.path, "reason": reason, "status": "held"},
            )
            continue
        fresh_ok, fresh_reason = await _revalidate(step, services)
        if not fresh_ok:
            held.append(fresh_reason)
            services.audit.append(
                run_id=plan.run_id,
                actor="agent",
                action="mutate_denied",
                detail={"plan_id": plan.id, "path": step.path, "reason": fresh_reason},
            )
            continue
        action_id = save_action(services, run_id=plan.run_id, plan_id=plan.id, step=step, outcome="pending")
        try:
            outcome = await services.github.mutate(step.method, step.path, step.body, role="execute")
        except OutcomeUnknown:
            record = load_action(services, action_id)
            record["status"] = "outcome_unknown"
            record["after"] = {"outcome": "unknown"}
            write_action(services, record)
            plan.status = "cancelled"
            save_plan(services, plan)
            summary = f"Cancelled during {step.method} {step.path}. Outcome unknown. Run reconcile {action_id}."
            services.audit.append(
                run_id=plan.run_id,
                actor="kill_switch",
                action="run_cancelled",
                detail={"reason": "cancelled, outcome unknown", "action_id": action_id},
            )
            services.audit.append(
                run_id=plan.run_id,
                actor="kill_switch",
                action="outcome_unknown",
                detail={"action_id": action_id, "path": step.path, "note": "cancelled, outcome unknown"},
            )
            return _finish(services, trace, plan.run_id, "cancelled", summary, warnings, data_issues, blocked, plan.id, mutated)
        except ToolCancelled:
            plan.status = "cancelled"
            save_plan(services, plan)
            raise
        except GitHubError as exc:
            plan.status = "blocked"
            save_plan(services, plan)
            summary = f"API error during {step.method} {step.path}. Failing closed. {exc}"
            services.audit.append(
                run_id=plan.run_id,
                actor="agent",
                action="mutate_failed",
                detail={"path": step.path, "error": str(exc)},
            )
            return _finish(services, trace, plan.run_id, "held", summary, warnings, data_issues, blocked, plan.id, mutated)
        record = load_action(services, action_id)
        record["status"] = "executed" if outcome == "done" else "noop"
        record["after"] = {"outcome": outcome, "object_id": step.object_id}
        write_action(services, record)
        if outcome == "done":
            mutated.append(step.path)
        services.audit.append(
            run_id=plan.run_id,
            actor="agent",
            action="mutate_executed" if outcome == "done" else "idempotent_noop",
            detail={
                "path": step.path,
                "method": step.method,
                "reason": reason,
                "kind": step.kind,
                "action_id": action_id,
                "status": "auto" if reason.startswith("policy auto-execute") else "approved",
                "classification": classify(step, services.settings, services.manifest),
                "claim": step.object_id,
                "before": step.before or {},
                "after": {"outcome": outcome},
            },
        )
        trace.event(
            step="execute",
            tool=f"{step.method} {step.path}",
            decision=reason,
            outcome=outcome,
            request={"path": step.path, "action_id": action_id},
        )
    unavailable = [step for step in plan.steps if step.disposition == "unavailable"]
    if held and mutated:
        plan.status = "pending_approval"
        status = "pending_approval"
        summary = f"Plan {plan.id} ran the reversible steps and is waiting on the rest. {plan.blast_radius}"
    elif held:
        plan.status = "pending_approval"
        status = "pending_approval"
        summary = f"Plan {plan.id} is waiting for approval. {plan.blast_radius}"
    elif mutated:
        plan.status = "executed"
        status = "executed"
        summary = f"Executed plan {plan.id}. {plan.blast_radius}"
    elif unavailable:
        plan.status = "blocked"
        status = "held"
        summary = "Planned containment that this token cannot perform. " + unavailable[0].reason
    else:
        plan.status = "blocked"
        status = "held"
        summary = f"Plan {plan.id} was not executed."
    save_plan(services, plan)
    services.monitor.update(plan=plan.model_dump(), decision=summary)
    return _finish(services, trace, plan.run_id, status, summary, warnings, data_issues, blocked, plan.id, mutated)


async def _cross_check(claims: list[Claim], services: Services) -> tuple[list[PlanStep], list[str]]:
    steps: list[PlanStep] = []
    notes: list[str] = []
    owner = services.settings.test_repo_owner
    repo = services.settings.test_repo_name
    for claim in claims:
        services.kill.raise_if_tripped()
        if claim.kind in UNAVAILABLE_REASONS:
            steps.append(
                PlanStep(
                    kind=claim.kind,
                    method="NONE",
                    path="",
                    object_id=claim.object_id or "unspecified",
                    reason=UNAVAILABLE_REASONS[claim.kind],
                    disposition="unavailable",
                )
            )
            continue
        if claim.kind == "ssh_key":
            keys = await services.github.get_json("/user/keys") or []
            match = _match_key(keys, claim)
            if not match:
                notes.append("No live SSH key matches the alert.")
                continue
            if services.manifest.ssh_known(object_id=str(match["id"]), fingerprint=match.get("fingerprint") or None):
                notes.append(f"SSH key {match['id']} is on the known-good manifest.")
                continue
            steps.append(
                PlanStep(
                    kind="ssh_key",
                    method="DELETE",
                    path=f"/user/keys/{match['id']}",
                    object_id=str(match["id"]),
                    reason=f"claim ssh key {match['id']} matched live ssh key {match['id']} ({match.get('title') or 'untitled'})",
                    disposition="auto",
                    before=match,
                    reverse_method="POST",
                    reverse_path="/user/keys",
                    reverse_body={"title": match.get("title") or "restored", "key": match.get("key") or ""},
                )
            )
        elif claim.kind == "email" and claim.email:
            emails = await services.github.get_json("/user/emails") or []
            match = next((item for item in emails if item.get("email", "").lower() == claim.email.lower()), None)
            if not match:
                notes.append("No live account email matches the alert.")
                continue
            if match.get("primary"):
                notes.append(f"{match['email']} is the primary address and will not be removed.")
                continue
            if services.manifest.email_known(match["email"]):
                notes.append(f"{match['email']} is on the known-good manifest.")
                continue
            steps.append(
                PlanStep(
                    kind="email",
                    method="DELETE",
                    path="/user/emails",
                    object_id=match["email"],
                    reason=f"claim {match['email']} matched live email {match['email']}",
                    primary=bool(match.get("primary")),
                    body={"emails": [match["email"]]},
                    before=match,
                )
            )
        elif claim.kind in {"gpg_key", "ssh_signing_key"} and claim.object_id:
            path = "/user/gpg_keys" if claim.kind == "gpg_key" else "/user/ssh_signing_keys"
            rows = await services.github.get_json(path) or []
            match = next((item for item in rows if str(item.get("id")) == claim.object_id), None)
            if not match:
                notes.append(f"No live {claim.kind} matches the alert.")
                continue
            known = services.manifest.gpg_keys if claim.kind == "gpg_key" else services.manifest.ssh_signing_keys
            if services.manifest.id_known(known, str(match["id"])):
                notes.append(f"{claim.kind} {match['id']} is on the known-good manifest.")
                continue
            steps.append(
                PlanStep(
                    kind=claim.kind,
                    method="DELETE",
                    path=f"{path}/{match['id']}",
                    object_id=str(match["id"]),
                    reason=f"unknown {claim.kind} {match['id']}",
                )
            )
        elif claim.kind == "deploy_key" and claim.object_id:
            rows = await services.github.get_json(f"/repos/{owner}/{repo}/keys") or []
            match = next((item for item in rows if str(item.get("id")) == claim.object_id), None)
            if not match:
                notes.append("No live deploy key matches the alert.")
                continue
            if services.manifest.id_known(services.manifest.repo(owner, repo).deploy_keys, str(match["id"])):
                notes.append(f"Deploy key {match['id']} is on the known-good manifest.")
                continue
            steps.append(
                PlanStep(
                    kind="deploy_key",
                    method="DELETE",
                    path=f"/repos/{owner}/{repo}/keys/{match['id']}",
                    object_id=str(match["id"]),
                    owner=owner,
                    repo=repo,
                    reason=f"claim deploy key {match['id']} matched live deploy key {match['id']}",
                    disposition="auto",
                    before=match,
                    reverse_method="POST",
                    reverse_path=f"/repos/{owner}/{repo}/keys",
                    reverse_body={
                        "title": match.get("title") or "restored",
                        "key": match.get("key") or "",
                        "read_only": bool(match.get("read_only", True)),
                    },
                )
            )
        elif claim.kind == "webhook" and claim.object_id:
            rows = await services.github.get_json(f"/repos/{owner}/{repo}/hooks") or []
            match = next((item for item in rows if str(item.get("id")) == claim.object_id), None)
            if not match:
                notes.append("No live webhook matches the alert.")
                continue
            if services.manifest.id_known(services.manifest.repo(owner, repo).webhooks, str(match["id"])):
                notes.append(f"Webhook {match['id']} is on the known-good manifest.")
                continue
            from urllib.parse import urlparse

            host = (urlparse((match.get("config") or {}).get("url", "")).hostname or "").lower()
            unknown_host = host not in services.settings.webhook_hosts()
            steps.append(
                PlanStep(
                    kind="webhook",
                    method="DELETE",
                    path=f"/repos/{owner}/{repo}/hooks/{match['id']}",
                    object_id=str(match["id"]),
                    owner=owner,
                    repo=repo,
                    reason=f"claim webhook {match['id']} matched live webhook {match['id']} at {host or 'an unknown host'}",
                    disposition="auto" if unknown_host else "approval",
                    before=match,
                    reverse_method="POST",
                    reverse_path=f"/repos/{owner}/{repo}/hooks",
                    reverse_body={
                        # GitHub returns a masked secret. Posting the mask would set it as the secret.
                        "config": {k: v for k, v in (match.get("config") or {}).items() if k != "secret"},
                        "events": match.get("events") or ["push"],
                        "active": bool(match.get("active", True)),
                    },
                )
            )
        elif claim.kind == "collaborator" and claim.login:
            rows = await services.github.get_json(f"/repos/{owner}/{repo}/collaborators") or []
            match = next((item for item in rows if item.get("login", "").lower() == claim.login.lower()), None)
            if not match:
                notes.append("No live collaborator matches the alert.")
                continue
            known = {item.lower() for item in services.manifest.repo(owner, repo).collaborators}
            if match["login"].lower() in known:
                notes.append(f"Collaborator {match['login']} is on the known-good manifest.")
                continue
            steps.append(
                PlanStep(
                    kind="collaborator",
                    method="DELETE",
                    path=f"/repos/{owner}/{repo}/collaborators/{match['login']}",
                    object_id=match["login"],
                    owner=owner,
                    repo=repo,
                    reason=f"unknown collaborator {match['login']}",
                )
            )
        elif claim.kind == "branch_protection" and claim.branch:
            protection = await services.github.get_json(
                f"/repos/{owner}/{repo}/branches/{claim.branch}/protection"
            )
            saved = services.manifest.repo(owner, repo).protections.get(claim.branch)
            if claim.change == "removed" or not protection:
                if not saved:
                    notes.append(
                        f"Branch {claim.branch} has no saved protection document, so it cannot be restored."
                    )
                    continue
                steps.append(
                    PlanStep(
                        kind="branch_protection",
                        method="PUT",
                        path=f"/repos/{owner}/{repo}/branches/{claim.branch}/protection",
                        object_id=claim.branch,
                        owner=owner,
                        repo=repo,
                        reason=f"restore known-good protection on {claim.branch}",
                        disposition="auto",
                        before=protection or {},
                        body=saved,
                    )
                )
                continue
            if claim.branch in services.manifest.repo(owner, repo).protected_branches:
                notes.append(f"Protection on {claim.branch} is on the known-good manifest.")
                continue
            steps.append(
                PlanStep(
                    kind="branch_protection",
                    method="DELETE",
                    path=f"/repos/{owner}/{repo}/branches/{claim.branch}/protection",
                    object_id=claim.branch,
                    owner=owner,
                    repo=repo,
                    reason=f"unknown branch protection on {claim.branch}",
                    disposition="approval",
                    before=protection,
                )
            )
        else:
            notes.append(f"Ignored an incomplete {claim.kind} claim.")
    return steps, notes


def _match_key(keys: list[dict], claim: Claim) -> dict | None:
    for key in keys:
        if claim.object_id and str(key.get("id")) == str(claim.object_id):
            return key
        fingerprint = key.get("fingerprint") or ""
        if claim.fingerprint and fingerprint and claim.fingerprint == fingerprint:
            return key
    return None


def _blast(steps: list[PlanStep]) -> str:
    bits = [
        f"claim {step.kind} {step.object_id} next to live {step.kind} {step.object_id} ({step.reason})"
        for step in steps
    ] or ["no steps"]
    return "Plans " + "; ".join(bits) + ". Known-good objects stay. Only a confirmed match can run."


def _triage_summary(document: Document, reason: str, warnings: list[str], data_issues: list[str], blocked: list[dict]) -> str:
    if document.modality == "email":
        lead = f"Triaged email from {document.from_domain or 'an unknown sender'} ({document.subject or 'no subject'})."
    else:
        lead = f"Triaged the {document.modality}."
    tail = f" It is not a verified GitHub account-security alert ({reason}). No revert was planned."
    extra = []
    instruction_warnings = {
        "hidden_instruction",
        "encoded_instruction",
        "zero_width_instruction",
        "instruction_shaped_text",
        "fake_authority",
        "exfil_request",
        "poisoned_tool_output",
        "conflicting_instructions",
    }
    if instruction_warnings.intersection(warnings):
        extra.append("Instruction-shaped content was not followed.")
    if data_issues:
        extra.append(f"Flagged {len(data_issues)} data problem(s).")
    if blocked:
        hosts = sorted({item.get("host") or item.get("recipient_domain") or "outbound" for item in blocked})
        extra.append("Blocked outbound to " + ", ".join(hosts) + ".")
    return lead + tail + (" " + " ".join(extra) if extra else "")


def _source_label(source: str) -> str:
    name = source.replace("\\", "/").split("/")[-1]
    return name or source


def _finish(
    services: Services,
    trace: Any,
    run_id: str,
    status: str,
    summary: str,
    warnings: list[str],
    data_issues: list[str],
    blocked: list[dict],
    plan_id: str | None,
    mutated: list[str],
    error: str | None = None,
) -> RunResult:
    explanation = _explain(services, summary)
    trace.event(step="finish", decision=status, outcome=status, input_summary=summary[:280], extra={"cost_points": services.meter.points})
    services.audit.append(
        run_id=run_id,
        actor="agent",
        action="run_finished",
        detail={"status": status, "plan_id": plan_id or "", "mutated": mutated, "cost_points": services.meter.points},
    )
    services.monitor.finish(status, summary)
    return RunResult(
        run_id=run_id,
        status=status,  # type: ignore[arg-type]
        summary=summary,
        warnings=warnings,
        data_issues=data_issues,
        blocked=blocked,
        plan_id=plan_id,
        mutated=mutated,
        trace_path=str(trace.path),
        cost_points=services.meter.points,
        error=error,
        explanation=explanation,
    )


def _explain(services: Services, summary: str) -> str | None:
    settings = services.settings
    if not settings.llm_enabled or not settings.llm_base_url:
        return None
    # Display only. The decision above is already final.
    try:
        response = httpx.post(
            settings.llm_base_url.rstrip("/") + "/v1/chat/completions",
            headers={"Authorization": f"Bearer {reveal(settings.llm_api_key)}"} if reveal(settings.llm_api_key) else {},
            json={
                "model": settings.llm_model or "local",
                "messages": [
                    {"role": "system", "content": "Write one short explanation. You cannot authorize actions."},
                    {"role": "user", "content": summary[:500]},
                ],
            },
            timeout=8.0,
        )
        if response.status_code >= 400:
            return None
        payload = response.json()
        return str(payload["choices"][0]["message"]["content"])[:500]
    except (httpx.HTTPError, KeyError, IndexError, ValueError):
        return None
