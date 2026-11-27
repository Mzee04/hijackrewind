"""State machine: ingest, verify, cross-check, plan, maybe execute.

The optional explainer runs after the decision and cannot change it.
"""

from __future__ import annotations

import uuid
from pathlib import Path
from typing import Any

import httpx

from hijackrewind.claims import extract_claims
from hijackrewind.email_auth import verify_channel
from hijackrewind.github_client import GitHubError
from hijackrewind.ingest import ingest_file, ingest_url
from hijackrewind.killswitch import ToolCancelled
from hijackrewind.models import Claim, Document, Plan, PlanStep, RunResult
from hijackrewind.policy import authorize
from hijackrewind.runtime import Services


def new_id(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex[:12]}"


def save_plan(services: Services, plan: Plan) -> None:
    directory = services.settings.plan_dir()
    directory.mkdir(parents=True, exist_ok=True)
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
        claims = extract_claims(screen.visible_text if screen else document.visible_text)
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
        allow_auto = len(steps) == 1 and steps[0].kind == "ssh_key" and services.settings.auto_execute_ssh_key
        return await _execute(services, trace, plan, document, warnings, data_issues, blocked, allow_auto=allow_auto, approved=False)
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
        summary = f"Stopped cleanly after {type(exc).__name__}. No further mutate."
        services.audit.append(
            run_id=run_id,
            actor="agent",
            action="run_failed",
            detail={"error": type(exc).__name__},
        )
        trace.event(step="error", decision=type(exc).__name__, outcome="failed")
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
    if approved:
        plan.approved = True
        services.audit.append(
            run_id=run_id,
            actor="operator",
            action="plan_approved",
            detail={"plan_id": plan.id},
        )
    else:
        services.audit.append(run_id=run_id, actor="operator", action="plan_denied", detail={"plan_id": plan.id})
        plan.status = "denied"
        save_plan(services, plan)
        summary = f"Denied plan {plan.id}. No mutate."
        return _finish(services, trace, run_id, "held", summary, [], [], [], plan.id, [])
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
    if len(plan.steps) > max(services.settings.mutate_cap - services.meter.mutates, 0):
        decisions = [(False, "plan has more deletes than the per-run mutate cap")] * len(plan.steps)
    else:
        decisions = [
            authorize(
                step,
                services.settings,
                services.manifest,
                services.meter,
                allow_auto=allow_auto,
                approved=approved,
            )
            for step in plan.steps
        ]
    if not all(ok for ok, _reason in decisions):
        reason = next(reason for ok, reason in decisions if not ok)
        if "dry-run" in reason:
            plan.status = "dry_run"
            status = "dry_run"
            summary = f"Dry-run plan {plan.id}. {plan.blast_radius} Nothing was changed."
        elif "approval" in reason:
            plan.status = "pending_approval"
            status = "pending_approval"
            summary = f"Plan {plan.id} is waiting for approval. {plan.blast_radius}"
        else:
            plan.status = "blocked"
            status = "held"
            summary = f"Plan {plan.id} was not executed. {reason}"
        save_plan(services, plan)
        services.audit.append(
            run_id=plan.run_id,
            actor="agent",
            action="mutate_denied",
            detail={"plan_id": plan.id, "reason": reason},
        )
        trace.event(step="policy", decision=reason, outcome=status, request={"plan_id": plan.id})
        services.monitor.update(plan=plan.model_dump(), decision=reason)
        return _finish(services, trace, plan.run_id, status, summary, warnings, data_issues, blocked, plan.id, [])

    mutated: list[str] = []
    services.monitor.update(step="execute", decision=decisions[0][1])
    for step, (ok, reason) in zip(plan.steps, decisions, strict=True):
        services.kill.raise_if_tripped()
        try:
            await services.github.delete(step.path, body=step.body)
        except ToolCancelled:
            plan.status = "cancelled"
            save_plan(services, plan)
            raise
        except GitHubError as exc:
            plan.status = "blocked"
            save_plan(services, plan)
            summary = f"API error during {step.path}. Failing closed. {exc}"
            services.audit.append(
                run_id=plan.run_id,
                actor="agent",
                action="mutate_failed",
                detail={"path": step.path, "error": str(exc)},
            )
            trace.event(step="execute", tool=f"DELETE {step.path}", decision="fail closed", outcome="held")
            return _finish(services, trace, plan.run_id, "held", summary, warnings, data_issues, blocked, plan.id, mutated)
        mutated.append(step.path)
        services.audit.append(
            run_id=plan.run_id,
            actor="agent",
            action="mutate_executed",
            detail={"path": step.path, "reason": reason, "kind": step.kind},
        )
        trace.event(
            step="execute",
            tool=f"DELETE {step.path}",
            decision=reason,
            outcome="executed",
            request={"path": step.path},
        )
    plan.status = "executed"
    save_plan(services, plan)
    services.monitor.update(plan=plan.model_dump())
    summary = f"Executed plan {plan.id}. {plan.blast_radius}"
    return _finish(services, trace, plan.run_id, "executed", summary, warnings, data_issues, blocked, plan.id, mutated)


async def _cross_check(claims: list[Claim], services: Services) -> tuple[list[PlanStep], list[str]]:
    steps: list[PlanStep] = []
    notes: list[str] = []
    owner = services.settings.test_repo_owner
    repo = services.settings.test_repo_name
    for claim in claims:
        services.kill.raise_if_tripped()
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
                    reason=f"unknown SSH key {match['id']} ({match.get('title') or 'untitled'})",
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
                    reason=f"unknown account email {match['email']}",
                    primary=bool(match.get("primary")),
                    body={"emails": [match["email"]]},
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
                    reason=f"unknown deploy key {match['id']}",
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
            steps.append(
                PlanStep(
                    kind="webhook",
                    method="DELETE",
                    path=f"/repos/{owner}/{repo}/hooks/{match['id']}",
                    object_id=str(match["id"]),
                    owner=owner,
                    repo=repo,
                    reason=f"unknown webhook {match['id']}",
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
            if not protection:
                notes.append(f"Branch {claim.branch} has no live protection to remove.")
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
    bits = [step.reason for step in steps]
    return "Deletes " + "; ".join(bits) + ". Does not lock the account or touch known-good objects."


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
            headers={"Authorization": "Bearer [REDACTED]"} if not settings.llm_api_key else {"Authorization": f"Bearer {settings.llm_api_key}"},
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
