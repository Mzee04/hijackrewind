"""Code-level authorization. The plan's own disposition label is not consulted.

Auto-execute requires all of:
- the caller passed allow_auto=True
- the action kind is one this config turns on
- the live object was matched to the claim and is not on the known-good manifest
"""

from __future__ import annotations

from hijackrewind.config import Settings
from hijackrewind.egress import repo_is_configured
from hijackrewind.github_client import CostMeter
from hijackrewind.manifest import Manifest
from hijackrewind.models import PlanStep

UNAVAILABLE_REASONS = {
    "oauth_grant": (
        "No mutate was sent. Revoking an OAuth grant requires the application's "
        "client id and client secret. A user token cannot call that endpoint."
    ),
    "pat": (
        "No mutate was sent. GitHub removed the authorizations API. A user token "
        "cannot list or revoke other personal access tokens."
    ),
    "session": "No mutate was sent. GitHub has no REST endpoint that revokes web sessions.",
    "repo_delete": "No mutate was sent. Deleting a repository is refused by policy.",
}


def object_is_known(step: PlanStep, manifest: Manifest) -> bool:
    if step.kind == "ssh_key":
        return manifest.ssh_known(object_id=step.object_id, fingerprint=None)
    if step.kind == "email":
        return manifest.email_known(step.object_id)
    if step.kind == "gpg_key":
        return manifest.id_known(manifest.gpg_keys, step.object_id)
    if step.kind == "ssh_signing_key":
        return manifest.id_known(manifest.ssh_signing_keys, step.object_id)
    repo = manifest.repo(step.owner, step.repo)
    if step.kind == "deploy_key":
        return manifest.id_known(repo.deploy_keys, step.object_id)
    if step.kind == "webhook":
        return manifest.id_known(repo.webhooks, step.object_id)
    if step.kind == "collaborator":
        return step.object_id.lower() in {item.lower() for item in repo.collaborators}
    if step.kind == "branch_protection" and step.method == "DELETE":
        return step.object_id in repo.protected_branches
    return False


def classify(step: PlanStep, settings: Settings, manifest: Manifest) -> str:
    """unknown, suspicious, confirmed, known, or unavailable. Display and policy share this."""
    if step.kind in UNAVAILABLE_REASONS or step.method == "NONE":
        return "unavailable"
    if object_is_known(step, manifest):
        return "known"
    if step.kind == "branch_protection" and step.method == "PUT":
        saved = manifest.repo(step.owner, step.repo).protections.get(step.object_id)
        if saved and step.body == saved:
            return "confirmed"
        return "suspicious"
    if not step.before:
        return "unknown"
    live_id = str(step.before.get("id", step.before.get("email", "")))
    if str(step.object_id) not in {live_id, str(step.before.get("email", "")).lower()}:
        return "suspicious"
    if step.kind == "webhook":
        return "confirmed" if _host_unknown(step, settings) else "suspicious"
    return "confirmed"


def _host_unknown(step: PlanStep, settings: Settings) -> bool:
    from urllib.parse import urlparse

    host = (urlparse(((step.before or {}).get("config") or {}).get("url", "")).hostname or "").lower()
    return bool(host) and host not in settings.webhook_hosts()


def _config_allows_auto(step: PlanStep, settings: Settings) -> bool:
    if step.kind == "ssh_key" and step.method == "DELETE":
        return settings.auto_execute_ssh_key
    if step.kind == "deploy_key" and step.method == "DELETE":
        return settings.auto_execute_containment
    if step.kind == "webhook" and step.method == "DELETE":
        return settings.auto_execute_containment and _host_unknown(step, settings)
    if step.kind == "branch_protection" and step.method == "PUT":
        return settings.auto_execute_containment
    return False


def authorize(
    step: PlanStep,
    settings: Settings,
    manifest: Manifest,
    meter: CostMeter,
    *,
    allow_auto: bool,
    approved: bool,
) -> tuple[bool, str]:
    kind = classify(step, settings, manifest)
    if kind == "unavailable":
        return False, step.reason or UNAVAILABLE_REASONS.get(step.kind, "no supported endpoint")
    if settings.mode == "dry-run":
        return False, "mode is dry-run"
    if step.method not in {"DELETE", "PUT", "POST"}:
        return False, "method is not a containment mutate"
    if not repo_is_configured(step.path, settings.test_repo_owner, settings.test_repo_name):
        return False, "repo is outside the configured test repository"
    if kind == "known" or object_is_known(step, manifest):
        return False, "object is on the known-good manifest"
    if step.primary:
        return False, "refusing to delete the primary email"
    if step.kind == "repo_delete":
        return False, UNAVAILABLE_REASONS["repo_delete"]
    if kind != "confirmed":
        return False, f"classification is {kind}; explicit approval is not enough without a confirmed match"
    if not meter.can_mutate():
        return False, "per-run mutate cap reached"
    if allow_auto and _config_allows_auto(step, settings):
        return True, f"policy auto-execute for confirmed {step.kind}"
    if approved:
        return True, "operator approval recorded in the audit log"
    return False, "explicit approval required"


def authorize_rewind(record: dict, settings: Settings) -> tuple[bool, str]:
    """Operator restore. Dry-run is refused here and again in the HTTP client."""
    if settings.mode == "dry-run":
        return False, "mode is dry-run"
    if record.get("status") == "rolled_back":
        return True, "already rolled back"
    if record.get("status") == "outcome_unknown":
        return False, "outcome unknown; run reconcile before rewind"
    if record.get("status") not in {"pending", "executed"}:
        return False, "action is not in a rewindable state"
    method = record.get("reverse_method")
    path = record.get("reverse_path") or ""
    if method not in {"POST", "PUT"} or not path:
        return False, "this action has no reversible API call"
    if not repo_is_configured(path, settings.test_repo_owner, settings.test_repo_name):
        return False, "rewind path is outside the configured test repository"
    return True, "policy allows rewind of the saved before-state"
