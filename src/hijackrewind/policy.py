"""Code-level authorization. Prompts, files, and the optional LLM cannot call this.

Policy table:

| Action | Disposition | Why |
| --- | --- | --- |
| Delete an unknown SSH key | auto | Reversible by posting the saved public key |
| Delete an unknown deploy key on the test repo | auto | Reversible by posting the saved public key |
| Delete a webhook whose host is not allowlisted | auto | Reversible by posting the saved config, except the secret GitHub does not return |
| Restore branch protection from the known-good document | auto | The body comes from the manifest, not from the alert |
| Delete an account email, GPG key, signing key, or collaborator | approval | Ambiguous or harder to undo |
| Delete a repository, change an org, or remove branch protection that is not a restore | approval or refused | Destructive |
| Revoke an OAuth grant, another PAT, or a web session | unavailable | No endpoint a user token can call |
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


def authorize(
    step: PlanStep,
    settings: Settings,
    manifest: Manifest,
    meter: CostMeter,
    *,
    allow_auto: bool,
    approved: bool,
) -> tuple[bool, str]:
    del allow_auto
    if step.disposition == "unavailable" or step.method == "NONE":
        return False, step.reason or UNAVAILABLE_REASONS.get(step.kind, "no supported endpoint")
    if settings.mode == "dry-run":
        return False, "mode is dry-run"
    if not repo_is_configured(step.path, settings.test_repo_owner, settings.test_repo_name):
        return False, "repo is outside the configured test repository"
    if object_is_known(step, manifest):
        return False, "object is on the known-good manifest"
    if step.primary:
        return False, "refusing to delete the primary email"
    if step.kind == "repo_delete":
        return False, UNAVAILABLE_REASONS["repo_delete"]
    if not meter.can_mutate():
        return False, "per-run mutate cap reached"
    if step.disposition == "auto":
        if step.kind == "ssh_key" and not settings.auto_execute_ssh_key:
            return False, "explicit approval required"
        return True, f"policy auto-execute for reversible {step.kind}"
    if approved:
        return True, "operator approval recorded in the audit log"
    return False, "explicit approval required"
