"""Code-level authorization. Prompts, files, and the optional LLM cannot call this."""

from __future__ import annotations

from hijackrewind.config import Settings
from hijackrewind.egress import repo_is_configured
from hijackrewind.github_client import CostMeter
from hijackrewind.manifest import Manifest
from hijackrewind.models import PlanStep


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
    if step.kind == "branch_protection":
        return step.object_id in repo.protected_branches
    return True


def authorize(
    step: PlanStep,
    settings: Settings,
    manifest: Manifest,
    meter: CostMeter,
    *,
    allow_auto: bool,
    approved: bool,
) -> tuple[bool, str]:
    if step.method != "DELETE":
        return False, "only DELETE reverts are on the allowlist"
    if not repo_is_configured(step.path, settings.test_repo_owner, settings.test_repo_name):
        return False, "repo is outside the configured test repository"
    if object_is_known(step, manifest):
        return False, "object is on the known-good manifest"
    if step.primary:
        return False, "refusing to delete the primary email"
    if settings.mode == "dry-run":
        return False, "mode is dry-run"
    if not meter.can_mutate():
        return False, "per-run mutate cap reached"
    if allow_auto and approved:
        return False, "auto-execute and approval were both set"
    if allow_auto and step.kind == "ssh_key" and settings.auto_execute_ssh_key:
        return True, "policy auto-execute for one verified unknown ssh key"
    if approved:
        return True, "operator approval recorded in the audit log"
    return False, "explicit approval required"
