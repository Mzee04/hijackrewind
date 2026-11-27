"""Shared records. Decisions are data. Authorization happens in policy.py."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field


class Claim(BaseModel):
    kind: Literal[
        "ssh_key",
        "email",
        "gpg_key",
        "ssh_signing_key",
        "deploy_key",
        "webhook",
        "collaborator",
        "branch_protection",
        "oauth_grant",
        "pat",
        "session",
        "repo_delete",
    ]
    change: str = ""
    object_id: str | None = None
    title: str | None = None
    fingerprint: str | None = None
    email: str | None = None
    login: str | None = None
    branch: str | None = None
    repo_owner: str | None = None
    repo_name: str | None = None


class ChannelVerdict(BaseModel):
    verified: bool
    reason: str
    from_domain: str = ""
    dkim_domain: str = ""
    lookalike: bool = False
    pretends_github: bool = False


class Lure(BaseModel):
    kind: Literal["http", "mail"]
    host: str = ""
    path: str = "/"
    recipient: str = ""


class ScreenResult(BaseModel):
    visible_text: str
    summary: str
    warnings: list[str] = Field(default_factory=list)
    data_issues: list[str] = Field(default_factory=list)
    lures: list[Lure] = Field(default_factory=list)


class Document(BaseModel):
    source: str
    modality: str
    visible_text: str
    raw_text: str
    subject: str = ""
    from_name: str = ""
    from_address: str = ""
    from_domain: str = ""
    reply_to: str = ""
    authentication_results: str = ""
    raw_bytes: bytes = Field(default=b"", exclude=True)
    screen: ScreenResult | None = None


class PlanStep(BaseModel):
    kind: str
    method: Literal["DELETE", "PUT", "POST", "NONE"]
    path: str
    object_id: str
    reason: str
    owner: str = ""
    repo: str = ""
    primary: bool = False
    body: dict | None = None
    disposition: Literal["auto", "approval", "unavailable"] = "approval"
    before: dict | None = None
    reverse_method: Literal["DELETE", "PUT", "POST"] | None = None
    reverse_path: str | None = None
    reverse_body: dict | None = None


class Plan(BaseModel):
    id: str
    run_id: str
    steps: list[PlanStep]
    blast_radius: str
    status: Literal[
        "draft",
        "pending_approval",
        "dry_run",
        "executing",
        "executed",
        "denied",
        "cancelled",
        "blocked",
    ] = "draft"
    approved: bool = False
    approval_used: bool = False
    created_at: str = ""
    expires_at: str = ""


class RunResult(BaseModel):
    run_id: str
    status: Literal[
        "held",
        "quarantined",
        "executed",
        "dry_run",
        "pending_approval",
        "cancelled",
        "failed",
    ]
    summary: str
    warnings: list[str] = Field(default_factory=list)
    data_issues: list[str] = Field(default_factory=list)
    blocked: list[dict] = Field(default_factory=list)
    plan_id: str | None = None
    mutated: list[str] = Field(default_factory=list)
    trace_path: str = ""
    cost_points: int = 0
    error: str | None = None
    explanation: str | None = None
