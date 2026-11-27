"""Known-good objects. Anything on this list is not a revert target."""

from __future__ import annotations

import json
from pathlib import Path

from pydantic import BaseModel, Field


class RepoManifest(BaseModel):
    deploy_keys: list[dict] = Field(default_factory=list)
    webhooks: list[dict] = Field(default_factory=list)
    collaborators: list[str] = Field(default_factory=list)
    protected_branches: list[str] = Field(default_factory=list)
    protections: dict[str, dict] = Field(default_factory=dict)


class Manifest(BaseModel):
    ssh_keys: list[dict] = Field(default_factory=list)
    emails: list[str] = Field(default_factory=list)
    gpg_keys: list[dict] = Field(default_factory=list)
    ssh_signing_keys: list[dict] = Field(default_factory=list)
    repos: dict[str, RepoManifest] = Field(default_factory=dict)

    def ssh_known(self, *, object_id: str | None, fingerprint: str | None) -> bool:
        for item in self.ssh_keys:
            if object_id is not None and str(item.get("id")) == str(object_id):
                return True
            if fingerprint and item.get("fingerprint") == fingerprint:
                return True
        return False

    def email_known(self, email: str) -> bool:
        return email.lower() in {item.lower() for item in self.emails}

    def id_known(self, items: list[dict], object_id: str | None) -> bool:
        if object_id is None:
            return False
        return any(str(item.get("id")) == str(object_id) for item in items)

    def repo(self, owner: str, name: str) -> RepoManifest:
        return self.repos.get(f"{owner}/{name}", RepoManifest())


def load_manifest(path: Path | str) -> Manifest:
    file_path = Path(path)
    if not file_path.is_file():
        return Manifest()
    return Manifest.model_validate(json.loads(file_path.read_text(encoding="utf-8")))
