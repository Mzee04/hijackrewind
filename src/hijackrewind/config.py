"""Typed configuration. Tokens stay in the environment and are never written out."""

from __future__ import annotations

from pathlib import Path
from typing import Literal
from urllib.parse import urlparse

from pydantic import AliasChoices, Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Operator settings. Init arguments win over environment variables."""

    model_config = SettingsConfigDict(
        extra="ignore",
        populate_by_name=True,
    )

    mode: Literal["sandbox", "dry-run", "live"] = Field(
        default="sandbox",
        validation_alias=AliasChoices("HIJACKREWIND_MODE", "MODE"),
    )
    stub_url: str = Field(default="http://127.0.0.1:8088", validation_alias="HIJACKREWIND_STUB_URL")
    github_token: str = Field(default="", validation_alias="GITHUB_TOKEN")
    github_api_url: str = Field(default="https://api.github.com", validation_alias="GITHUB_API_URL")
    test_repo_owner: str = Field(default="test-owner", validation_alias="TEST_REPO_OWNER")
    test_repo_name: str = Field(default="test-repo", validation_alias="TEST_REPO_NAME")
    manifest_path: str = Field(
        default="sandbox/fixtures/known-good.json",
        validation_alias="HIJACKREWIND_MANIFEST",
    )
    sender_allowlist: str = Field(default="github.com", validation_alias="HIJACKREWIND_SENDER_ALLOWLIST")
    auto_execute_ssh_key: bool = Field(default=True, validation_alias="HIJACKREWIND_AUTO_EXECUTE_SSH_KEY")
    mutate_cap: int = Field(default=1, validation_alias="HIJACKREWIND_MUTATE_CAP")
    dashboard_host: str = Field(default="127.0.0.1", validation_alias="HIJACKREWIND_DASHBOARD_HOST")
    dashboard_port: int = Field(default=8765, validation_alias="HIJACKREWIND_DASHBOARD_PORT")
    llm_enabled: bool = Field(default=False, validation_alias="HIJACKREWIND_LLM_ENABLED")
    llm_base_url: str = Field(default="", validation_alias="HIJACKREWIND_LLM_BASE_URL")
    llm_api_key: str = Field(default="", validation_alias="HIJACKREWIND_LLM_API_KEY")
    llm_model: str = Field(default="", validation_alias="HIJACKREWIND_LLM_MODEL")
    mailpit_url: str = Field(default="http://127.0.0.1:8025", validation_alias="MAILPIT_URL")
    trace_dir: str = Field(default="traces", validation_alias="HIJACKREWIND_TRACE_DIR")
    audit_log: str = Field(default=".hijackrewind/audit.jsonl", validation_alias="HIJACKREWIND_AUDIT_LOG")
    home: str = Field(default=".hijackrewind", validation_alias="HIJACKREWIND_HOME")
    delete_delay: float = Field(default=0.0, validation_alias="HIJACKREWIND_DELETE_DELAY")
    max_retry_wait: float = Field(default=2.0, validation_alias="HIJACKREWIND_MAX_RETRY_WAIT")

    def allowlisted_domains(self) -> list[str]:
        return [part.strip().lower().rstrip(".") for part in self.sender_allowlist.split(",") if part.strip()]

    def api_base(self) -> str:
        if self.mode == "live":
            return self.github_api_url.rstrip("/")
        return self.stub_url.rstrip("/")

    def api_host(self) -> str:
        return (urlparse(self.api_base()).hostname or "").lower()

    def uses_stub(self) -> bool:
        return self.mode != "live"

    def secret_values(self) -> list[str]:
        values = [self.github_token, self.llm_api_key]
        return [value for value in values if value]

    def kill_file(self) -> Path:
        return Path(self.home) / "KILL"

    def plan_dir(self) -> Path:
        return Path(self.home) / "plans"


def load_settings(env_file: str | None = ".env") -> Settings:
    if env_file and Path(env_file).is_file():
        return Settings(_env_file=env_file)
    return Settings(_env_file=None)
