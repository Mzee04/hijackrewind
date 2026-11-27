"""Typed configuration. Tokens stay in the environment and are never written out."""

from __future__ import annotations

from pathlib import Path
from typing import Literal
from urllib.parse import urlparse

from pydantic import AliasChoices, Field, SecretStr, field_validator
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
    github_token: SecretStr = Field(default=SecretStr(""), validation_alias="GITHUB_TOKEN")
    github_api_url: str = Field(default="https://api.github.com", validation_alias="GITHUB_API_URL")
    test_repo_owner: str = Field(default="test-owner", validation_alias="TEST_REPO_OWNER")
    test_repo_name: str = Field(default="test-repo", validation_alias="TEST_REPO_NAME")
    manifest_path: str = Field(
        default="sandbox/fixtures/known-good.json",
        validation_alias="HIJACKREWIND_MANIFEST",
    )
    sender_allowlist: str = Field(default="github.com", validation_alias="HIJACKREWIND_SENDER_ALLOWLIST")
    auto_execute_ssh_key: bool = Field(default=False, validation_alias="HIJACKREWIND_AUTO_EXECUTE_SSH_KEY")
    auto_execute_containment: bool = Field(default=False, validation_alias="HIJACKREWIND_AUTO_EXECUTE_CONTAINMENT")
    mutate_cap: int = Field(default=1, validation_alias="HIJACKREWIND_MUTATE_CAP")
    dashboard_host: str = Field(default="127.0.0.1", validation_alias="HIJACKREWIND_DASHBOARD_HOST")
    dashboard_port: int = Field(default=8765, validation_alias="HIJACKREWIND_DASHBOARD_PORT")
    llm_enabled: bool = Field(default=False, validation_alias="HIJACKREWIND_LLM_ENABLED")
    llm_base_url: str = Field(default="", validation_alias="HIJACKREWIND_LLM_BASE_URL")
    llm_api_key: SecretStr = Field(default=SecretStr(""), validation_alias="HIJACKREWIND_LLM_API_KEY")
    dashboard_token: SecretStr = Field(default=SecretStr(""), validation_alias="HIJACKREWIND_DASHBOARD_TOKEN")
    audit_hmac_key: SecretStr = Field(default=SecretStr(""), validation_alias="HIJACKREWIND_AUDIT_HMAC_KEY")
    plan_ttl_seconds: int = Field(default=900, validation_alias="HIJACKREWIND_PLAN_TTL_SECONDS")
    llm_model: str = Field(default="", validation_alias="HIJACKREWIND_LLM_MODEL")
    mailpit_url: str = Field(default="http://127.0.0.1:8025", validation_alias="MAILPIT_URL")
    trace_dir: str = Field(default="traces", validation_alias="HIJACKREWIND_TRACE_DIR")
    audit_log: str = Field(default=".hijackrewind/audit.jsonl", validation_alias="HIJACKREWIND_AUDIT_LOG")
    home: str = Field(default=".hijackrewind", validation_alias="HIJACKREWIND_HOME")
    delete_delay: float = Field(default=0.0, validation_alias="HIJACKREWIND_DELETE_DELAY")
    max_retry_wait: float = Field(default=2.0, validation_alias="HIJACKREWIND_MAX_RETRY_WAIT")
    dkim_dns: str = Field(default="", validation_alias="HIJACKREWIND_DKIM_DNS")
    test_github_login: str = Field(default="", validation_alias="TEST_GITHUB_LOGIN")
    request_timeout: float = Field(default=30.0, validation_alias="HIJACKREWIND_REQUEST_TIMEOUT")
    webhook_host_allowlist: str = Field(default="", validation_alias="HIJACKREWIND_WEBHOOK_HOST_ALLOWLIST")

    def webhook_hosts(self) -> set[str]:
        return {part.strip().lower() for part in self.webhook_host_allowlist.split(",") if part.strip()}

    @field_validator("github_api_url")
    @classmethod
    def _official_api(cls, value: str) -> str:
        parsed = urlparse(value)
        if parsed.scheme != "https" or (parsed.hostname or "").lower() != "api.github.com":
            raise ValueError("GITHUB_API_URL must be https://api.github.com")
        if parsed.username or parsed.password or parsed.query or parsed.fragment:
            raise ValueError("GITHUB_API_URL must be https://api.github.com with no userinfo or query")
        return "https://api.github.com"

    def dkim_mode(self) -> str:
        choice = self.dkim_dns.strip().lower()
        if choice in {"local", "live"}:
            return choice
        return "live" if self.mode == "live" else "local"

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
        values = [
            reveal(self.github_token),
            reveal(self.llm_api_key),
            reveal(self.dashboard_token),
            reveal(self.audit_hmac_key),
        ]
        return [value for value in values if value]

    def kill_file(self) -> Path:
        return Path(self.home) / "KILL"

    def plan_dir(self) -> Path:
        return Path(self.home) / "plans"


def reveal(value: SecretStr | str | None) -> str:
    if value is None:
        return ""
    if isinstance(value, SecretStr):
        return value.get_secret_value()
    return str(value)


def load_settings(env_file: str | None = ".env") -> Settings:
    if env_file and Path(env_file).is_file():
        return Settings(_env_file=env_file)
    return Settings(_env_file=None)
