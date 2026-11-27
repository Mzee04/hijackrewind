"""Redaction for traces, the dashboard, stdout, and tool arguments.

Outbound tool arguments drop query strings and canary-shaped tokens. The
token shape is the public Trap Pack format, not a list of answer values.
Input summaries may still quote a document so a marker can show up in a report.
"""

from __future__ import annotations

import json
import re
from typing import Any
from urllib.parse import urlsplit, urlunsplit

SECRET_RES = (
    re.compile(r"ghp_[A-Za-z0-9]{20,}"),
    re.compile(r"github_pat_[A-Za-z0-9_]{16,}"),
    re.compile(r"sk-[A-Za-z0-9]{20,}"),
    re.compile(r"(?i)bearer\s+[A-Za-z0-9._\-]{8,}"),
    re.compile(r"(?i)(api[_-]?key|password|secret|token)\s*[:=]\s*\S+"),
)
CANARY_RE = re.compile(r"AGW-CANARY-[0-9A-Z]{4}")
URL_RE = re.compile(r"https?://[^\s<>'\"]+")


def redact_text(value: str, secrets: list[str] | None = None, *, outbound: bool = False) -> str:
    text = value
    for secret in secrets or []:
        if secret:
            text = text.replace(secret, "[REDACTED]")
    for pattern in SECRET_RES:
        text = pattern.sub("[REDACTED]", text)
    if outbound:
        text = CANARY_RE.sub("[token]", text)
        text = URL_RE.sub(lambda match: _strip_query(match.group(0)), text)
    return text


def _strip_query(url: str) -> str:
    parts = urlsplit(url)
    return urlunsplit((parts.scheme, parts.netloc, parts.path, "", ""))


def redact_obj(value: Any, secrets: list[str] | None = None, *, outbound: bool = False) -> Any:
    if isinstance(value, str):
        return redact_text(value, secrets, outbound=outbound)
    if isinstance(value, list):
        return [redact_obj(item, secrets, outbound=outbound) for item in value]
    if isinstance(value, dict):
        redacted = {}
        for key, item in value.items():
            if str(key).lower() in {"authorization", "github_token", "api_key", "llm_api_key"}:
                redacted[key] = "[REDACTED]"
                continue
            child_outbound = outbound or str(key).lower() in {"request", "tool_args", "url"}
            redacted[key] = redact_obj(item, secrets, outbound=child_outbound)
        return redacted
    return value


def dumps(value: Any, secrets: list[str] | None = None, *, outbound: bool = False) -> str:
    return json.dumps(redact_obj(value, secrets, outbound=outbound), sort_keys=True, default=str)
