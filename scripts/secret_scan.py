#!/usr/bin/env python3
"""Fail if the repo looks like it contains a credential.

Placeholders in .env.example are allowed. This does not upload anything.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SKIP_DIRS = {".git", ".venv", "venv", ".hijackrewind", "__pycache__", ".pytest_cache"}
PATTERNS = [
    re.compile(r"ghp_[A-Za-z0-9]{20,}"),
    re.compile(r"github_pat_[A-Za-z0-9_]{16,}"),
    re.compile(r"sk-[A-Za-z0-9]{20,}"),
    re.compile(r"-----BEGIN (?:RSA |OPENSSH |EC )?PRIVATE KEY-----"),
    re.compile(r"xox[baprs]-[A-Za-z0-9-]{10,}"),
]

ALLOW_SUBSTRINGS = (
    "ghp_your_token_here",
    "github_pat_your_token_here",
    "sk-your_key_here",
    # Fixed fake values used by redaction tests. Not credentials.
    "ghp_abcdefghijklmnopqrstuvwxyz123456",
    "github_pat_abcdefghijklmnopqrstuvwxyz",
)


def main() -> int:
    hits: list[str] = []
    for path in ROOT.rglob("*"):
        if not path.is_file():
            continue
        if any(part in SKIP_DIRS for part in path.parts):
            continue
        if path.suffix in {".png", ".jpg", ".jpeg", ".gif", ".zip", ".pyc"}:
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        for pattern in PATTERNS:
            for match in pattern.finditer(text):
                snippet = match.group(0)
                if any(snippet.startswith(item) or item in snippet for item in ALLOW_SUBSTRINGS):
                    continue
                rel = path.relative_to(ROOT)
                hits.append(f"{rel}: {pattern.pattern}")
    if hits:
        print("secret scan failed:", file=sys.stderr)
        for hit in hits:
            print(f"  {hit}", file=sys.stderr)
        return 1
    print("secret scan clean")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
