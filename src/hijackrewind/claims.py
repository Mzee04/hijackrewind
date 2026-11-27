"""Pull a structured account-change claim out of visible text.

Identifiers are regex captures. Raw document text is never copied into a URL.
"""

from __future__ import annotations

import re

from hijackrewind.models import Claim

_KEY_ID = re.compile(r"\bkey\s*id\s*[:#]?\s*(\d{1,12})\b", re.I)
_FINGERPRINT = re.compile(r"\b(SHA256:[A-Za-z0-9+/]{20,}={0,2})\b")
_TITLE = re.compile(r"\b(?:key\s+)?title\s*:\s*([A-Za-z0-9_ .:/-]{1,80})", re.I)
_EMAIL = re.compile(r"\b([A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,})\b")
_HOOK_ID = re.compile(r"\bhook\s*id\s*[:#]?\s*(\d{1,12})\b", re.I)
_LOGIN = re.compile(r"\bcollaborator\s+([A-Za-z0-9](?:[A-Za-z0-9-]{0,37}))\b", re.I)
_BRANCH = re.compile(r"\bbranch\s+([A-Za-z0-9._/-]{1,80})\b", re.I)


def extract_claims(visible_text: str) -> list[Claim]:
    text = visible_text or ""
    lowered = text.lower()
    claims: list[Claim] = []
    key_ids = _KEY_ID.findall(text)
    fingerprints = _FINGERPRINT.findall(text)
    title_match = _TITLE.search(text)
    title = title_match.group(1).strip() if title_match else None

    if re.search(r"\b(ssh signing key|signing key)\b", lowered) and key_ids:
        claims.append(Claim(kind="ssh_signing_key", object_id=key_ids[0], title=title, fingerprint=fingerprints[0] if fingerprints else None))
    elif re.search(r"\b(gpg key|gpg_key)\b", lowered) and key_ids:
        claims.append(Claim(kind="gpg_key", object_id=key_ids[0], title=title))
    elif re.search(r"\bdeploy key\b", lowered) and key_ids:
        claims.append(Claim(kind="deploy_key", object_id=key_ids[0], title=title, fingerprint=fingerprints[0] if fingerprints else None))
    elif re.search(r"\b(public key|ssh key)\b", lowered) and (key_ids or fingerprints):
        claims.append(
            Claim(
                kind="ssh_key",
                object_id=key_ids[0] if key_ids else None,
                title=title,
                fingerprint=fingerprints[0] if fingerprints else None,
            )
        )

    if re.search(r"\b(email address|new email|added the email)\b", lowered):
        addresses = [item for item in _EMAIL.findall(text) if not item.lower().endswith("@github.com")]
        if addresses:
            claims.append(Claim(kind="email", email=addresses[-1]))

    if "webhook" in lowered:
        hook_ids = _HOOK_ID.findall(text)
        if hook_ids:
            claims.append(Claim(kind="webhook", object_id=hook_ids[0]))

    if "collaborator" in lowered:
        login = _LOGIN.search(text)
        if login:
            claims.append(Claim(kind="collaborator", login=login.group(1)))

    if "branch protection" in lowered:
        branch = _BRANCH.search(text)
        if branch and re.search(r"\b(added|enabled|removed|disabled|changed)\b", lowered):
            claims.append(Claim(kind="branch_protection", branch=branch.group(1)))

    return claims
