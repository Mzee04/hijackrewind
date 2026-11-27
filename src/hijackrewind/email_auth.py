"""Authentication-Results alignment. Fail closed when the attestation is missing.

This parses the border MTA's Authentication-Results header. It does not
recompute a DKIM signature. Sandbox fixtures are not signed by GitHub.
"""

from __future__ import annotations

import re

from hijackrewind.models import ChannelVerdict, Document

_DKIM = re.compile(r"\bdkim\s*=\s*(pass|fail|none|neutral|temperror|permerror|policy)\b", re.I)
_HEADER_D = re.compile(r"\bheader\.d\s*=\s*([A-Za-z0-9.-]+)", re.I)
_ALERT = re.compile(
    r"new public key|ssh key|deploy key|signing key|gpg key|was added to your account|webhook",
    re.I,
)


def _labels(domain: str) -> str:
    return domain.lower().strip().rstrip(".")


def is_allowlisted(domain: str, allowlist: list[str]) -> bool:
    candidate = _labels(domain)
    if not candidate:
        return False
    for allowed in allowlist:
        base = _labels(allowed)
        if candidate == base or candidate.endswith("." + base):
            return True
    return False


def _edit_distance(left: str, right: str) -> int:
    if abs(len(left) - len(right)) > 2:
        return 3
    previous = list(range(len(right) + 1))
    for i, lch in enumerate(left, start=1):
        current = [i]
        for j, rch in enumerate(right, start=1):
            current.append(min(previous[j] + 1, current[j - 1] + 1, previous[j - 1] + (lch != rch)))
        previous = current
    return previous[-1]


def is_lookalike(domain: str, allowlist: list[str]) -> bool:
    """True when the domain imitates an allowlisted domain without being one."""
    candidate = _labels(domain)
    if not candidate or is_allowlisted(candidate, allowlist):
        return False
    for allowed in allowlist:
        base = _labels(allowed)
        if base and base in candidate:
            return True
        brand = base.split(".")[0]
        first = candidate.split(".")[0]
        same_suffix = candidate.split(".")[-1:] == base.split(".")[-1:]
        if same_suffix and brand and _edit_distance(first, brand) == 1:
            return True
        folded = candidate.replace("0", "o").replace("1", "l")
        if folded == base:
            return True
    parts = candidate.split(".")
    brand = parts[-2] if len(parts) >= 2 else parts[0]
    if brand != "github" and _edit_distance(brand, "github") <= 1:
        return True
    if "github" in candidate and not is_allowlisted(candidate, ["github.com"]):
        return True
    return False


def verify_channel(document: Document, allowlist: list[str]) -> ChannelVerdict:
    domain = _labels(document.from_domain)
    lookalike = is_lookalike(domain, allowlist) if domain else False
    visible = document.visible_text or ""
    chrome = f"{document.from_name} {document.subject}"
    pretends = False
    if document.modality == "email":
        brandish = "github" in chrome.lower() or "github" in domain
        alertish = bool(_ALERT.search(visible) or _ALERT.search(document.subject or ""))
        if lookalike or (brandish and alertish and not is_allowlisted(domain, allowlist)):
            pretends = True
        if brandish and alertish and not document.authentication_results:
            pretends = True

    if document.modality != "email":
        return ChannelVerdict(
            verified=False,
            reason="only an aligned email can authorize a revert",
            from_domain=domain,
            lookalike=lookalike,
            pretends_github=False,
        )

    header = document.authentication_results or ""
    if not header.strip():
        return ChannelVerdict(
            verified=False,
            reason="missing Authentication-Results",
            from_domain=domain,
            lookalike=lookalike,
            pretends_github=pretends,
        )
    dkim_match = _DKIM.search(header)
    dkim = dkim_match.group(1).lower() if dkim_match else ""
    d_match = _HEADER_D.search(header)
    d_domain = _labels(d_match.group(1)) if d_match else ""
    if dkim != "pass":
        return ChannelVerdict(
            verified=False,
            reason=f"dkim is {dkim or 'missing'}",
            from_domain=domain,
            dkim_domain=d_domain,
            lookalike=lookalike,
            pretends_github=pretends,
        )
    if not d_domain:
        return ChannelVerdict(
            verified=False,
            reason="dkim=pass without header.d",
            from_domain=domain,
            lookalike=lookalike,
            pretends_github=pretends,
        )
    aligned = domain == d_domain or domain.endswith("." + d_domain)
    if not aligned:
        return ChannelVerdict(
            verified=False,
            reason="From domain is not aligned with dkim d=",
            from_domain=domain,
            dkim_domain=d_domain,
            lookalike=lookalike or is_lookalike(d_domain, allowlist),
            pretends_github=pretends or is_lookalike(d_domain, allowlist),
        )
    if not is_allowlisted(d_domain, allowlist):
        fake = is_lookalike(d_domain, allowlist)
        return ChannelVerdict(
            verified=False,
            reason="lookalike sending domain" if fake else "sending domain is not allowlisted",
            from_domain=domain,
            dkim_domain=d_domain,
            lookalike=fake,
            pretends_github=pretends or fake,
        )
    return ChannelVerdict(
        verified=True,
        reason=f"dkim=pass aligned with {d_domain}",
        from_domain=domain,
        dkim_domain=d_domain,
        lookalike=False,
        pretends_github=False,
    )
