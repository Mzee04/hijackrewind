"""Channel checks. A revert needs a DKIM signature that verifies in code.

Authentication-Results is recorded and ignored as proof. Sandbox mode resolves
the test key locally. Live mode uses DNS. Header-only dkim=pass is unverified.
"""

from __future__ import annotations

import re

from hijackrewind.dkim_verify import check_signature
from hijackrewind.models import ChannelVerdict, Document

_DKIM = re.compile(r"\bdkim\s*=\s*(pass|fail|none|neutral|temperror|permerror|policy)\b", re.I)
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


def verify_channel(document: Document, allowlist: list[str], *, dns: str = "local") -> ChannelVerdict:
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

    signature = check_signature(document.raw_bytes or b"", dns=dns)
    d_domain = _labels(signature.domain)
    header = document.authentication_results or ""
    header_match = _DKIM.search(header)
    header_says_pass = bool(header_match and header_match.group(1).lower() == "pass")
    signed_lookalike = bool(d_domain) and is_lookalike(d_domain, allowlist)
    if not signature.ok:
        reason = signature.reason
        if header_says_pass and "missing" in reason:
            reason = "Authentication-Results says dkim=pass but there is no verifiable signature"
        return ChannelVerdict(
            verified=False,
            reason=reason,
            from_domain=domain,
            dkim_domain=d_domain,
            lookalike=lookalike or signed_lookalike,
            pretends_github=pretends or signed_lookalike,
        )
    aligned = bool(d_domain) and (domain == d_domain or domain.endswith("." + d_domain))
    if not aligned:
        return ChannelVerdict(
            verified=False,
            reason="From domain is not aligned with the DKIM signature",
            from_domain=domain,
            dkim_domain=d_domain,
            lookalike=lookalike or signed_lookalike,
            pretends_github=pretends or signed_lookalike,
        )
    if not is_allowlisted(d_domain, allowlist):
        fake = is_lookalike(d_domain, allowlist)
        return ChannelVerdict(
            verified=False,
            reason="lookalike sending domain" if fake else "signing domain is not allowlisted",
            from_domain=domain,
            dkim_domain=d_domain,
            lookalike=fake,
            pretends_github=pretends or fake,
        )
    return ChannelVerdict(
        verified=True,
        reason=f"DKIM signature verified for {d_domain}",
        from_domain=domain,
        dkim_domain=d_domain,
        lookalike=False,
        pretends_github=False,
    )
