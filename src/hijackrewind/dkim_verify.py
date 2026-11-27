"""Cryptographic DKIM checks.

Sandbox and tests use an injected resolver. The bundled test key verifies the
signed fixture with no network. Live mode calls DNS. A header that only says
dkim=pass is not a signature.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from functools import lru_cache

import dkim

from hijackrewind.runtime import repo_root

SELECTOR = "test"
DOMAIN = "github.com"
BUNDLED_NAME = b"test._domainkey.github.com."
_EXTRA: dict[bytes, bytes] = {}
_SIGNED_HEADERS = [b"from", b"to", b"subject", b"date", b"message-id"]
_D_PARAM = re.compile(br"\bd=([^;\s]+)", re.I)


@dataclass(frozen=True)
class SignatureCheck:
    ok: bool
    domain: str
    reason: str


def register_dkim_txt(fqdn: str, txt: str) -> None:
    """Install a TXT record on the local resolver. Tests use this for ephemeral keys."""
    name = fqdn.strip().rstrip(".").lower().encode() + b"."
    _EXTRA[name] = txt.encode()


def local_dns(name: bytes, timeout: int = 5) -> bytes | None:
    del timeout
    key = name if name.endswith(b".") else name + b"."
    key = key.lower()
    if key in _EXTRA:
        return _EXTRA[key]
    if key == BUNDLED_NAME:
        bundled = _bundled_txt()
        return bundled.encode() if bundled else None
    return None


@lru_cache(maxsize=1)
def _bundled_txt() -> str:
    path = repo_root() / "sandbox" / "fixtures" / "dkim-test-key.txt"
    if not path.is_file():
        return ""
    return path.read_text(encoding="utf-8").strip()


def sign_message(message: bytes, *, selector: str, domain: str, privkey_pem: bytes) -> bytes:
    """Return message with a DKIM-Signature header prepended. message is CRLF bytes."""
    signature = dkim.sign(
        message,
        selector.encode(),
        domain.encode(),
        privkey_pem,
        include_headers=_SIGNED_HEADERS,
    )
    return signature + message


def check_signature(raw: bytes, *, dns: str = "local") -> SignatureCheck:
    domain = _first_domain(raw)
    if b"dkim-signature:" not in raw.lower():
        return SignatureCheck(False, domain, "missing a verifiable DKIM signature")
    dnsfunc = None if dns == "live" else local_dns
    try:
        ok = bool(dkim.verify(raw, dnsfunc=dnsfunc))
    except Exception:
        return SignatureCheck(False, domain, "DKIM verification raised an error")
    if not ok:
        return SignatureCheck(False, domain, "DKIM signature did not verify")
    if not domain:
        return SignatureCheck(False, "", "DKIM signature did not name a domain")
    return SignatureCheck(True, domain, f"DKIM signature verified for {domain}")


def _first_domain(raw: bytes) -> str:
    for line in _unfold(raw):
        if line.lower().startswith(b"dkim-signature:"):
            match = _D_PARAM.search(line)
            if match:
                return match.group(1).decode("ascii", errors="replace").lower().rstrip(".")
    return ""


def _unfold(raw: bytes) -> list[bytes]:
    unfolded: list[bytes] = []
    current = b""
    for line in raw.splitlines():
        if line[:1] in (b" ", b"\t") and current:
            current += b" " + line.strip()
            continue
        if current:
            unfolded.append(current)
        current = line
    if current:
        unfolded.append(current)
    return unfolded
