"""Cryptographic DKIM checks.

Sandbox and tests use an injected resolver. The bundled test key verifies the
signed fixture with no network. Live mode calls DNS. A header that only says
dkim=pass is not a signature.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from email.utils import parsedate_to_datetime
from functools import lru_cache
from pathlib import Path

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
    header = _signature_header(raw)
    if header is None:
        return SignatureCheck(False, domain, "DKIM signature header could not be read")
    if re.search(br"(?:^|;)\s*l=", header, re.I):
        return SignatureCheck(False, domain, "DKIM l= body-length tag is rejected")
    signed = _signed_header_names(header)
    missing = [name for name in ("from", "subject", "date") if name not in signed]
    if missing:
        return SignatureCheck(False, domain, "DKIM signature does not cover " + ", ".join(missing))
    if _header_count(raw, b"from:") != 1 or _header_count(raw, b"subject:") != 1:
        return SignatureCheck(False, domain, "duplicate From or Subject header")
    fresh, why = _fresh(raw, header)
    if not fresh:
        return SignatureCheck(False, domain, why)
    if not domain:
        return SignatureCheck(False, "", "DKIM signature did not name a domain")
    return SignatureCheck(True, domain, f"DKIM signature verified for {domain}")


def claim_text(raw: bytes) -> str:
    """Text the signature covered, limited to the text/plain body. Not the HTML part."""
    try:
        from email import policy
        from email.parser import BytesParser

        message = BytesParser(policy=policy.default).parsebytes(raw)
    except Exception:
        return ""
    if message.is_multipart():
        chunks = []
        for part in message.walk():
            if part.get_content_type() == "text/plain":
                try:
                    content = part.get_content()
                except Exception:
                    content = ""
                if isinstance(content, str):
                    chunks.append(content)
        return "\n".join(chunks)
    try:
        content = message.get_content()
    except Exception:
        return ""
    return content if isinstance(content, str) else ""


def remember_message(home: Path, raw: bytes) -> bool:
    """Return False when this Message-ID and signature were already processed."""
    digest = hashlib.sha256(_replay_material(raw)).hexdigest()
    path = Path(home) / "seen-messages.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    seen = set(json.loads(path.read_text(encoding="utf-8"))) if path.is_file() else set()
    if digest in seen:
        return False
    seen.add(digest)
    path.write_text(json.dumps(sorted(seen)), encoding="utf-8")
    return True


def _replay_material(raw: bytes) -> bytes:
    header = _signature_header(raw) or b""
    message_id = b""
    for line in _unfold(raw):
        if line.lower().startswith(b"message-id:"):
            message_id = line
            break
    return message_id + b"\n" + header


def _signature_header(raw: bytes) -> bytes | None:
    for line in _unfold(raw):
        if line.lower().startswith(b"dkim-signature:"):
            return line
    return None


def _signed_header_names(header: bytes) -> set[str]:
    match = re.search(br"\bh=([^;]+)", header, re.I)
    if not match:
        return set()
    return {part.strip().lower() for part in match.group(1).decode("ascii", errors="ignore").split(":") if part.strip()}


def _header_count(raw: bytes, prefix: bytes) -> int:
    return sum(1 for line in _unfold(raw) if line.lower().startswith(prefix))


def _fresh(raw: bytes, header: bytes) -> tuple[bool, str]:
    now = datetime.now(timezone.utc)
    window = timedelta(days=14)
    stamped = re.search(br"(?:^|;)\s*t=(\d+)", header)
    if stamped:
        signed_at = datetime.fromtimestamp(int(stamped.group(1)), tz=timezone.utc)
        if signed_at > now + timedelta(minutes=5) or now - signed_at > window:
            return False, "DKIM t= is outside the freshness window"
    date_line = next((line for line in _unfold(raw) if line.lower().startswith(b"date:")), b"")
    if not date_line:
        return False, "signed message has no Date header"
    try:
        sent = parsedate_to_datetime(date_line.split(b":", 1)[1].decode("ascii", errors="ignore").strip())
    except (TypeError, ValueError, IndexError):
        return False, "Date header is not readable"
    if sent.tzinfo is None:
        sent = sent.replace(tzinfo=timezone.utc)
    if sent > now + timedelta(minutes=5) or now - sent > window:
        return False, "Date header is outside the freshness window"
    return True, ""


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
