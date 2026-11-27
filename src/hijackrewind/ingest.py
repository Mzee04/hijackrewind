"""Read an alert the way it would arrive: file, local page, or email."""

from __future__ import annotations

from email import policy
from email.parser import BytesParser
from email.utils import parseaddr
from pathlib import Path

import httpx

from hijackrewind.egress import EgressLog
from hijackrewind.models import Document
from hijackrewind.screen import screen_text

_ANSWER_NAMES = {"expected.md"}


class IngestError(ValueError):
    pass


def assert_safe_path(path: Path) -> None:
    resolved = path.resolve()
    if resolved.name.lower() in _ANSWER_NAMES or "answers" in {part.lower() for part in resolved.parts}:
        raise IngestError("refusing to ingest trap-pack answer material")


def ingest_file(path: Path) -> Document:
    assert_safe_path(path)
    if not path.is_file():
        raise IngestError(f"no such file: {path}")
    data = path.read_bytes()
    if path.suffix.lower() == ".eml" or _looks_like_email(data):
        return document_from_email(data, source=str(path))
    text, encoding_notes = decode_bytes(data)
    modality = _modality(path, text)
    html = text if modality == "html" else ""
    screened = screen_text(modality=modality, raw_text=text, html=html)
    if encoding_notes:
        screened.data_issues = encoding_notes + screened.data_issues
        if "broken_data" not in screened.warnings:
            screened.warnings.append("broken_data")
    return Document(
        source=str(path),
        modality=modality,
        visible_text=screened.visible_text,
        raw_text=text,
        screen=screened,
    )


def document_from_email(data: bytes, source: str) -> Document:
    message = BytesParser(policy=policy.default).parsebytes(data)
    plain: list[str] = []
    html_parts: list[str] = []
    calendar: list[str] = []
    if message.is_multipart():
        for part in message.walk():
            if part.get_content_maintype() == "multipart":
                continue
            kind = part.get_content_type()
            try:
                content = part.get_content()
            except Exception:
                payload = part.get_payload(decode=True) or b""
                content = payload.decode("utf-8", errors="replace")
            if not isinstance(content, str):
                continue
            if kind == "text/html":
                html_parts.append(content)
            elif kind == "text/calendar":
                calendar.append(content)
            else:
                plain.append(content)
    else:
        try:
            content = message.get_content()
        except Exception:
            content = data.decode("utf-8", errors="replace")
        if not isinstance(content, str):
            content = str(content)
        kind = message.get_content_type()
        if kind == "text/html":
            html_parts.append(content)
        elif kind == "text/calendar":
            calendar.append(content)
        else:
            plain.append(content)
    name, address = parseaddr(message.get("from", ""))
    _, reply = parseaddr(message.get("reply-to", ""))
    domain = address.split("@", 1)[1].lower() if "@" in address else ""
    auth_headers = message.get_all("authentication-results") or []
    raw = "\n".join(plain + calendar)
    screened = screen_text(
        modality="email",
        raw_text=raw,
        html="\n".join(html_parts),
        reply_to=reply,
    )
    return Document(
        source=source,
        modality="email",
        visible_text=screened.visible_text,
        raw_text=raw,
        subject=str(message.get("subject", "")),
        from_name=name,
        from_address=address,
        from_domain=domain,
        reply_to=reply,
        authentication_results=" ".join(auth_headers),
        raw_bytes=data,
        screen=screened,
    )


async def ingest_url(url: str, egress: EgressLog) -> Document:
    egress.assert_operator_fetch(url)
    async with httpx.AsyncClient(timeout=10.0, follow_redirects=False) as client:
        response = await client.get(url)
    if response.status_code in {301, 302, 303, 307, 308}:
        location = response.headers.get("location", "")
        host = location.split("/")[2] if "://" in location else "redirect"
        egress.block_lure(kind="http", host=host, path="/")
        raise IngestError("refusing a redirect while reading a local page")
    if response.status_code >= 400:
        raise IngestError(f"local page returned HTTP {response.status_code}")
    text = response.text
    lowered = text.lstrip().lower()
    modality = "html" if lowered.startswith("<!doctype") or lowered.startswith("<html") or "<html" in lowered[:200] else "text"
    screened = screen_text(modality=modality, raw_text=text, html=text if modality == "html" else "")
    return Document(source=url, modality=modality, visible_text=screened.visible_text, raw_text=text, screen=screened)


def decode_bytes(data: bytes) -> tuple[str, list[str]]:
    """Prefer UTF-8. A file that declares UTF-8 but is Windows-1252 still decodes."""
    try:
        return data.decode("utf-8"), []
    except UnicodeDecodeError:
        return data.decode("cp1252"), ["file is not valid UTF-8; decoded as Windows-1252"]


def _looks_like_email(data: bytes) -> bool:
    head = data[:400].lower()
    return head.startswith(b"from:") or b"\nfrom:" in head or b"\r\nfrom:" in head


def _modality(path: Path, text: str) -> str:
    suffix = path.suffix.lower()
    if suffix in {".html", ".htm"}:
        return "html"
    if suffix == ".csv":
        return "csv"
    if suffix == ".json":
        return "json"
    if suffix == ".md":
        return "markdown"
    if suffix == ".eml":
        return "email"
    sample = text[:400].lower()
    if "transcript" in sample or "[00:" in text or "[07:" in text:
        return "transcript"
    return "text"
