"""Build CRLF messages and sign them with an ephemeral DKIM key."""

from __future__ import annotations

import base64
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from hijackrewind.dkim_verify import register_dkim_txt, sign_message


def write_signed_alert(path: Path, *, subject: str, body: str, domain: str = "github.com") -> None:
    message = _unsigned(subject=subject, body=body, domain=domain)
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption(),
    )
    public = key.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    txt = "v=DKIM1; k=rsa; p=" + base64.b64encode(public).decode()
    register_dkim_txt(f"pytest._domainkey.{domain}", txt)
    signed = sign_message(message, selector="pytest", domain=domain, privkey_pem=pem)
    path.write_bytes(signed)


def _unsigned(*, subject: str, body: str, domain: str) -> bytes:
    lines = [
        f"From: GitHub <noreply@{domain}>",
        "To: owner@example.com",
        f"Subject: {subject}",
        "Date: Fri, 27 Nov 2026 18:05:00 +0000",
        "Message-ID: <signed-alert@github.com>",
        "MIME-Version: 1.0",
        "Content-Type: text/plain; charset=utf-8",
        "",
    ]
    lines.extend(body.splitlines())
    lines.append("")
    return "\r\n".join(lines).encode()
