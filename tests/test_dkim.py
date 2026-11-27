import base64

import dkim
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from hijackrewind.dkim_verify import check_signature, local_dns, register_dkim_txt, sign_message
from hijackrewind.email_auth import verify_channel
from hijackrewind.ingest import ingest_file
from hijackrewind.models import Document
from hijackrewind.runtime import repo_root

ALLOW = ["github.com"]


def _key_for(domain: str, selector: str = "pytest") -> tuple[bytes, str]:
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
    register_dkim_txt(f"{selector}._domainkey.{domain}", txt)
    return pem, txt


def _message(domain: str, body: str = "A new public key was added to your account.\r\nKey id: 99\r\n") -> bytes:
    lines = [
        f"From: GitHub <noreply@{domain}>",
        "To: owner@example.com",
        "Subject: [GitHub] A new public key was added to your account",
        "Date: Fri, 27 Nov 2026 18:05:00 +0000",
        "Message-ID: <unit@github.com>",
        "MIME-Version: 1.0",
        "Content-Type: text/plain; charset=utf-8",
        "",
        body,
    ]
    return "\r\n".join(lines).encode()


def test_valid_signature_verifies_offline():
    pem, _txt = _key_for("github.com")
    signed = sign_message(_message("github.com"), selector="pytest", domain="github.com", privkey_pem=pem)
    result = check_signature(signed, dns="local")
    assert result.ok
    assert result.domain == "github.com"
    assert dkim.verify(signed, dnsfunc=local_dns) is True


def test_tampered_body_fails():
    pem, _txt = _key_for("github.com", selector="tamper")
    signed = sign_message(_message("github.com"), selector="tamper", domain="github.com", privkey_pem=pem)
    flipped = signed.replace(b"Key id: 99", b"Key id: 98")
    result = check_signature(flipped, dns="local")
    assert not result.ok
    assert "did not verify" in result.reason


def test_wrong_domain_is_not_allowlisted():
    pem, _txt = _key_for("github.com.evil.test", selector="look")
    signed = sign_message(
        _message("github.com.evil.test"),
        selector="look",
        domain="github.com.evil.test",
        privkey_pem=pem,
    )
    document = Document(
        source="lookalike",
        modality="email",
        visible_text="A new public key was added to your account. Key id: 99",
        raw_text="alert",
        subject="[GitHub] A new public key was added to your account",
        from_name="GitHub",
        from_address="noreply@github.com.evil.test",
        from_domain="github.com.evil.test",
        raw_bytes=signed,
    )
    verdict = verify_channel(document, ALLOW)
    assert not verdict.verified
    assert verdict.lookalike
    assert verdict.dkim_domain == "github.com.evil.test"


def test_header_only_pass_is_unverified():
    raw = (
        "Authentication-Results: mx.local; dkim=pass header.d=github.com\r\n"
        "From: GitHub <noreply@github.com>\r\n"
        "Subject: [GitHub] A new public key was added to your account\r\n"
        "\r\n"
        "Key id: 99\r\n"
    ).encode()
    document = Document(
        source="header-only",
        modality="email",
        visible_text="A new public key was added to your account. Key id: 99",
        raw_text="Key id: 99",
        subject="[GitHub] A new public key was added to your account",
        from_name="GitHub",
        from_address="noreply@github.com",
        from_domain="github.com",
        authentication_results="mx.local; dkim=pass header.d=github.com",
        raw_bytes=raw,
    )
    verdict = verify_channel(document, ALLOW)
    assert not verdict.verified
    assert "no verifiable signature" in verdict.reason


def test_shipped_fixture_verifies_with_bundled_key():
    document = ingest_file(repo_root() / "sandbox" / "fixtures" / "genuine-new-ssh-key.eml")
    verdict = verify_channel(document, ALLOW, dns="local")
    assert verdict.verified
    assert verdict.dkim_domain == "github.com"
