from hijackrewind.email_auth import is_allowlisted, is_lookalike, verify_channel
from hijackrewind.ingest import ingest_file
from hijackrewind.runtime import repo_root

ALLOW = ["github.com"]


def test_allowlist_accepts_subdomains_and_rejects_suffix_tricks():
    assert is_allowlisted("github.com", ALLOW)
    assert is_allowlisted("noreply.github.com", ALLOW)
    assert not is_allowlisted("github.com.evil.test", ALLOW)
    assert not is_allowlisted("githib.com", ALLOW)
    assert not is_allowlisted("github.co", ALLOW)


def test_lookalikes():
    assert is_lookalike("github.com.evil.test", ALLOW)
    assert is_lookalike("githib.com", ALLOW)
    assert not is_lookalike("github.com", ALLOW)
    assert not is_lookalike("noreply.github.com", ALLOW)
    assert not is_lookalike("patchnotes.example.net", ALLOW)


def test_genuine_fixture_verifies():
    document = ingest_file(repo_root() / "sandbox" / "fixtures" / "genuine-new-ssh-key.eml")
    verdict = verify_channel(document, ALLOW)
    assert verdict.verified
    assert verdict.dkim_domain == "github.com"


def test_lookalike_fixture_fails_closed():
    document = ingest_file(repo_root() / "sandbox" / "fixtures" / "lookalike-new-ssh-key.eml")
    verdict = verify_channel(document, ALLOW)
    assert not verdict.verified
    assert verdict.lookalike
    assert verdict.pretends_github


def test_missing_authentication_results_fails_closed(tmp_path):
    path = tmp_path / "missing.eml"
    path.write_text(
        "From: GitHub <noreply@github.com>\n"
        "Subject: [GitHub] A new public key was added to your account\n"
        "\n"
        "Key id: 99\n",
        encoding="utf-8",
    )
    verdict = verify_channel(ingest_file(path), ALLOW)
    assert not verdict.verified
    assert "missing" in verdict.reason
    assert verdict.pretends_github
