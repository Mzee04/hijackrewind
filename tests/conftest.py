import pytest

from hijackrewind.config import Settings
from hijackrewind.runtime import StubServer, build_services, load_seed, repo_root, reset_stub


@pytest.fixture(scope="session")
def stub() -> StubServer:
    server = StubServer()
    server.start()
    yield server
    server.stop()


@pytest.fixture
def settings(stub: StubServer, tmp_path) -> Settings:
    root = repo_root()
    return Settings(
        _env_file=None,
        mode="sandbox",
        stub_url=stub.url,
        github_token="",
        llm_enabled=False,
        llm_api_key="",
        manifest_path=str(root / "sandbox" / "fixtures" / "known-good.json"),
        trace_dir=str(tmp_path / "traces"),
        audit_log=str(tmp_path / "audit.jsonl"),
        home=str(tmp_path / "home"),
        auto_execute_ssh_key=True,
        auto_execute_containment=True,
        mutate_cap=1,
        sender_allowlist="github.com",
        test_repo_owner="test-owner",
        test_repo_name="test-repo",
        delete_delay=0,
    )


@pytest.fixture
def services(settings: Settings):
    reset_stub(settings.stub_url, load_seed())
    return build_services(settings)
