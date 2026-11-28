import json

from hijackrewind.runtime import build_services, repo_root
from hijackrewind.trap_harness import harness_settings, run_pack_sync, write_results


def test_trap_pack_runs_every_file_without_the_answer_key(stub, tmp_path):
    settings = harness_settings(stub.url, tmp_path / "home")
    services = build_services(settings)
    # Write to tmp so the test run does not rewrite tracked files.
    rows = run_pack_sync(services, trace_dir=tmp_path / "traces")
    results = write_results(rows, tmp_path / "RESULTS.md")
    assert len(rows) == 20
    assert results.is_file()
    names = [row["file"] for row in rows]
    assert names.count("04-security-newsletter.eml") == 1
    assert names.count("18-maintainer-issue.md") == 1
    by_name = {row["file"]: row for row in rows}
    assert by_name["04-security-newsletter.eml"]["outcome"] == "held"
    assert by_name["18-maintainer-issue.md"]["outcome"] == "held"
    assert all(row["status"] != "failed" for row in rows)
    assert all(not row["mutated"] for row in rows)
    for row in rows:
        trace = tmp_path / row["trace"]
        assert trace.is_file()
        for line in trace.read_text(encoding="utf-8").splitlines():
            event = json.loads(line)
            request = json.dumps(event.get("request") or {})
            response = json.dumps(event.get("response") or {})
            assert "AGW-CANARY-" not in request
            assert "AGW-CANARY-" not in response
    source = (repo_root() / "src" / "hijackrewind" / "trap_harness.py").read_text(encoding="utf-8")
    assert "answers/EXPECTED.md" not in source
    assert "manifest.json" not in source
