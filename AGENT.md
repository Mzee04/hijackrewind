# Architecture

Track: **open**. Pitch: when a GitHub account-security alert arrives, prove it is genuine, quarantine lures, and revert only the unauthorized object.

Runtime model: none on the default path. An optional OpenAI-compatible chat endpoint (`HIJACKREWIND_LLM_*`) may write one explanation after the decision. It is off unless the operator turns it on, and nothing it returns is consulted by `policy.authorize`.

The code was written with an AI coding assistant during the hackathon window. The decisions below are in Python, not in a prompt.

## Layout

| Module | Role |
| --- | --- |
| `cli.py` | Operator commands. Same pipeline as the dashboard. |
| `ingest.py` | `.eml`, documents, and `http://127.0.0.1` pages. Refuses the answer-key directory. |
| `screen.py` | Untrusted-content screen: hidden HTML, base64 instructions, zero-width characters, broken tables, CSV, JSON, and calendars. |
| `email_auth.py` | DKIM signature verification, alignment, and lookalike domains. |
| `claims.py` | Regex extraction of a concrete object. No raw document text is copied into a URL. |
| `policy.py` | The only place a mutate is authorized. |
| `github_client.py` | One HTTP client: timeouts, kill-switch race, rate-limit wait, path allowlist. |
| `stub_app.py` | Local list/delete API shaped like the GitHub routes we support. |
| `audit.py` | Append-only hash chain. |
| `dashboard.py` | Local page for the live view, approvals, and the kill switch. |
| `trap_harness.py` | Runs `official-trap-pack/traps/` and writes `tests/trap-pack/RESULTS.md`. |

## State machine

`ingest → screen → egress blocks → verify channel → extract claims → cross-check API → plan → policy → maybe execute`

A channel that is not an aligned allowlisted email cannot create a plan. A plan in `dry-run` mode is not executed. A plan with more steps than `HIJACKREWIND_MUTATE_CAP` (default 1) is not executed. Auto-execute is only the case of exactly one unknown SSH key when `HIJACKREWIND_AUTO_EXECUTE_SSH_KEY=true`.

## Tools the agent can call

Reads and deletes, and only these:

- `/user/keys`, `/user/emails`, `/user/gpg_keys`, `/user/ssh_signing_keys`
- `/repos/{TEST_REPO_OWNER}/{TEST_REPO_NAME}/keys`
- `/repos/{TEST_REPO_OWNER}/{TEST_REPO_NAME}/hooks`
- `/repos/{TEST_REPO_OWNER}/{TEST_REPO_NAME}/collaborators`
- `/repos/{TEST_REPO_OWNER}/{TEST_REPO_NAME}/branches/{branch}/protection`

Anything else is an egress denial, including other repositories, lure URLs, and mail. Mail is not a tool that can succeed.

## Permissions

Sandbox mode talks to the stub with no token. Live mode sends `GITHUB_TOKEN` as a bearer header and never writes that header to a trace. The known-good manifest is a local file the operator edits. The agent cannot widen it because a document asked.

## Traces

JSONL under `traces/` for operator runs and `tests/trap-pack/traces/` for the Trap Pack. Each line has a timestamp, run id, step, a short input summary, the decision, the tool, a redacted request, a redacted response, and an outcome.
