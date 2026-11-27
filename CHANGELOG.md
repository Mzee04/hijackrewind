# Changelog

## Unreleased

- Hardening pass. Dry-run is refused inside the HTTP client, including rewind. Auto-execute is off unless `HIJACKREWIND_AUTO_EXECUTE_SSH_KEY` or `HIJACKREWIND_AUTO_EXECUTE_CONTAINMENT` is set, and only a confirmed match qualifies. The plan label is not a grant. Plans expire, approval is one-time, and a denied plan cannot run. A rollback record is written before the request. An interrupted mutate is `outcome_unknown` (`cancelled, outcome unknown`); `hijackrewind reconcile` reads remote state. The dashboard requires a local host, a CSRF token, and an operator token. DKIM requires From, Subject, and Date, rejects `l=`, checks freshness, and rejects a replayed signature. The audit log is tamper-evident, with a lock, a checkpoint, and a clean failure on malformed JSON.
- Webhook rewind now restores the saved `active` flag, so an inactive hook is not brought back as active. A restored webhook still has no secret, and a recreated object gets a new id.
- Reversible containment can run without a click: unknown SSH keys, unknown deploy keys, webhooks on a host that is not allowlisted, and a branch-protection restore from the known-good document. `hijackrewind rewind ACTION_ID` puts the saved before-state back when the API allows it.
- OAuth grant revocation, other personal access tokens, and web sessions are planned and not sent. A user token has no endpoint for them. Repository deletion is refused.
- GET retries 5xx and rate limits with backoff and jitter. Timeouts stop a slow call. An in-flight DELETE cancelled by the kill switch is an audit event `tool_cancelled`.
- The dashboard shows a timeline, action status, a large kill switch, and the audit hash-chain result. `hijackrewind audit verify` checks that chain.
- `docs/LIVE_TEST.md` records the 27 Nov 2026 run against `thelove987/hijackrewind-test` and the runbook for a later throwaway account. CI still uses recorded responses and does not call GitHub.
- Verify DKIM signatures with dkimpy. Sandbox mode uses a bundled test key and an injected resolver. Live mode uses DNS. `Authentication-Results: dkim=pass` without a verifiable signature does not authorize a revert.
- Live GitHub mode refuses any host other than `api.github.com`, and `hijackrewind doctor` checks the token login, classic scopes, and the one configured test repository. CI covers list and delete with recorded responses. The 27 Nov 2026 live test is in `docs/LIVE_TEST.md`.
- Re-ran all 20 Trap Pack inputs after the DKIM change. 7 caught by the egress guardrail, 13 held, 0 mutated.

## 1.0.0

- Sandbox agent that triages a GitHub account alert and deletes one verified unknown SSH key.
- Kill switch that cancels an in-flight DELETE, append-only audit log, and a local dashboard.
