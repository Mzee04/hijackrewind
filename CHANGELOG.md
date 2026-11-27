# Changelog

## Unreleased

- Webhook rewind now restores the saved `active` flag, so an inactive hook is not brought back as active.
- Reversible containment can run without a click: unknown SSH keys, unknown deploy keys, webhooks on a host that is not allowlisted, and a branch-protection restore from the known-good document. `hijackrewind rewind ACTION_ID` puts the saved before-state back when the API allows it.
- OAuth grant revocation, other personal access tokens, and web sessions are planned and not sent. A user token has no endpoint for them. Repository deletion is refused.
- GET retries 5xx and rate limits with backoff and jitter. Timeouts stop a slow call. An in-flight DELETE cancelled by the kill switch is an audit event `tool_cancelled`.
- The dashboard shows a timeline, action status, a large kill switch, and the audit hash-chain result. `hijackrewind audit verify` checks that chain.
- `docs/LIVE_TEST.md` is the runbook for one throwaway account. Live GitHub was not called from this workspace.
- Verify DKIM signatures with dkimpy. Sandbox mode uses a bundled test key and an injected resolver. Live mode uses DNS. `Authentication-Results: dkim=pass` without a verifiable signature does not authorize a revert.
- Live GitHub mode refuses any host other than `api.github.com`, and `hijackrewind doctor` checks the token login, classic scopes, and the one configured test repository. List and delete behaviour is covered by recorded responses. The real API was not called.
- Re-ran all 20 Trap Pack inputs after the DKIM change. 7 caught by the egress guardrail, 13 held, 0 mutated.

## 1.0.0

- Sandbox agent that triages a GitHub account alert and deletes one verified unknown SSH key.
- Kill switch that cancels an in-flight DELETE, append-only audit log, and a local dashboard.
