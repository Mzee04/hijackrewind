# Changelog

## Unreleased

- Verify DKIM signatures with dkimpy. Sandbox mode uses a bundled test key and an injected resolver. Live mode uses DNS. `Authentication-Results: dkim=pass` without a verifiable signature does not authorize a revert.
- Live GitHub mode refuses any host other than `api.github.com`, and `hijackrewind doctor` checks the token login, classic scopes, and the one configured test repository. List and delete behaviour is covered by recorded responses. The real API was not called.
- Re-ran all 20 Trap Pack inputs after the DKIM change. 7 caught by the egress guardrail, 13 held, 0 mutated.

## 1.0.0

- Sandbox agent that triages a GitHub account alert and deletes one verified unknown SSH key.
- Kill switch that cancels an in-flight DELETE, append-only audit log, and a local dashboard.
