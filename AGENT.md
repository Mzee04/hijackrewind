# HijackRewind architecture

Track: **open** (see `.agentware.toml`).

Runtime model: none. The default path is deterministic Python. An optional OpenAI-compatible endpoint can draft one explanation sentence and cannot authorize a mutate. That option ships off.

Tools, permissions, and the state machine are filled in with the pipeline. The intended mutate surface is the personal-account and single-test-repo REST actions documented in the product brief: SSH keys, account emails, and optionally GPG keys, SSH signing keys, deploy keys, webhooks, collaborators, and branch protection on one configured repository.

No org audit-log API, no session revoke, no third-party OAuth revoke, and no non-GitHub account flow.
