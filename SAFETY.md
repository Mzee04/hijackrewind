# Safety

HijackRewind is the account owner's automation for a dedicated test account, or for the local stub. It says so here and in the README. Outbound text does not pretend to be GitHub staff or a person.

The controls below are Python. A sentence inside an alert, a page, or a model reply cannot turn them off.

## Guardrails

`policy.authorize` allows a mutate only when all of these are true:

- The mode is `sandbox` or `live`. Dry-run is refused here and again in `github_client.mutate`, including rewind.
- The classification, computed from the live before-state and the known-good manifest, is `confirmed`. The plan's disposition label is ignored. `unknown` and `suspicious` stay unexecuted even if an operator approves them.
- The path is on the revert allowlist and, for a repo path, the owner and name are the configured test repo.
- The object is not on the known-good manifest and is not the primary email.
- The run still has mutate budget (default 1) when the role is execute.
- Auto-execute also needs `allow_auto` and the flag for that kind. Otherwise a confirmed object needs a one-time approval. A denied or expired plan cannot run.

The client enforces the same path and host rules again at send time. Live mode accepts only `https://api.github.com`. Query strings on API calls are refused. Redirects are refused. `GET` retries 429, 500, 502, and 503 when the wait is within `HIJACKREWIND_MAX_RETRY_WAIT` (default 2 seconds). Mutating methods are not retried. `POST`, `PUT`, `PATCH`, and `DELETE` cost 5 rate-limit points. `GET` costs 1.

Lure URLs found in untrusted content are recorded as blocked outbound and are not opened, even when the host is `127.0.0.1`. The only fetch of a page is the URL the operator passed in, and only if that host is localhost.

Secret-shaped lines (exported keys, a passphrase answer) are omitted from the short summary. Tool arguments drop query strings and the public canary shape `AGW-CANARY-XXXX`. Specific canary values are not listed in the agent.

## Kill switch

`KillSwitch.trip` sets a flag that is checked immediately before each request. If the HTTP task is still running, it is cancelled and the client is closed. When the mutate had already been sent, the action becomes `outcome_unknown` and the audit note is `cancelled, outcome unknown`. That is a client abort. It is not a server-side cancellation. `hijackrewind reconcile ACTION_ID` reads the remote object. Later calls raise `ToolCancelled` until `hijackrewind kill --reset`.

The dashboard button and `hijackrewind kill` use that flag. Killing the OS process is not the switch the tests or the demo use.

`hijackrewind demo --kill` is the short repro where the stub is still holding the delete, so it does not apply it. The audit action includes `run_cancelled`. Key 99 is still present on that path. If a later run loses the response after the server applied the change, reconcile is the check.

## Live monitoring

The dashboard at `127.0.0.1:8765` shows the step, tool calls, decision, rate-limit points, plan, blocked hosts, audit tail, and a background task error when one was raised. Mutating routes require a local Host, a local Origin when the browser sends one, the operator token, and the CSRF token. Untrusted text is set with `textContent`. The sandbox demo button does not run in live mode.

## Audit trail

The log is tamper-evident. Each append takes a file lock, then writes `seq`, `prev_hash`, and `hash` over the canonical JSON of the previous hash plus the event. A checkpoint file stores the latest hash, and an HMAC of that hash when `HIJACKREWIND_AUDIT_HMAC_KEY` is set. `AuditLog` has append, read, and verify. It has no update and no delete. `hijackrewind audit verify` walks the chain, rejects malformed JSON, and rejects a checkpoint that does not match the tail. The same events show on the dashboard.

## Fail closed

A missing DKIM signature, a signature that does not verify, a lookalike domain, an API error, a timeout, an unknown modality, or a lure URL produces no mutate. `Authentication-Results: dkim=pass` is not treated as a signature. The trace records the stop. Trap Pack files are hostile inputs; instructions inside them are ignored.

## Personal data

Sandbox mode is the default and uses fixture addresses. Live mode is limited to the token and the one test repo in the environment. Do not point it at a personal account you cannot afford to change.
