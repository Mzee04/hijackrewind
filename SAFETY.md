# Safety

HijackRewind is the account owner's automation for a dedicated test account, or for the local stub. It says so here and in the README. Outbound text does not pretend to be GitHub staff or a person.

The controls below are Python. A sentence inside an alert, a page, or a model reply cannot turn them off.

## Guardrails

`policy.authorize` allows a `DELETE` only when all of these are true:

- The mode is `sandbox` or `live` (`dry-run` stops after the plan).
- The path is on the revert allowlist and, for a repo path, the owner and name are the configured test repo.
- The object is not on the known-good manifest and is not the primary email.
- The run still has mutate budget (default 1).
- Either the plan is exactly one unknown SSH key and auto-execute is on, or an operator approval event is already in the audit log.

The client enforces the same path and host rules again at send time. Query strings on API calls are refused. Redirects are refused. `GET` retries at most once, and only when `Retry-After` is within `HIJACKREWIND_MAX_RETRY_WAIT` (default 2 seconds). `DELETE` is not retried.

Lure URLs found in untrusted content are recorded as blocked outbound and are not opened, even when the host is `127.0.0.1`. The only fetch of a page is the URL the operator passed in, and only if that host is localhost.

Secret-shaped lines (exported keys, a passphrase answer) are omitted from the short summary. Tool arguments drop query strings and the public canary shape `AGW-CANARY-XXXX`. Specific canary values are not listed in the agent.

## Kill switch

`KillSwitch.trip` sets a flag the HTTP task polls. The in-flight `httpx` task is cancelled and the client is closed. The stub records the disconnect when the delayed `DELETE` is cancelled, and it does not apply the delete. Later calls raise `ToolCancelled` until `hijackrewind kill --reset`.

The dashboard button and `hijackrewind kill` use that flag. Killing the OS process is not the switch the tests or the demo use.

`hijackrewind demo --kill` is the short repro: the stub holds the delete, the switch trips, the audit action is `run_cancelled`, and key 99 is still present.

## Live monitoring

The dashboard at `127.0.0.1:8765` shows the step, tool calls, decision, rate-limit points, plan, blocked hosts, and audit tail. It polls twice a second. It binds to localhost so a remote host cannot press approve or kill.

## Audit trail

`audit.jsonl` is opened with `O_APPEND` only. Each event stores `seq`, `prev_hash`, and `hash` over the canonical JSON of the previous hash plus the event. `AuditLog` has append, read, and verify. It has no update and no delete. `hijackrewind audit --verify` walks the chain. Editing a past line fails verification. The same events show on the dashboard.

## Fail closed

Missing `Authentication-Results`, a lookalike domain, an API error, a timeout, an unknown modality, or a lure URL produces no mutate. The trace records the stop. Trap Pack files are hostile inputs; instructions inside them are ignored.

## Personal data

Sandbox mode is the default and uses fixture addresses. Live mode is limited to the token and the one test repo in the environment. Do not point it at a personal account you cannot afford to change.
