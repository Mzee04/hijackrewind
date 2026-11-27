# Safety

HijackRewind is the account owner's automation for a dedicated test account or the local stub. It discloses that in the README and in this file. It does not impersonate GitHub staff or a person.

Guardrails, the kill switch, live monitoring, and the append-only audit log are implemented in code and covered by pytest. Destructive actions are allowed only by policy in code. A prompt inside an alert cannot widen the allowlist, raise the mutate cap, or turn the kill switch back off.

This scaffold file is expanded as those controls land. Until then, do not point the tool at a real account.
