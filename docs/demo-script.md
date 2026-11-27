# Demo script

Sandbox only. No GitHub token. Say that in the first sentence. Record the real terminal. Do not paste canned output.

## 0:00–0:20 Genuine alert

```bash
python3 -m hijackrewind demo
```

The demo process sets SSH auto-execute for itself. The fixture is `sandbox/fixtures/genuine-new-ssh-key.eml`. The stub starts with known-good key 1 and unknown key 99. After the run, key 99 is gone and key 1 is still there. The audit line is `mutate_executed` for `/user/keys/99`. The plan text names claim `ssh_key 99` next to the live key.

A normal run of the same file, without the demo flag, leaves key 99 in place:

```bash
python3 -m hijackrewind run sandbox/fixtures/genuine-new-ssh-key.eml
```

Status is `pending_approval`.

## 0:20–0:40 Phishing rejected

```bash
python3 -m hijackrewind run sandbox/fixtures/lookalike-new-ssh-key.eml
```

The sender is `github.com.evil.test`. Status is `quarantined`. The lure host is an `egress_blocked` audit line. The stub mutation list does not grow.

## 0:40–1:10 Containment and rewind

From the demo run, copy the action id on the `mutate_executed` audit line:

```bash
python3 -m hijackrewind audit
python3 -m hijackrewind rewind ACTION_ID
```

Rewind posts the saved public key. Key 99 is present again, with a new id if the API assigned one. A webhook rewind cannot restore the secret, because the API does not return it.

## 1:10–1:40 Kill switch and reconcile

```bash
python3 -m hijackrewind kill --reset
python3 -m hijackrewind demo --kill
python3 -m hijackrewind reconcile ACTION_ID
```

The kill scene trips the switch while the stub is still holding the delete, so that particular delete is not applied and key 99 remains. The audit note for an interrupted sent mutate is `cancelled, outcome unknown`. Reconcile reads the remote object and records whether it is present or absent. The client abort is not a server-side cancellation.

## 1:40–2:10 Audit trail and Trap Pack

```bash
python3 -m hijackrewind audit verify
python3 -m hijackrewind trap-pack
```

`audit verify` walks the tamper-evident chain. The Trap Pack run rewrites `tests/trap-pack/RESULTS.md` and the traces from the current code. Expect no mutations. Controls `04-security-newsletter.eml` and `18-maintainer-issue.md` are held.
