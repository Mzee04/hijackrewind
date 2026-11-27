# Demo script

One unattended run, then the kill switch. Three minutes. Record the real dashboard and terminal. Do not paste canned output.

The machine is the sandbox. No GitHub token. Say that in the first sentence.

## 0:00–0:15 Title

HijackRewind, open track. It checks a GitHub account alert and reverts only the unauthorized object. This take is the local stub.

## 0:15–0:35 Trigger

In one terminal:

```bash
python3 -m hijackrewind demo
```

Before the delete returns, the other terminal or the dashboard can show the stub keys if you already started `python3 -m hijackrewind dashboard` and pressed **Run sandbox demo** instead. Either trigger is one action. Then take your hands off the keyboard.

The fixture alert is `sandbox/fixtures/genuine-new-ssh-key.eml`. The stub has known-good key 1 and unknown key 99.

## 0:35–1:20 Unattended run

The dashboard moves ingest → verify → cross-check → plan → execute. Alignment is `dkim=pass` for `github.com`. The live stub list contains key 99. Policy deletes only that key. There is no approval click on this path.

## 1:20–1:40 Result

Key 99 is gone. Key 1 remains. The audit line is `mutate_executed` for `/user/keys/99`. The trace path is printed in the terminal.

## 1:40–2:20 Kill switch

```bash
python3 -m hijackrewind kill --reset
python3 -m hijackrewind demo --kill
```

The second command plants key 99 again, starts the delete, and trips the switch while the stub is still waiting. The terminal prints `pending delete finished: no`. The audit action is `run_cancelled`. Key 99 is still on the stub.

On camera you can instead press **Kill switch** on the dashboard during a slow delete. Set `HIJACKREWIND_DELETE_DELAY=2` in `.env` before that take so the call stays in flight long enough to hit the button. Reset the delay to `0` afterwards.

## 2:20–2:50 Reliability

```bash
python3 -m hijackrewind run sandbox/fixtures/lookalike-new-ssh-key.eml
```

The sender is `github.com.evil.test`. Status is `quarantined`. The lure host `collect.example.net` is an `egress_blocked` audit line. The stub mutations list is empty.

## 2:50–3:00 Stop

No extra clicks. The run, the kill, and the quarantine are the product.
