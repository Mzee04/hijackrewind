# HijackRewind

Open-track agent for [Agentware 2026](https://agentwarehack.com/brief/). When a GitHub account-security alert arrives, HijackRewind checks that it is genuine, quarantines phishing and prompt-injection lures, and reverts only the unauthorized object on a dedicated test account or on a local stub.

Sandbox mode is the default and needs no credentials. This file is the short scaffold note; the operator guide lands with the rest of the pipeline.

```bash
python -m pip install -e ".[dev]"
cp .env.example .env
python -m hijackrewind --help
```

Author: Toyyib Olamilekan Muhammed (GitHub `Mzee04`). MIT licensed. This is the account owner's automation. It does not impersonate GitHub staff or a human correspondent.
