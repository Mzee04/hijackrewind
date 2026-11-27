# Live test

CI does not call GitHub. The checks in this repository use recorded responses.

A live test was run on 27 Nov 2026 against the disposable account `thelove987/hijackrewind-test`. A deploy key and a webhook were contained, rewind restored them, and the kill switch and audit verify passed. Account-wide endpoints returned 403 and failed closed with a repo-scoped token.

## Runbook

Use a throwaway GitHub account and one repository created for this test. Do not point HijackRewind at an account you use for anything else.

`doctor` refuses a token whose `/user` login is not `TEST_GITHUB_LOGIN`, and it refuses a repository whose full name is not `TEST_REPO_OWNER/TEST_REPO_NAME`. `GITHUB_API_URL` must be `https://api.github.com`.

## Token

Create a fine-grained personal access token on the throwaway account:

- Resource owner: that account only
- Repository access: only the test repository
- Account permissions: Git SSH keys (read and write) and Email addresses (read and write), if you intend to exercise those deletes
- Repository permissions: Administration (read and write) for deploy keys, webhooks, and branch protection on that one repository

A classic token is also accepted by `doctor` when `X-OAuth-Scopes` contains `admin:public_key` and `user`. Prefer the fine-grained token so the credential cannot see other repositories.

## Environment

```bash
cp .env.example .env
```

Set:

```bash
HIJACKREWIND_MODE=live
GITHUB_TOKEN=the-throwaway-token
TEST_GITHUB_LOGIN=the-throwaway-login
TEST_REPO_OWNER=the-throwaway-login
TEST_REPO_NAME=hijackrewind-sandbox
HIJACKREWIND_DKIM_DNS=live
```

Put every SSH key, email, deploy key, and webhook you want to keep into `HIJACKREWIND_MANIFEST`. For `main`, include a `protections` object that is a valid branch-protection PUT body if you want a downgrade restored.

## Order

1. `python3 -m hijackrewind doctor`
   Stop if it exits non-zero. A 401, a different login, a missing classic scope, or another repository name means do not continue.
2. Add one throwaway SSH key, deploy key, or webhook on the test account. Save the GitHub notification `.eml`.
3. `python3 -m hijackrewind run path/to/alert.eml`
   Live mode checks the DKIM signature with DNS. A real GitHub notification can verify. A file that only contains `Authentication-Results: dkim=pass` will not.
4. `python3 -m hijackrewind audit verify`
5. If the action was reversible, `python3 -m hijackrewind rewind ACTION_ID` puts the saved public key or webhook config back. Webhook secrets are not returned by GitHub, so a restored hook has no secret.

## What a user token cannot do

`doctor` and the agent will not call these, because the user token has no endpoint for them:

- Revoke an OAuth app grant (that call needs the app's client id and client secret)
- List or revoke other personal access tokens
- Revoke a web session
- Delete the repository (refused by policy even though a destructive endpoint exists)

Those alerts become a planned action with that reason and no HTTP mutate.
