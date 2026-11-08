# GitHub App: Agent Config Guard and Swallowed

The App runs two checks on every pull request and posts one comment, updated in place on
each push. Findings are ranked, and each one comes with a suggested fix.

| Check run | What it reports | Conclusion |
| --- | --- | --- |
| **Agent Config Guard** | Changes that let an agent do more: new allow rules (expanded by the Range knowledge base into what they really reach), removed deny rules, wider permission or sandbox modes, new hooks, new MCP servers and their credentials, skill `allowed-tools`, Codex `.rules` allow rules, and new instruction lines telling agents to skip a check. The existing engine findings (workflows, egress, startup payloads) are included too. | `failure` at high or above (`APDB_GUARD_FAIL_ON`), `neutral` below, `success` with no findings |
| **Swallowed errors** | New places where the diff catches an error and drops it, in Python and TypeScript/JavaScript, ranked by what the protected code does: auth, then data loss, then network, then other. | `neutral` with findings (`APDB_SWALLOWED_FAIL_ON`, default `never`), `success` otherwise |

## What the App does and does not do

- It reads pull request files, Git trees and blobs through the API with a token scoped to
  the one repository the event is about. It never checks out or runs pull request code, so
  fork pull requests are safe to analyze.
- It never fetches credential paths (`.env`, keys, `.npmrc` and similar), and it puts
  credential key names, never values, in its output. Comment text from the pull request is
  escaped so it cannot hide or restyle the comment.
- It edits only a comment that carries its marker **and** was created by this App, so a
  copied marker in someone else's comment is left alone.
- If reading the pull request fails, Config Guard reports `failure` ("did not finish")
  rather than passing; Swallowed reports `neutral`. The comment says so too, and never shows
  the all-clear line when a check crashed or read the pull request only partly.
- When pushes arrive close together, only the newest push writes the comment; each push
  still gets its own check runs.

### Marking a swallowed error as deliberate

Add a comment on the `except`/`catch` line or inside the handler:

```python
except FileNotFoundError:  # swallowed: ok - already gone is the goal
    pass
```

```ts
} catch {
  // swallowed: ok analytics must never break the page
}
```

Marked catches are listed with their reason and are not ranked. A ruff `noqa: S110`,
`S112`, `BLE001` or `SIM105` on the handler counts too, and is listed as "no reason given".

## Register and install the App (Saagar)

These steps touch your GitHub account settings and create a private key, so they are yours
to do. Keep the key and the webhook secret on your machine; none of the steps needs them
pasted anywhere else.

1. **Make a webhook secret** in a terminal:

   ```bash
   mkdir -p ~/.config/agent-config-guard && chmod 700 ~/.config/agent-config-guard
   openssl rand -hex 32 > ~/.config/agent-config-guard/webhook-secret
   chmod 600 ~/.config/agent-config-guard/webhook-secret
   ```

2. **Get a webhook URL.** For a local run, open <https://smee.io/new> and copy the channel
   URL. (A smee channel is public to anyone holding its URL and carries webhook payloads:
   repository names, PR titles and SHAs, not file contents. Use a private tunnel or a
   deployed URL for anything beyond the demo.)

3. **Create the App** at <https://github.com/settings/apps/new>:
   - GitHub App name: something unique, for example `agent-config-guard-<your-handle>`.
   - Homepage URL: this repository's URL.
   - Webhook: **Active**. Webhook URL: the smee URL from step 2. Webhook secret: the
     contents of `~/.config/agent-config-guard/webhook-secret`.
   - Repository permissions: **Checks: Read and write**, **Contents: Read-only**,
     **Pull requests: Read and write**, **Metadata: Read-only** (preset). Nothing else.
   - Subscribe to events: **Pull request**, **Check run** and **Check suite**.
   - Where can this GitHub App be installed: **Only on this account**.
   - Click **Create GitHub App** and note the **App ID** at the top of the next page.

4. **Generate a private key** in the App's settings: **Credentials** → **Key pairs** → **New key**.
   Move the downloaded `.pem` next to the secret and lock it down:

   ```bash
   mv ~/Downloads/agent-config-guard-*.private-key.pem ~/.config/agent-config-guard/app.pem
   chmod 600 ~/.config/agent-config-guard/app.pem
   ```

5. **Install it** (Install App → your account → **Only select repositories** →
   `agent-config-guard-demo`).

6. **Run it** from this repository, in two terminals:

   ```bash
   export APDB_APP_ID=<the App ID from step 3>
   export APDB_PRIVATE_KEY_PATH=~/.config/agent-config-guard/app.pem
   export APDB_WEBHOOK_SECRET="$(cat ~/.config/agent-config-guard/webhook-secret)"
   uv run agent-permission-diff app serve --port 8787
   ```

   ```bash
   npx smee-client --url <the smee URL> --target http://127.0.0.1:8787/webhook
   ```

7. **Trigger the demo PRs.** Close and reopen each pull request in
   `agent-config-guard-demo` (or push to its branch). Each one should get the two check
   runs and a single comment. **Re-run** on a check run, or **Re-run all checks**, also
   works, including for pull requests from forks.

### Settings

| Variable | Meaning |
| --- | --- |
| `APDB_APP_ID` | Numeric App ID (required). |
| `APDB_PRIVATE_KEY_PATH` | Path to the App's `.pem` private key (required). |
| `APDB_WEBHOOK_SECRET` | The webhook secret, at least 16 characters (required). |
| `APDB_GUARD_FAIL_ON` | `critical`, `high` (default), `medium`, `low` or `never`. |
| `APDB_SWALLOWED_FAIL_ON` | Same values; default `never` (advisory). |
| `APDB_GITHUB_API_URL` | API base URL; default `https://api.github.com`. |

## Prove it locally without registering anything

`app replay` sends a recorded webhook through the real server against an in-memory GitHub.
It signs the webhook with a throwaway secret, signs the App JWT with a throwaway RSA key,
exchanges it for a repository-scoped token, reads the files, and prints the two check runs
and the comment. Nothing touches the network.

```bash
uv run agent-permission-diff app replay tests/fixtures/app/broad-bash-allow
uv run agent-permission-diff app replay tests/fixtures/app/silent-except
```

The same works on two refs of any local repository:

```bash
gh repo clone saagpatel/agent-config-guard-demo /tmp/guard-demo
uv run agent-permission-diff app replay --git-repo /tmp/guard-demo --base main --head hook-mcp-instructions
```

Recordings live in `tests/fixtures/app/<scenario>/`: `event.json` (the webhook event name
and payload) plus the `base/` and `head/` file trees. `scripts/make_demo_repo.py` turns
them into the demo repository.

## Limits of this slice

- Swallowed is static. A handler that only logs at debug level, or swallows through a
  helper function, is not reported; a probe run that proves a finding comes next.
- Category ranking reads called names (`verify_token`, `db.commit`, `fetch`), so a
  wrapper with a neutral name ranks as "other".
- Config Guard reads startup configs first, then changed agent-facing files, up to 300 per
  side; GitHub lists at most 3,000 changed files. Anything past a limit, or missing from a
  truncated tree, is marked unread, which Config Guard reports as a finding rather than
  passing. Both sides are compared from the pull request's merge base, so changes that
  landed on the base branch later are not blamed on the pull request.
- An allow rule the Range has no data on (an unknown program, an unrecognised tool) is
  reported as high: unknown reach is not treated as safe.
- Webhook deliveries are processed in the server process; a restart drops in-flight work
  (re-run the check). Hosting is not part of this slice.
