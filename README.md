# pi-bitwarden

[中文版](README.zh.md)

A [pi coding agent](https://github.com/earendil-works/pi-coding-agent) extension that delivers Bitwarden secrets to **processes, not the LLM**.

When the model needs to run a command that requires a credential (an API token, `docker login`, `git push`...), the secret goes straight from your Bitwarden vault into the bash child process's environment. The secret **never appears in the conversation** — it is not sent to the LLM provider and not written to session files.

## Features

| Tool | What it does | Model sees the secret? |
|---|---|---|
| `bw_list` | List items (name / username / URI / id), never secrets | ❌ |
| `bw_inject` | Fetch a secret into a bash env var (per-call confirmation) | ❌ only "injected as $XXX" |
| `bw_clipboard` | Copy to the system clipboard, auto-cleared after 30s | ❌ |
| `bw_reveal` | Plain text (per-call confirmation + strong warning, can be disabled) | ✅ user-approved per call |
| `/bw status\|unlock\|lock\|clear` | Manage unlock state | — |

## Security model

- **Master password**: Zenity desktop prompt (TUI input fallback without a desktop), passed to `bw unlock` only via an env var — never argv, logs, or sessions
- **BW_SESSION lives in pi process memory only**: never on disk, never in the bash environment (the model cannot snoop the vault with `bw list`)
- **Output scrubber**: a `tool_result` hook replaces every active secret (and its base64 form) in all tool results with `[BW_SCRUBBED:$VAR]` — `printenv`, `echo $VAR` and friends are caught
- **Fail-closed**: with neither UI nor desktop, confirmations are always denied
- **Auto-lock**: after N idle minutes (default 0 = one unlock per session), on `/bw lock`, on `/new` `/fork` session switches, and on pi exit — locking drops the session key and every injected variable
- **Audit log**: `~/.bw/pi-extension/audit.log` (timestamps, item names, env names, allow/deny — never secret values)
- **Env-name blocklist**: rejects injection vectors like `PATH`, `LD_*`, `NODE_OPTIONS`, `BW_*`, `PI_*`

### Filling browser forms

Works with agent-browser, the model never seeing the secret:

```bash
bw_inject item GitHub env GH_PASS          # 1) inject
agent-browser fill @e4 "$GH_PASS"          # 2) fill the form
```

For sites you log into repeatedly, import once into agent-browser's own auth vault — no secret needed afterwards:

```bash
printenv $GH_PASS | agent-browser auth save my-app --username me@example.com --password-stdin
agent-browser auth login my-app
```

### Known residual risks (honest disclosure)

- After injection, the model could in principle exfiltrate a secret through a network command (`curl` etc. — the scrubber cannot catch that). This is inherent to "secret in the bash environment" and is gated by the per-injection confirmation.
- One-way hashes (md5/sha256) are not scrubbed.
- A `bw_reveal` plain-text value necessarily transits the LLM provider and the session file — hence the per-call confirmation.

## Install

Requires: the `bw` CLI, logged in (`bw login`); `zenity` for desktop prompts (without a desktop the TUI fallback works).

```bash
# Option 1: as a pi package
pi install git:github.com/hljhljhlj/pi-bitwarden

# Option 2: dev install (edits in the repo take effect on /reload)
git clone https://github.com/hljhljhlj/pi-bitwarden ~/Project/pi-bitwarden
~/Project/pi-bitwarden/install.sh   # symlinks into ~/.pi/agent/extensions/
```

## Config `~/.bw/pi-extension/config.json`

```jsonc
{
  "autoLockMinutes": 0,     // idle auto-lock; 0 = one master-password prompt per session
  "keepOnResume": true,     // keep unlock state across /resume (/new and /fork always lock)
  "clipboardClearSeconds": 30,
  "allowReveal": true,      // false = disable the plain-text channel entirely
  "maxInjectedEnv": 12
}
```

## Development & tests

```bash
npm test    # = bash test/run.sh
```

The end-to-end suite is fully headless: mocked `bw` / `zenity` / `wl-copy` (`test/mocks/`) plus one real `pi --no-session --mode json` session per scenario. **All assertions run against tool-result events**, never against the model's prose (model summaries paraphrase and hallucinate; tool events are authoritative).

Coverage: load + bash override, not-logged-in hint (no prompt), leak-free listing, inject → env var → output scrubbing, base64-variant scrubbing, clipboard, fail-closed deny path, reveal allow path, and **exactly one unlock per session**.

> Debugging lesson: an arithmetic expansion error in `echo "$(( $(cat multi-line-file) + 1 ))"` makes bash abort the script with exit code 0 — silently "allowing" a confirmation dialog. Counters must be single-number truncating writes.

## History

This extension replaces the earlier `bw-mcp` (a blind-proxy MCP for vault organization — renaming, moving, deleting — with secrets force-redacted). pi-bitwarden solves the opposite problem: getting secrets *to* a process, via env injection, clipboard, or gated plain text, each behind human confirmation.

## License

MIT
