# kyber — Safe sandbox for terminal AI agents

Kyber gives you an isolated Docker sandbox with a terminal inside. You install
and run whatever AI agent you like there (opencode, claude, codex, aider, ...).
The agent can do **anything inside the sandbox** — install packages, run code,
`curl`, `rm -rf` — and nothing touches your host except the `/work` workspace
volume.

## Quickstart

```bash
pip install -e .
kyber init                        # checks Docker + sandbox image + keys
kyber sandbox build               # builds kyber-sandbox:latest (once)
kyber sandbox up --name demo      # create + start an isolated sandbox
kyber sandbox shell demo          # open a terminal inside it
# inside the sandbox:
npm i -g opencode && opencode     # or: claude, codex, aider, ...
exit
kyber sandbox down demo           # destroy container + network (workspace kept)
```

More commands:

```bash
kyber sandbox ls                          # list sessions
kyber sandbox exec demo -- "ls -la /work" # one command, non-interactive
kyber sandbox logs demo                   # container logs
kyber sandbox snapshot demo -o demo.tar   # export /work to host
kyber sandbox down demo --delete-workspace
kyber doctor
```

Keys: set e.g. `ANTHROPIC_API_KEY` / `OPENAI_API_KEY` / `LLM_API_KEY` in your
shell (or `.env`) before `up` — they are passed into the container only.

Need no network inside? `kyber sandbox up --name demo --offline`.

## Safety model

Single source of truth: `kyber/sandbox/policies.py` (open mode).

* Boundary, not censorship: **no command is blocked inside** the sandbox.
* Always on: `cap_drop ALL`, `no-new-privileges`, non-root user `65532`,
  `pids_limit`, memory/CPU caps, `tmpfs` on `/tmp`.
* Never: no `docker.sock` mount, no host bind-mounts except the dedicated
  workspace volume at `/work`, no `--privileged`.
* Per-session bridge network (destroyed with the container); `--offline`
  makes it internal. Full egress is the default so agents can install tools.
* Every host-initiated action is appended to `~/.kyber/sandbox-audit.log`.

## Layout

- `kyber/sandbox/policies.py` isolation source of truth (strict legacy + open mode)
- `kyber/sandbox/shell.py` session runtime (up/shell/exec/logs/snapshot/down/build)
- `kyber/sandbox/manager.py` legacy low-level Docker manager (kept, strict mode)
- `kyber/cli_sandbox.py` `kyber sandbox ...` commands
- `kyber/cli.py` `init`, `doctor`, bare-`kyber` help
- `kyber/onboard.py` setup checks, `kyber/config.py` settings, `kyber/server.py` home/docker helpers
- `sandbox/images/Dockerfile.sandbox-agent` general agent image

Breaking change (v0.2): the v0.1 red-team scan platform (API, worker, scanners,
MCP, `wizard`/`demo`/`submit`/`agent`) was removed in the full pivot to
general sandbox. The old attacker/target Dockerfiles remain under
`sandbox/images/` for reference.
