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
kyber sandbox ls                                # list sessions (docker + local)
kyber sandbox exec demo --cmd "ls -la /work"    # one command, non-interactive
kyber sandbox logs demo                         # container logs / audit entries
kyber sandbox snapshot demo -o demo.tar         # export /work to host
kyber sandbox view demo                         # live terminal dashboard (Ctrl-C quits)
kyber sandbox down demo --delete-workspace
kyber doctor
```

## Sandbox terminal identity

You can always tell you're inside the cage: the sandbox shell has a magenta
`⬢ kyber/<name>` prompt, sets your terminal tab title to `⬢ kyber sandbox:
<name>`, and prints a banner on entry — plus `kyber sandbox shell` marks the
transition with a panel on the host side. Purely cosmetic (the real boundary
is the container), baked into the image: after pulling/building a new image,
run `kyber sandbox build` once; `kyber doctor` tells you if your image
predates the identity layer.

`kyber sandbox view <name>` is a live read-only mission view: session,
`/work` tree, recent logs, audit trail. Nothing there can disturb the session.

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

## Without Docker (opt-in local fallback)

If no Docker daemon is running (`kyber doctor` says "daemon unreachable"),
you have two options:

1. Start one (macOS): `open -a Docker` or `colima start` — real isolation.
2. Run without containers (no isolation boundary — accidents only, not malware):

```bash
kyber sandbox up --backend local --allow-unsafe --name demo
kyber sandbox shell --backend local --allow-unsafe demo
kyber sandbox exec --backend local --allow-unsafe demo --cmd "pytest -q"
```

Host-visible workspace: `kyber sandbox up --name demo --mount ~/projects/demo`
binds that one host dir as `/work` (docker backend) instead of a sealed
named volume — the agent can touch exactly that dir, host tools see it live.
Never `$HOME`, `/`, or `~/.kyber`; `down --delete-workspace` never deletes
a host mount.

What the local backend does: a workspace at `~/.kyber/workspaces/<name>/`,
commands run there with a scrubbed env (only `PATH` + your agent API keys —
`SSH_AUTH_SOCK` etc. never leak in), `HOME` jailed to the workspace, CPU
time caps, wall-clock timeouts, and an audit trail. It refuses to run as
root. `--offline` is only accepted when macOS `sandbox-exec` can actually
enforce it (probed at `up` time — on recent macOS it can't, and `up`
fails fast telling you so instead of pretending). Same session names can't
exist in both backends at once.

## Layout

- `kyber/sandbox/policies.py` isolation source of truth (strict legacy + open mode)
- `kyber/sandbox/docker_env.py` runtime detection (CLI-present vs daemon-reachable)
- `kyber/sandbox/shell.py` docker session runtime (up/shell/exec/logs/snapshot/down/build)
- `kyber/sandbox/local.py` opt-in unsafe local fallback (no daemon)
- `kyber/sandbox/backends.py` `--backend auto|docker|local` dispatcher
- `kyber/sandbox/view.py` live read-only terminal dashboard (`sandbox view`)
- `kyber/sandbox/common.py` shared errors/session/audit helpers
- `kyber/sandbox/manager.py` legacy low-level Docker manager (kept, strict mode)
- `kyber/cli_sandbox.py` `kyber sandbox ...` commands
- `kyber/cli.py` `init`, `doctor`, bare-`kyber` help
- `kyber/onboard.py` setup checks, `kyber/config.py` settings, `kyber/server.py` home/docker helpers
- `sandbox/images/Dockerfile.sandbox-agent` general agent image

Breaking change (v0.2): the v0.1 red-team scan platform (API, worker, scanners,
MCP, `wizard`/`demo`/`submit`/`agent`) was removed in the full pivot to
general sandbox. The old attacker/target Dockerfiles remain under
`sandbox/images/` for reference.
