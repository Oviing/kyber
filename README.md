# kyber — Agent Red-Team Sandbox (MVP)

API-only platform: submit snippets / repos / service URLs → agents red-team them in isolated Docker sandboxes → JSON/SARIF findings.

## Quickstart (5 minutes)

```bash
git clone <repo> && cd kyber
pip install -e ".[dev]"
kyber init     # checks Python, bootstraps .env, reports Docker/LLM status
kyber demo     # 1-minute example scan on a bundled sample — always finds something
kyber          # guided scan of your own target
```

Just typing `kyber` starts a guided wizard: it brings the API up if needed,
asks what to scan, runs the agents, and shows findings.

Other commands: `kyber wizard --target FILE --profile quick`, `kyber up` /
`kyber down` (managed API server), `kyber doctor` (diagnostics),
`kyber submit/status/report` (manual flow), `kyber init` (setup check),
`kyber demo` (worked example), `kyber mcp --install` (MCP client setup).

## What to scan

- **file**: a source file, or a `.zip` archive (50 MB max). Single files only, not directories.
- **repo**: a git URL (scans the referenced snapshot).
- **url**: a live service — only one you own or have permission to test (consent is asked).

Profiles: `quick` (secrets + known-bad patterns, fast), `full` (deep SAST/DAST),
`adversarial` (AI-code + jailbreak checks), `agent` (an LLM drives the sandbox).

Heads-up: `.zip` files containing only binaries (`.exe`, `.dll`, images) have no
source text to scan — you'll get an `info/no-scannable-text` finding explaining
that instead of silent zero results. Unzip and submit source files for real coverage.

## LLM agent (does the work inside the sandbox)

Prompt an LLM that red-teams the target with sandbox tools (ls/read/exec,
scanners, safe probes). Any model works via LiteLLM:

```bash
pip install -e ".[llm]"   # provides litellm
export LLM_MODEL=gpt-4o-mini LLM_API_KEY=...
kyber agent --target ./app.zip --goal "find RCE and explain exploitability"
```

Without a model backend the command asks before running a deterministic
fallback sweep (no model involved — findings are still real, just not LLM-driven);
`kyber doctor` shows backend status. Same engine via API: submit with
`profile: agent` + `goal`. Trace lands in
`<artifact_dir>/scans/<id>/agent_trace.json`.

## MCP server (Claude / MCP clients)

Easiest: `kyber mcp --install` (writes your Claude Desktop config; `--dry-run`
to preview). Manual alternative:

```json
{"mcpServers": {"kyber": {"command": "kyber", "args": ["mcp"]}}}
```

Tools: `load_target_snippet` / `load_target_archive`, `sandbox_exec/ls/read`,
`run_scanner`, `run_probe`, `submit_finding`, `list_findings`, `get_trace`.
Every exec is policy-gated (`kyber/sandbox/policies.py`); archives extract
inside the container only.

## Docker / sandbox isolation

Docker setup stays manual on purpose (you should know when untrusted code runs
isolated vs. not). Without Docker — or without the sandbox images — scans run
in a limited fallback mode and the CLI tells you so; `kyber doctor` shows the
details.

```bash
cp .env.example .env  # or just run `kyber init`
docker compose up --build
docker build -f sandbox/images/Dockerfile.attacker -t kyber-attacker:latest sandbox/images
docker build -f sandbox/images/Dockerfile.target-py -t kyber-target-py:latest sandbox/images
```

## Troubleshooting

- **Port busy / API won't start**: `kyber doctor` shows what's on the port; `kyber down`
  stops only the server Kyber started itself; logs live in `~/.kyber/api.log`.
- **"Cannot reach API"**: remote URLs are never autostarted — start the API there first.
- **0 findings**: can mean clean — or unscannable (see binary-zip note above); check the
  full report for `info/` findings that explain coverage.
- **Agent ran without a model**: by design it asks first; pass `--fallback-ok` to skip
  the prompt, or set `LLM_MODEL`/`LLM_API_KEY` for a real LLM run.
- **Manual API flow** (needs API running): `kyber up`, then
  `kyber submit --file tests/test_judge.py --profile quick` and `kyber report <scan-id>`.

API: `POST /v1/targets`, `POST /v1/targets/upload` (.zip archives, 50 MB max),
`POST /v1/scans`, `GET /v1/scans/{id}`, `GET /v1/scans/{id}/findings`, `GET .../report.sarif`.
For production, set `DATABASE_URL=postgresql...` + `API_KEYS` in `.env` (see `.env.example`).

## Layout

- `kyber/api/` FastAPI + auth + routes
- `kyber/sandbox/` Docker manager + `policies.py` (isolation source of truth)
- `kyber/agents/` planner, scanner, exploiter, adversarial, judge, graph
- `kyber/agent/` LLM loop + sandbox tool layer (`--fallback-ok` lives here)
- `kyber/tools/` scanner parsers, safe probes, jailbreak pack
- `kyber/worker/jobs.py` RQ job (inline fallback when Redis absent)
- `kyber/cli.py` Typer CLI (`init`, `demo`, `wizard`, `agent`, `mcp`, `doctor` …)
- `kyber/onboard.py` setup checks shared by init/doctor/demo/agent/mcp
- `evals/cases.py` regression cases
