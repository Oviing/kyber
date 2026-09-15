# kyber — Agent Red-Team Sandbox (MVP)

API-only platform: submit snippets / repos / service URLs → agents red-team them in isolated Docker sandboxes → JSON/SARIF findings.

## Quickstart

Just type `kyber` — a guided wizard checks the setup, starts the API if needed,
asks what to scan, runs the agents, and shows findings:

```bash
pip install -e ".[dev]"
kyber              # guided scan (cold start does everything)
```

Other commands: `kyber wizard --target FILE --profile quick`, `kyber up` /
`kyber down` (managed API server), `kyber doctor` (diagnostics),
`kyber submit/status/report` (manual flow).

## LLM agent (does the work inside the sandbox)

Prompt an LLM that red-teams the target with sandbox tools (ls/read/exec,
scanners, safe probes). Any model works via LiteLLM:

```bash
pip install -e ".[llm]"   # provides litellm
export LLM_MODEL=gpt-4o-mini LLM_API_KEY=...
kyber agent --target ./app.zip --goal "find RCE and explain exploitability"
# without a key it runs a deterministic fallback sweep so the command still returns value
```

Same engine via API: submit with `profile: agent` + `goal`. Trace lands in
`<artifact_dir>/scans/<id>/agent_trace.json`.

## MCP server (Claude / MCP clients)

```json
{"mcpServers": {"kyber": {"command": "kyber", "args": ["mcp"]}}}
```

Tools: `load_target_snippet` / `load_target_archive`, `sandbox_exec/ls/read`,
`run_scanner`, `run_probe`, `submit_finding`, `list_findings`, `get_trace`.
Every exec is policy-gated (`kyber/sandbox/policies.py`); archives extract
inside the container only.

Manual flow (needs API running):

```bash
uvicorn kyber.api.main:app --reload  # default sqlite ./kyber.db, API key dev-key-1
export KYBER_API_KEY=dev-key-1
kyber submit --file tests/test_judge.py --profile quick
kyber report <scan-id>
# archives: validated server-side, extracted inside the sandbox only
kyber submit --file BomCalculator_v2.2.0_DM.zip --profile quick
```

## Production (with sandbox isolation)

```bash
cp .env.example .env  # set DATABASE_URL=postgresql... + API_KEYS
docker compose up --build
docker build -f sandbox/images/Dockerfile.attacker -t kyber-attacker:latest sandbox/images
docker build -f sandbox/images/Dockerfile.target-py -t kyber-target-py:latest sandbox/images
```

API: `POST /v1/targets`, `POST /v1/targets/upload` (.zip archives, 50 MB max),
`POST /v1/scans`, `GET /v1/scans/{id}`, `GET /v1/scans/{id}/findings`, `GET .../report.sarif`.

## Layout

- `kyber/api/` FastAPI + auth + routes
- `kyber/sandbox/` Docker manager + `policies.py` (isolation source of truth)
- `kyber/agents/` planner, scanner, exploiter, adversarial, judge, graph
- `kyber/tools/` scanner parsers, safe probes, jailbreak pack
- `kyber/worker/jobs.py` RQ job (inline fallback when Redis absent)
- `kyber/cli.py` Typer CLI
- `evals/cases.py` regression cases
