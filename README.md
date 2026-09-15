# kyber — Agent Red-Team Sandbox (MVP)

API-only platform: submit snippets / repos / service URLs → agents red-team them in isolated Docker sandboxes → JSON/SARIF findings.

## Quickstart (local, no Docker required for smoke test)

```bash
pip install -e ".[dev]"
pytest -q
uvicorn kyber.api.main:app --reload  # default sqlite ./kyber.db, API key dev-key-1
```

Submit via CLI (needs API running):

```bash
export KYBER_API_KEY=dev-key-1
python -m kyber.cli submit --file evals/../tests/test_judge.py --profile quick
python -m kyber.cli report <scan-id>
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
