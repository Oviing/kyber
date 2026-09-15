"""Adversarial agent: jailbreak probes + insecure AI-code static checks."""
from kyber.tools.adversarial import JAILBREAK_PROMPTS, evaluate_jailbreak, scan_ai_code


def get_prompts() -> list[dict]:
    return [{"id": c["id"], "prompt": c["prompt"]} for c in JAILBREAK_PROMPTS]


def run_adversarial_static(snippet: str) -> list[dict]:
    return scan_ai_code(snippet or "")


def score_model_output(prompt_id: str, output: str) -> dict | None:
    return evaluate_jailbreak(prompt_id, output)
