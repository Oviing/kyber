"""LiteLLM wrapper: single-string prompt in, single-string completion out.

Keeps the agent loop provider-agnostic (OpenAI, Anthropic, Ollama, ... all
work via `settings.llm_model`, e.g. `gpt-4o-mini`, `claude-3-5-sonnet`,
`ollama/llama3`). Import of litellm is lazy so the base install stays lean.
"""
from __future__ import annotations


def default_llm_fn(prompt: str) -> str:
    from kyber.config import settings

    try:
        import litellm
    except ImportError as e:
        raise RuntimeError(
            "LLM agent needs the 'llm' extra: pip install -e \".[llm]\" "
            "(provides litellm). Set LLM_MODEL / LLM_API_KEY or "
            "KYBER_LLM_MODEL via settings.") from e
    model = settings.llm_model
    api_key = settings.llm_api_key or None
    try:
        resp = litellm.completion(
            model=model,
            messages=[{"role": "user", "content": prompt}],
            api_key=api_key,
            max_tokens=800,
            temperature=0.2,
        )
    except Exception as e:
        raise RuntimeError(f"LLM call failed (model={model!r}): {e}") from e
    try:
        return resp.choices[0].message.content or ""
    except Exception:
        return str(resp)
