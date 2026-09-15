"""Onboarding helpers: environment checks shared by `init`, `doctor`, `demo`,
`agent` preflight, and `mcp --install`. All checks are best-effort and never
raise — they return structured (ok, detail) results for display.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from typing import Optional

SANDBOX_IMAGES = ("kyber-attacker:latest", "kyber-target-py:latest")

PROFILE_HELP = (
    "quick: secrets + known-bad patterns (fast, no model needed) | "
    "full: deep SAST/DAST incl. live probes | "
    "adversarial: AI-code + jailbreak checks | "
    "agent: an LLM drives the sandbox (needs model key, else fallback sweep)"
)

# Deliberately vulnerable sample so `kyber demo` always finds something.
DEMO_CODE = '''"""Kyber demo target: contains an obvious secret and a command injection sink."""
import os

API_KEY = "sk-demo-1234567890abcdef"  # hardcoded secret (demo)

AWS_KEY = "AKIAIOSFODNN7EXAMPLE"  # demo AWS key pattern


def list_files(user_input):
    # command injection sink (demo): unsanitized input reaches os.system
    os.system("ls " + user_input)
'''

DEMO_FILENAME = "kyber_demo_target.py"


def seen_file() -> str:
    from kyber.server import home_dir

    return os.path.join(home_dir(), "seen")


def is_first_run() -> bool:
    try:
        return not os.path.exists(seen_file())
    except OSError:
        return False


def mark_seen() -> None:
    try:
        with open(seen_file(), "w") as fh:
            fh.write("1")
    except OSError:
        pass


def first_run_banner() -> Optional[str]:
    """One-time hint for brand-new users. Returns the banner or None."""
    if not is_first_run():
        return None
    mark_seen()
    return ("First time here? Try `kyber demo` for a 1-minute guided example, "
            "or `kyber doctor` to check your setup.")


def litellm_installed() -> bool:
    try:
        import litellm  # noqa: F401

        return True
    except ImportError:
        return False


def llm_ready() -> tuple[bool, str]:
    """Is a real LLM backend available for `kyber agent`?"""
    from kyber.config import settings

    if not litellm_installed():
        return False, "litellm not installed (pip install -e \".[llm]\")"
    model = settings.llm_model or ""
    key = settings.llm_api_key or os.environ.get("LLM_API_KEY", "")
    if model.startswith(("ollama/", "ollama_chat/")):
        return True, f"local model {model} (no key needed)"
    if not key:
        return False, "LLM_API_KEY is not set"
    return True, f"model {model}"


def sandbox_images_status(timeout: int = 10) -> tuple[Optional[bool], str]:
    """Check sandbox images exist. Returns (None, ...) when docker is absent."""
    if shutil.which("docker") is None:
        return None, "docker not found"
    try:
        out = subprocess.run(
            ["docker", "images", "--format", "{{.Repository}}:{{.Tag}}"],
            capture_output=True, text=True, timeout=timeout, check=False)
    except Exception as e:
        return None, f"docker query failed ({e})"
    if out.returncode != 0:
        return None, "docker query failed"
    have = set((out.stdout or "").split())
    missing = [i for i in SANDBOX_IMAGES if i not in have]
    if not missing:
        return True, "sandbox images present"
    return False, "missing: {}".format(", ".join(missing))


def docker_hint() -> Optional[str]:
    """Short warning for scan flows when isolation is unavailable or incomplete."""
    if shutil.which("docker") is None:
        return ("Docker not found: scans run in limited fallback mode (thinner results). "
                "Sandbox isolation stays manual — see README production section. "
                "Run `kyber doctor` for details.")
    ok, detail = sandbox_images_status()
    if ok is False:
        return (f"Sandbox images {detail}. Scans fall back to limited mode until you build them "
                "(see README production section).")
    return None


# ---- MCP client install ----

def mcp_config_path(client: str = "claude-desktop") -> Optional[str]:
    if client != "claude-desktop":
        return None
    home = os.path.expanduser("~")
    if sys.platform == "darwin":
        return os.path.join(home, "Library", "Application Support",
                            "Claude", "claude_desktop_config.json")
    if sys.platform.startswith("win"):
        base = os.environ.get("APPDATA") or home
        return os.path.join(base, "Claude", "claude_desktop_config.json")
    return os.path.join(home, ".config", "Claude", "claude_desktop_config.json")


def mcp_server_entry(command: str = "kyber") -> dict:
    return {"command": command, "args": ["mcp"]}


def install_mcp_client(client: str = "claude-desktop", command: str = "kyber",
                       dry_run: bool = False) -> tuple[bool, str]:
    """Merge the kyber MCP server into the client's config file."""
    path = mcp_config_path(client)
    if path is None:
        return False, f"unknown client {client!r} (only claude-desktop is supported)"
    cfg: dict = {}
    if os.path.exists(path):
        try:
            with open(path, encoding="utf-8") as fh:
                cfg = json.load(fh)
        except (OSError, ValueError) as e:
            return False, f"existing config at {path} is unreadable ({e}); fix it first"
    servers = cfg.get("mcpServers")
    if not isinstance(servers, dict):
        servers = {}
        cfg["mcpServers"] = servers
    servers["kyber"] = mcp_server_entry(command)
    rendered = json.dumps(cfg, indent=2)
    if dry_run:
        return True, f"would write {path}:\n{rendered}"
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(rendered + "\n")
    except OSError as e:
        return False, f"could not write {path} ({e})"
    return True, f"kyber MCP server installed in {path} (restart {client} to pick it up)"
