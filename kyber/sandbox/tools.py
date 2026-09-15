"""Agent tool flavors: baked Linux builds + forwarded auth, no per-sandbox redo.

macOS host binaries cannot execute in the Linux sandbox, so tools enter via
image flavors (`build --with claude,codex`) while auth enters per session:
env tokens (Claude subscription) or single allowlisted credential files
(Codex/opencode/Gemini), each gated by explicit user consent.

Manifest schema `kyber-tool/v1` (repo `sandbox/images/tools/*.yaml` first,
then `~/.kyber/tools.d/*.yaml` for company tools):

  schema: kyber-tool/v1
  id: acme-coder                        # [a-z0-9_-]+, filename must match
  display: Acme Coder
  description: ...
  install: ["npm install -g @acme/coder-cli"]   # RUN verbatim, as root, in flavor stage
  dirs: [/home/sandbox/.acme-coder]     # created + chowned in flavor stage
  check: acme-coder --version           # `doctor` readiness probe (runs in image)
  build_secrets:                        # optional: private-registry creds for build only
    - {id: npmrc, src: ~/.npmrc}        # via BuildKit --mount (never in layers)
  auth:
    env: [ACME_API_KEY]                 # forwarded from host env (values never stored)
    files:                              # single files only — never dirs, never globs
      - {src: ~/.acme-coder/credentials.json,
         dest: /home/sandbox/.acme-coder/credentials.json, mode: ro}
    notes: "Log in once on your Mac; sandboxes reuse it."
"""
from __future__ import annotations

import hashlib
import json
import os
import re
from dataclasses import dataclass
from typing import Optional

from kyber.sandbox.common import SandboxError, home_dir
from kyber.sandbox.policies import SANDBOX_WORKDIR

SCHEMA = "kyber-tool/v1"
TOOL_ID_RE = re.compile(r"[a-z0-9][a-z0-9_-]{0,63}")
CONSENT_FILENAME = "consent.json"

EXAMPLE_MANIFEST = """\
# Example company tool. Rename this file to <id>.yaml (must match id below).
schema: kyber-tool/v1
id: acme-coder
display: Acme Coder (example)
description: Company terminal agent. Replace install/auth with the real thing.
install:
  - npm install -g @acme/coder-cli
dirs:
  - /home/sandbox/.acme-coder
check: acme-coder --version
# Private registry? Uncomment: token stays out of layers via BuildKit secret.
# build_secrets:
#   - id: npmrc
#     src: ~/.npmrc
auth:
  env:
    - ACME_API_KEY
  files:
    - src: ~/.acme-coder/credentials.json
      dest: /home/sandbox/.acme-coder/credentials.json
      mode: ro
  notes: >-
    Log in once on your Mac; sandboxes reuse it. Prefer ro mounts; use rw only
    when the tool refreshes tokens itself.
"""


@dataclass(frozen=True)
class BuildSecret:
    id: str   # BuildKit secret id referenced by --mount in install RUNs
    src: str  # host absolute path (expanded), e.g. ~/.npmrc


@dataclass(frozen=True)
class AuthFile:
    src: str   # host absolute path (expanded)
    dest: str  # container absolute path
    mode: str  # "ro" | "rw"


@dataclass(frozen=True)
class ToolManifest:
    id: str
    display: str
    description: str
    install: tuple
    dirs: tuple
    check: str
    auth_env: tuple
    auth_files: tuple  # tuple[AuthFile, ...]
    build_secrets: tuple  # tuple[BuildSecret, ...]
    notes: str
    source: str  # "builtin" | "user"


def _repo_tools_dir() -> str:
    try:
        import kyber as _pkg

        root = os.path.dirname(os.path.dirname(os.path.abspath(_pkg.__file__)))
        return os.path.join(root, "sandbox", "images", "tools")
    except Exception:
        return ""


def user_tools_dir() -> str:
    return os.path.join(home_dir(), "tools.d")


def ensure_user_dir() -> str:
    """Create ~/.kyber/tools.d + example on first use. Returns the dir."""
    d = user_tools_dir()
    try:
        os.makedirs(d, exist_ok=True)
    except OSError as e:
        raise SandboxError(f"could not create {d}: {e}") from e
    example = os.path.join(d, "acme-coder.yaml.example")
    if not os.path.exists(example):
        try:
            with open(example, "w", encoding="utf-8") as fh:
                fh.write(EXAMPLE_MANIFEST)
        except OSError:
            pass
    return d


def _parse_manifest(path: str, source: str) -> ToolManifest:
    import yaml

    try:
        with open(path, encoding="utf-8") as fh:
            data = yaml.safe_load(fh)
    except Exception as e:
        raise SandboxError(f"bad tool manifest {path}: {e}") from e
    if not isinstance(data, dict):
        raise SandboxError(f"bad tool manifest {path}: top level must be a mapping")

    def err(msg: str) -> SandboxError:
        return SandboxError(f"bad tool manifest {path}: {msg}")

    if data.get("schema") != SCHEMA:
        raise err(f"schema must be {SCHEMA!r}")
    tool_id = str(data.get("id") or "")
    if not TOOL_ID_RE.fullmatch(tool_id):
        raise err("id must match [a-z0-9_-]+ (max 64, start alnum)")
    base = os.path.basename(path)
    if base not in (tool_id + ".yaml", tool_id + ".yaml.example"):
        raise err(f"filename must be {tool_id}.yaml")
    install = data.get("install") or []
    if not isinstance(install, list) or not install or not all(isinstance(s, str) for s in install):
        raise err("install must be a non-empty list of shell lines")
    dirs = tuple(str(d) for d in (data.get("dirs") or []))
    for d in dirs:
        if not d.startswith("/") or d in ("/", "/work", "/tmp", "/etc", "/usr", "/bin"):
            raise err(f"dirs entry {d!r} must be an absolute tool-owned path")
    check = str(data.get("check") or "").strip()
    if not check:
        raise err("check must be a non-empty verify command")
    auth = data.get("auth") or {}
    if not isinstance(auth, dict):
        raise err("auth must be a mapping")
    auth_env = tuple(str(k) for k in (auth.get("env") or []))
    for k in auth_env:
        if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", k):
            raise err(f"auth.env entry {k!r} is not a valid env name")
    files: list[AuthFile] = []
    for entry in (auth.get("files") or []):
        if not isinstance(entry, dict):
            raise err("auth.files entries must be mappings")
        src = os.path.abspath(os.path.expanduser(str(entry.get("src") or "")))
        dest = str(entry.get("dest") or "")
        mode = str(entry.get("mode") or "ro").lower()
        if not src or not os.path.isabs(src):
            raise err("auth.files src must be an absolute host path")
        if not dest.startswith("/") or dest in ("/", SANDBOX_WORKDIR):
            raise err(f"auth.files dest {dest!r} must be absolute and not / or /work")
        if dest == SANDBOX_WORKDIR or dest.startswith(SANDBOX_WORKDIR + "/"):
            raise err(f"auth.files dest {dest!r} must not hide the workspace")
        if mode not in ("ro", "rw"):
            raise err("auth.files mode must be ro or rw")
        files.append(AuthFile(src=src, dest=dest, mode=mode))
    return ToolManifest(
        id=tool_id, display=str(data.get("display") or tool_id),
        description=str(data.get("description") or ""),
        install=tuple(str(s) for s in install), dirs=dirs, check=check,
        auth_env=auth_env, auth_files=tuple(files),
        build_secrets=_parse_build_secrets(data.get("build_secrets") or [], err),
        notes=str((auth.get("notes")) or ""), source=source)


def _parse_build_secrets(raw: object, err) -> tuple:
    """Optional private-registry credentials for the build only.

    Secrets travel via BuildKit `--mount=type=secret` (never ENV/ARG), so they
    leave no trace in layers or history. Existence is validated at build time,
    not parse time, so `tools` listings never break over a missing file.
    """
    if not isinstance(raw, list):
        raise err("build_secrets must be a list")
    out: list[BuildSecret] = []
    for entry in raw:
        if not isinstance(entry, dict):
            raise err("build_secrets entries must be mappings")
        sid = str(entry.get("id") or "")
        src = os.path.abspath(os.path.expanduser(str(entry.get("src") or "")))
        if not TOOL_ID_RE.fullmatch(sid):
            raise err(f"build_secrets id {sid!r} must match [a-z0-9_-]+")
        if not src or not os.path.isabs(src):
            raise err("build_secrets src must be an absolute host path")
        out.append(BuildSecret(id=sid, src=src))
    return tuple(out)


def resolve_build_secrets(ids: list[str]) -> list[dict]:
    """[{id, src}] for a flavor build. Raises if a secret file is missing."""
    secrets: dict[str, str] = {}
    for tool_id in ids:
        for s in load_manifest(tool_id).build_secrets:
            secrets[s.id] = s.src
    resolved: list[dict] = []
    for sid, src in sorted(secrets.items()):
        if not os.path.isfile(src) or os.path.isdir(src):
            raise SandboxError(
                f"build secret {sid!r} missing: {src} not found on host. "
                f"Log in to the private registry on your Mac first.")
        resolved.append({"id": sid, "src": src})
    return resolved


def list_manifests() -> list[ToolManifest]:
    """All known tools: builtins first, then user dir (user wins on id clash)."""
    found: dict[str, ToolManifest] = {}
    repo = _repo_tools_dir()
    if repo and os.path.isdir(repo):
        for fname in sorted(os.listdir(repo)):
            if fname.endswith(".yaml"):
                m = _parse_manifest(os.path.join(repo, fname), "builtin")
                found[m.id] = m
    udir = user_tools_dir()
    if os.path.isdir(udir):
        for fname in sorted(os.listdir(udir)):
            if fname.endswith(".yaml"):
                m = _parse_manifest(os.path.join(udir, fname), "user")
                found[m.id] = m
    return sorted(found.values(), key=lambda m: m.id)


def available_ids() -> list[str]:
    return [m.id for m in list_manifests()]


def load_manifest(tool_id: str) -> ToolManifest:
    for m in list_manifests():
        if m.id == tool_id:
            return m
    known = ", ".join(available_ids()) or "(none)"
    raise SandboxError(f"unknown tool {tool_id!r}. Available: {known}. "
                       f"Add company tools as ~/.kyber/tools.d/<id>.yaml")


def parse_id_list(raw: str) -> list[str]:
    """'claude, codex' -> ['claude', 'codex']; dedupes, keeps order."""
    ids: list[str] = []
    for part in (raw or "").replace(";", ",").split(","):
        p = part.strip().lower()
        if p and p not in ids:
            ids.append(p)
    for pid in ids:
        if not TOOL_ID_RE.fullmatch(pid):
            raise SandboxError(f"invalid tool id {pid!r}: use [a-z0-9_-]+")
    return ids


def flavor_tag(ids: list[str], base_tag: str = "") -> str:
    """Deterministic flavor tag for a tool set, e.g. kyber-sandbox:with-claude-codex."""
    from kyber.sandbox.policies import SANDBOX_IMAGE

    base = (base_tag or SANDBOX_IMAGE).split(":")[0]
    slug = "-".join(sorted(ids))
    if len(slug) > 48:
        slug = hashlib.sha1(slug.encode()).hexdigest()[:12]
    return f"{base}:with-{slug}" if slug else (base_tag or SANDBOX_IMAGE)


def _secret_mounts(m) -> str:
    """`--mount=type=secret,...` flags for a tool's install RUN (BuildKit only)."""
    parts = []
    for s in m.build_secrets:
        # Mounted at the path each tool expects its config (npm reads ~/.npmrc
        # as root during build, i.e. /root/.npmrc). Convention: <id> maps to a
        # well-known target; npmrc is the only supported id for now.
        target = "/root/.npmrc" if s.id == "npmrc" else f"/run/secrets/{s.id}"
        parts.append(f"--mount=type=secret,id={s.id},target={target}")
    return " ".join(parts)


def flavor_dockerfile(ids: list[str], base_tag: str) -> str:
    """Generated flavor stage: base image + tool installs + owned dirs.

    One RUN per tool (better layer caching); tools declaring build_secrets get
    a `--mount=type=secret` RUN so registry tokens never land in layers.
    """
    manifests = [load_manifest(i) for i in ids]
    lines = [f"FROM {base_tag}", "USER root"]
    for m in manifests:
        mount_flags = _secret_mounts(m)
        run_open = f"RUN {mount_flags} set -eux \\" if mount_flags else "RUN set -eux \\"
        steps = [f"echo '== kyber tool: {m.id} =='"] + list(m.install)
        lines.append(run_open)
        lines.append(" && \\\n    ".join(steps))
    for m in manifests:
        for d in m.dirs:
            # mkdir -p leaves intermediate parents root-owned: re-chown the
            # whole tree so the sandbox user can create sibling dirs at runtime
            # (e.g. opencode's ~/.local/state next to ~/.local/share).
            lines.append(f"RUN mkdir -p {d} && chown -R 65532:65532 /home/sandbox")
    lines.append('LABEL kyber.identity="1"')
    lines.append("USER 65532")
    lines.append("WORKDIR /work")
    return "\n".join(lines) + "\n"


@dataclass
class ResolvedAuth:
    env: dict
    mounts: list[dict]  # [{src, dest, mode}]
    missing: list[str]  # human-readable gaps (auth not present on host)
    notes: list[str]


def resolve_auth(ids: list[str], host_env: Optional[dict] = None) -> ResolvedAuth:
    """Map tool auth needs to host reality. Missing creds are reported, not fatal."""
    import os as _os

    src = host_env if host_env is not None else _os.environ
    env: dict = {}
    mounts: list[dict] = []
    missing: list[str] = []
    notes: list[str] = []
    for tool_id in ids:
        m = load_manifest(tool_id)
        for key in m.auth_env:
            if src.get(key):
                env[key] = src[key]
            else:
                missing.append(f"{m.display}: {key} not set in host env")
        for f in m.auth_files:
            if _os.path.isfile(f.src) and not _os.path.isdir(f.src):
                mounts.append({"src": f.src, "dest": f.dest, "mode": f.mode,
                               "tool": m.id})
            else:
                missing.append(f"{m.display}: {f.src} not found on host")
        if m.notes:
            notes.append(f"{m.display}: {m.notes}")
    return ResolvedAuth(env=env, mounts=mounts, missing=missing, notes=notes)


def _consent_path() -> str:
    return os.path.join(home_dir(), CONSENT_FILENAME)


def _load_consent() -> dict:
    try:
        with open(_consent_path(), encoding="utf-8") as fh:
            data = json.load(fh)
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def _save_consent(store: dict) -> None:
    try:
        with open(_consent_path(), "w", encoding="utf-8") as fh:
            json.dump(store, fh, indent=2)
    except OSError as e:
        raise SandboxError(f"could not persist consent: {e}") from e


def _auth_fingerprint(m: ToolManifest) -> dict:
    return {"env": sorted(m.auth_env),
            "files": sorted(f"{f.src}->{f.dest}:{f.mode}" for f in m.auth_files)}


def is_consented(m: ToolManifest) -> bool:
    """Consent is per tool AND per manifest content — edits re-prompt."""
    rec = _load_consent().get(m.id)
    return isinstance(rec, dict) and rec.get("auth") == _auth_fingerprint(m)


def grant_consent(m: ToolManifest) -> None:
    store = _load_consent()
    import time as _time

    store[m.id] = {"auth": _auth_fingerprint(m),
                   "granted_at": _time.strftime("%Y-%m-%dT%H:%M:%S")}
    _save_consent(store)


def revoke_consent(tool_id: str) -> bool:
    store = _load_consent()
    if tool_id in store:
        store.pop(tool_id)
        _save_consent(store)
        return True
    return False


def consent_report(tool_id: str) -> str:
    """One consent screen block: exactly what file/env goes where and why."""
    m = load_manifest(tool_id)
    lines = [f"{m.display} ({m.id}) would receive:"]
    for key in m.auth_env:
        lines.append(f"  env {key} (value read live at up, never stored)")
    for f in m.auth_files:
        lines.append(f"  file {f.src} -> {f.dest} [{f.mode}]"
                     + (" (token refresh needs write)" if f.mode == "rw" else ""))
    if m.notes:
        lines.append(f"  note: {m.notes}")
    return "\n".join(lines)


def subscription_conflict(host_env: Optional[dict] = None) -> Optional[str]:
    """ANTHROPIC_API_KEY outranks subscription auth — flag the money trap."""
    import os as _os

    src = host_env if host_env is not None else _os.environ
    if src.get("ANTHROPIC_API_KEY") and src.get("CLAUDE_CODE_OAUTH_TOKEN"):
        return ("ANTHROPIC_API_KEY is set AND CLAUDE_CODE_OAUTH_TOKEN is set: "
                "the API key outranks the subscription inside Claude Code, so usage "
                "bills per-token instead of your plan. Unset ANTHROPIC_API_KEY or "
                "pass --subscription to strip it from the sandbox.")
    return None
