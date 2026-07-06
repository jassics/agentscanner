"""OSV.dev dependency-vulnerability client — used by AS-DEP-001 / AS-MCP-005.

Three deliberate design choices, each different from the obvious "copy
SkillSpector's SC4" approach:

1. **Disk-backed cache, not in-memory.** agentscanner is a short-lived CLI
   process — an in-memory cache buys nothing across separate ``scan``
   invocations (e.g. one per pre-commit run, one per CI job). Results are
   cached to ``~/.cache/agentscanner/osv_cache.json`` with a TTL, so repeated
   scans of the same repo/CI pipeline don't re-hit the network for unchanged
   dependencies.

2. **No hardcoded fallback CVE list.** A bundled "offline vulnerability list"
   goes stale the moment it's written and creates false confidence — a scan
   silently using a months-old snapshot looks identical to one using live
   data. When OSV.dev is unreachable (or ``--offline`` is set), the lookup
   returns ``None`` and the check simply finds nothing for that dependency —
   it never fabricates a verdict.

3. **Single-call per-dependency query, not batch+hydrate.** OSV's batch
   endpoint returns only vulnerability IDs and requires a second round trip
   per ID to get severity/summary data. Skills and MCP servers rarely
   declare more than a handful of dependencies, so a plain ``POST
   /v1/query`` per pinned dependency (which returns full vulnerability
   details in one round trip) is simpler and no slower in practice.
"""
from __future__ import annotations

import json
import os
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import List, Optional

from .models import Severity

_OSV_URL = "https://api.osv.dev/v1/query"
_TIMEOUT = float(os.environ.get("AGENTSCANNER_OSV_TIMEOUT", "3.0"))
_CACHE_TTL = int(os.environ.get("AGENTSCANNER_OSV_CACHE_TTL", str(24 * 3600)))

_SEVERITY_MAP = {
    "CRITICAL": Severity.CRITICAL,
    "HIGH": Severity.HIGH,
    "MODERATE": Severity.MEDIUM,
    "MEDIUM": Severity.MEDIUM,
    "LOW": Severity.LOW,
}


def is_offline() -> bool:
    """True when ``--offline`` (via ``AGENTSCANNER_OFFLINE``) was requested."""
    return os.environ.get("AGENTSCANNER_OFFLINE", "").strip().lower() in ("1", "true", "yes")


def _cache_dir() -> Path:
    base = os.environ.get("XDG_CACHE_HOME") or str(Path.home() / ".cache")
    d = Path(base) / "agentscanner"
    try:
        d.mkdir(parents=True, exist_ok=True)
    except OSError:
        pass
    return d


def _cache_path() -> Path:
    return _cache_dir() / "osv_cache.json"


def _load_cache() -> dict:
    p = _cache_path()
    if not p.is_file():
        return {}
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return {}


def _save_cache(cache: dict) -> None:
    try:
        _cache_path().write_text(json.dumps(cache), encoding="utf-8")
    except OSError:
        pass


def _cache_key(ecosystem: str, name: str, version: str) -> str:
    return f"{ecosystem}:{name}:{version}"


def query_dependency(ecosystem: str, name: str, version: Optional[str]) -> Optional[List[dict]]:
    """Return OSV vulnerability records affecting *name==version*.

    Returns ``None`` when the lookup could not be performed at all (no
    version to check, offline mode, or a network/parse error) — callers must
    treat ``None`` as "unknown", never as "clean". Returns ``[]`` when OSV.dev
    was actually queried and reported nothing.
    """
    if not version:
        return None

    key = _cache_key(ecosystem, name, version)
    cache = _load_cache()
    entry = cache.get(key)
    if entry and time.time() - entry.get("ts", 0) < _CACHE_TTL:
        return entry["vulns"]

    if is_offline():
        return None

    body = json.dumps(
        {"version": version, "package": {"name": name, "ecosystem": ecosystem}}
    ).encode("utf-8")
    req = urllib.request.Request(
        _OSV_URL, data=body, headers={"Content-Type": "application/json"}, method="POST"
    )
    try:
        with urllib.request.urlopen(req, timeout=_TIMEOUT) as resp:
            data = json.loads(resp.read().decode("utf-8"))
    except (urllib.error.URLError, TimeoutError, ValueError, OSError):
        return None

    vulns = data.get("vulns", []) if isinstance(data, dict) else []
    cache[key] = {"ts": time.time(), "vulns": vulns}
    _save_cache(cache)
    return vulns


def to_severity(vuln: dict) -> Severity:
    """Best-effort severity for one OSV vulnerability record.

    OSV does not expose a normalized numeric CVSS score across ecosystems —
    the ``severity`` field for CVSS_V3 entries is a vector string, not a
    score, and computing a base score from it requires the full CVSS
    formula. Rather than approximate that, we use the ``database_specific
    .severity`` label most GHSA-backed advisories (PyPI/npm) already carry,
    and default to HIGH — a confirmed advisory match — when no label is
    present.
    """
    db = vuln.get("database_specific", {})
    if isinstance(db, dict) and db.get("severity"):
        return _SEVERITY_MAP.get(str(db["severity"]).upper(), Severity.HIGH)
    return Severity.HIGH
