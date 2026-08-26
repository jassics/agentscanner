"""Shared detection patterns: secrets, dangerous commands, remote-exec, unicode.

Kept independently authored (not copied from any GPL source) so claudit can ship
under Apache-2.0.
"""
from __future__ import annotations

import re

# --- High-signal secret patterns (value-level) -----------------------------
SECRET_PATTERNS = [
    ("AWS access key id", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("Anthropic API key", re.compile(r"\bsk-ant-[A-Za-z0-9_\-]{20,}")),
    ("OpenAI API key", re.compile(r"\bsk-[A-Za-z0-9]{32,}")),
    ("GitHub token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b")),
    ("Slack token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}")),
    ("Google API key", re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b")),
    ("Private key block", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----")),
    ("JWT", re.compile(r"\beyJ[A-Za-z0-9_\-]+\.eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+")),
]

# env keys whose plaintext value is likely a credential
SECRET_KEY_NAME = re.compile(r"(?i)(api[_-]?key|secret|token|password|passwd|pwd|credential|access[_-]?key)")

# a value that is just an env reference / placeholder is NOT a hardcoded secret
ENV_REFERENCE = re.compile(r"^\s*(\$\{[^}]+\}|\$[A-Za-z_][A-Za-z0-9_]*|<[^>]+>|\"\"|''|)\s*$")


def is_env_reference(value: str) -> bool:
    """Return True if *value* is a shell/env placeholder rather than a literal secret."""
    return bool(ENV_REFERENCE.match(value or ""))


def find_secret(value: str):
    """Return (label, matched_text) for the first secret pattern hit, else None."""
    if not isinstance(value, str):
        return None
    for label, rx in SECRET_PATTERNS:
        m = rx.search(value)
        if m:
            return label, m.group(0)
    return None


# --- Remote code execution in shell commands -------------------------------
REMOTE_EXEC = re.compile(
    r"""(?ix)
    (?:curl|wget|fetch)\b[^|]*\|\s*(?:sudo\s+)?(?:ba)?sh        # curl ... | sh
  | (?:curl|wget)\b[^|]*\|\s*python\d?                          # curl ... | python
  | \b(?:eval|exec)\s+[\"']?\$\((?:curl|wget)                   # eval $(curl ...)
  | \biwr\b[^|]*\|\s*iex                                        # powershell iwr | iex
  | \b(?:Invoke-WebRequest|wget)\b[^|]*\|\s*Invoke-Expression
    """
)

# --- Dangerous commands that should not be broadly allowed -----------------
DANGEROUS_COMMANDS = {
    "curl", "wget", "sudo", "rm", "eval", "exec", "chmod", "chown",
    "nc", "ncat", "netcat", "dd", "mkfs", "scp", "ssh", "base64",
    "shred", "kill", "killall", "systemctl", "launchctl",
}

# --- Prompt-injection / steering indicators in prose -----------------------
INJECTION_PATTERNS = [
    ("override-instructions", re.compile(r"(?i)\b(ignore|disregard|forget)\b[^.\n]{0,40}\b(previous|prior|above|earlier|all)\b[^.\n]{0,20}\b(instruction|prompt|rule|direction)")),
    ("disable-controls", re.compile(r"(?i)\b(disable|bypass|turn\s+off|skip|ignore)\b[^.\n]{0,40}\b(hook|permission|guard|safety|security\s+check|approval|confirmation)")),
    ("silent-action", re.compile(r"(?i)\b(do\s+not|don'?t|never)\b[^.\n]{0,30}\b(tell|inform|notify|ask|warn)\b[^.\n]{0,20}\b(the\s+)?user")),
    ("auto-approve", re.compile(r"(?i)\b(without\s+(asking|confirmation|permission)|auto[- ]?approve|always\s+(say\s+)?yes)\b")),
    ("exfiltration", re.compile(r"(?i)\b(send|post|upload|exfiltrate|leak)\b[^.\n]{0,40}\b(credential|secret|token|password|api[_ -]?key|\.env|private\s+key)\b[^.\n]{0,40}\b(to|http|https|url|endpoint|server)")),
]

# Instructions in an agent/skill's OWN authored prose that explicitly override
# a natural stopping point -- distinct from INJECTION_PATTERNS above (which
# target untrusted content trying to redirect the agent). This is the agent's
# own author telling the model to disregard turn limits or resist interruption.
# Deliberately narrow (specific co-occurring phrasing, not generic "keep
# iterating until done" language, which is common and benign) to keep false
# positives low.
UNBOUNDED_EXECUTION_PATTERNS = [
    ("ignore-turn-limit", re.compile(r"(?i)\b(ignore|disregard|regardless\s+of|no\s+matter\s+how\s+many)\b[^.\n]{0,30}\b(turn|iteration|step)s?\b[^.\n]{0,10}\b(limit|cap|count|budget)")),
    ("resist-interruption", re.compile(r"(?i)\b(do\s+not|don'?t|never)\b[^.\n]{0,20}\bstop\b[^.\n]{0,30}\b(interrupt|told\s+to\s+stop|asked\s+to\s+stop|cancell?ed)")),
    ("run-indefinitely", re.compile(r"(?i)\b(run|work|keep\s+(on\s+)?(going|running|working))\b[^.\n]{0,20}\b(indefinitely|forever|without\s+(ever\s+)?stopping)\b")),
]

# Zero-width, bidi-control, and BOM characters that hide content in prompts.
# Built from explicit codepoints to keep the source readable and unambiguous.
_HIDDEN_RANGES = [
    (0x200B, 0x200F),  # zero-width space/joiners, LRM/RLM
    (0x202A, 0x202E),  # bidi embedding/override
    (0x2060, 0x2064),  # word joiner, invisible math operators
    (0x2066, 0x2069),  # bidi isolates
    (0xFEFF, 0xFEFF),  # BOM / zero-width no-break space
]
HIDDEN_UNICODE = re.compile(
    "[" + "".join(f"{chr(a)}-{chr(b)}" for a, b in _HIDDEN_RANGES) + "]"
)
