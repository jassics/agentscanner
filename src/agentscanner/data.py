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
