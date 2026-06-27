"""Check registry. Importing this package registers all built-in checks."""
from __future__ import annotations

from .base import CHECK_REGISTRY, Check, get_checks  # noqa: F401

# Import modules for their @register side effects.
from . import permissions  # noqa: F401,E402
from . import hooks        # noqa: F401,E402
from . import mcp          # noqa: F401,E402
from . import env_secrets  # noqa: F401,E402
from . import agents_skills  # noqa: F401,E402
from . import prompts      # noqa: F401,E402
from . import agentic_skills_ast  # noqa: F401,E402
