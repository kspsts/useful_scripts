from __future__ import annotations

import os
from pathlib import Path

APP_ROOT = Path(__file__).resolve().parent
PROJECT_ROOT = APP_ROOT.parent

DEFAULT_RULES_PATH = Path(os.getenv("DEFAULT_RULES_PATH", str(PROJECT_ROOT / "best_practices.json")))
