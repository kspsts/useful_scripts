from __future__ import annotations

from pathlib import Path
from typing import Dict, List, Tuple

import sys

# Ensure gpo_audit.py is importable
ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from gpo_audit import load_rules, evaluate_rules, parse_report  # type: ignore


def parse_and_evaluate(report_path: Path, rules_path: Path, include_ok: bool, include_missing: bool, missing_details: bool):
    rules = load_rules(rules_path)
    gpos, _meta = parse_report(report_path)
    evaluation = evaluate_rules(
        gpos,
        rules,
        include_ok=include_ok,
        include_missing=include_missing,
        missing_details=missing_details,
        show_sources=False,
    )
    return evaluation, len(gpos)
