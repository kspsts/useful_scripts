#!/usr/bin/env python3
"""Аудит GPMC HTML-отчётов по правилам из gpo_audit.ps1 (Python-версия)."""
import argparse
import csv
import html
import json
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Set

COLOR_RESET = "\033[0m"
COLOR_HEADER = "\033[36m"
COLOR_ERROR = "\033[31m"
COLOR_WARNING = "\033[33m"
COLOR_SUCCESS = "\033[32m"
COLOR_DETAIL = "\033[90m"
COLOR_NOTE = "\033[35m"
COLOR_FIX = "\033[33m"

SEVERITY_ORDER = {
    "critical": 0,
    "high": 1,
    "medium": 2,
    "low": 3,
    "info": 4,
}
SEVERITY_LEVELS = tuple(SEVERITY_ORDER.keys())


def normalize_key(value: str) -> str:
    if value is None:
        return ""
    return re.sub(r"\s+", " ", value.strip()).casefold()


def normalize_text(value: str, mode: str) -> str:
    if value is None:
        return ""
    if mode == "identity":
        return value.strip()
    if mode == "lower_ws_no_commas":
        cleaned = re.sub(r"[\s,]+", " ", value.strip())
        return cleaned.casefold()
    # default: collapse whitespace and lower
    cleaned = re.sub(r"\s+", " ", value.strip())
    return cleaned.casefold()


def get_first_int(value: str) -> Optional[int]:
    if not value:
        return None
    match = re.search(r"-?\d+", value)
    if match:
        try:
            return int(match.group(0))
        except ValueError:
            return None
    return None


def truncate_value(value: str, limit: int = 400) -> str:
    if value is None:
        return ""
    if len(value) <= limit:
        return value
    return value[:limit].rstrip() + " …"


@dataclass
class CompareConfig:
    type: str
    tokens: List[str] = field(default_factory=list)
    value: Optional[int] = None
    min: Optional[int] = None
    max: Optional[int] = None
    values: Optional[List[int]] = None


@dataclass
class Rule:
    id: str
    title: str
    category: str
    severity: str
    profiles: List[str]
    patterns_raw: List[str]
    desired_raw: List[str]
    desired_text: str
    normalize_code: str
    compare_data: Optional[Dict[str, object]]
    recommendation: str
    fix: str
    notes: str
    expected_regex_raw: List[str]
    origin: str = "rules"

    patterns: List[re.Pattern] = field(init=False)
    desired_norm: List[str] = field(init=False)
    expected_regex: List[re.Pattern] = field(init=False)
    expected_display: str = field(init=False)
    compare: Optional[CompareConfig] = field(init=False)

    def __post_init__(self) -> None:
        flags = re.IGNORECASE | re.DOTALL
        self.patterns = [re.compile(pat, flags) for pat in self.patterns_raw]
        self.desired_norm = [normalize_text(str(val), self.normalize_code) for val in self.desired_raw if str(val).strip()]
        self.expected_regex = [re.compile(pat, re.IGNORECASE) for pat in self.expected_regex_raw]
        self.expected_display = self.desired_text or " / ".join(str(v) for v in self.desired_raw if str(v).strip())
        if isinstance(self.compare_data, dict):
            comp_type = self.compare_data.get("type")
            tokens = self.compare_data.get("tokens", [])
            value = self.compare_data.get("value")
            min_value = self.compare_data.get("min")
            max_value = self.compare_data.get("max")
            values = self.compare_data.get("values")
            self.compare = CompareConfig(
                type=comp_type,
                tokens=[str(t) for t in tokens] if tokens else [],
                value=value,
                min=min_value,
                max=max_value,
                values=list(values) if values else None,
            )
        else:
            self.compare = None

    @property
    def desired_display(self) -> str:
        return self.expected_display


def build_table_pattern(policy_name: str) -> str:
    escaped = re.escape(policy_name)
    return rf"<td>\s*{escaped}\s*</td>\s*<td>\s*([^<]*)\s*</td>"


def _normalize_profiles(raw_profiles: Optional[Sequence[str]]) -> List[str]:
    if raw_profiles:
        return [str(profile) for profile in raw_profiles if str(profile).strip()]
    return ["Base"]


def _hydrate_rule(entry: Dict[str, Any], origin: str = "rules") -> Rule:
    if not isinstance(entry, dict):
        raise ValueError("rule entry must be a dictionary")

    patterns: List[str]
    desired_values: List[str]

    if entry.get("patterns"):
        patterns = [str(value) for value in entry.get("patterns", []) if str(value).strip()]
        desired_values = entry.get("desired") or entry.get("expected") or []
    else:
        policy = entry.get("policy")
        if not policy:
            raise ValueError(f"rule entry {entry!r} is missing 'patterns' or 'policy'")
        names: List[str] = [str(policy)]
        alt_names = entry.get("alt_policies") or entry.get("aliases") or []
        for name in alt_names:
            if str(name).strip():
                names.append(str(name))
        patterns = [build_table_pattern(name) for name in names]
        desired_values = entry.get("expected") or []

    rule_id = entry.get("id") or entry.get("policy")
    if not rule_id:
        raise ValueError("rule entry missing 'id' and 'policy'")

    title = entry.get("title") or entry.get("policy") or str(rule_id)

    return Rule(
        id=str(rule_id),
        title=str(title),
        category=str(entry.get("category", "Custom")),
        severity=str(entry.get("severity", "")),
        profiles=_normalize_profiles(entry.get("profiles")),
        patterns_raw=patterns,
        desired_raw=[str(v) for v in desired_values if str(v).strip()],
        desired_text=str(entry.get("desired_text", "")),
        normalize_code=str(entry.get("normalize", "lower_ws")),
        compare_data=entry.get("compare"),
        recommendation=str(entry.get("recommendation", "")),
        fix=str(entry.get("fix", "")),
        notes=str(entry.get("notes", "")),
        expected_regex_raw=[str(value) for value in entry.get("expected_regex", []) if str(value).strip()],
        origin=origin,
    )


def load_rules(path: Path) -> List[Rule]:
    data = json.loads(path.read_text(encoding="utf-8"))
    return [_hydrate_rule(entry, origin="rules") for entry in data]


def severity_weight(value: str) -> int:
    if not value:
        return len(SEVERITY_ORDER)
    return SEVERITY_ORDER.get(value.casefold(), len(SEVERITY_ORDER))


def load_compliance_rules(
    paths: Sequence[Path],
    min_severity: str,
    profiles_filter: Optional[Sequence[str]] = None,
) -> List[Rule]:
    threshold = SEVERITY_ORDER.get(min_severity.casefold(), len(SEVERITY_ORDER))
    profiles_filter_norm: Optional[Set[str]] = None
    if profiles_filter:
        profiles_filter_norm = {profile.casefold() for profile in profiles_filter if profile}

    rules: List[Rule] = []
    for path in paths:
        data = json.loads(path.read_text(encoding="utf-8"))
        for entry in data:
            rule = _hydrate_rule(entry, origin="compliance")
            if severity_weight(rule.severity) > threshold:
                continue
            if profiles_filter_norm is not None:
                rule_profiles = {profile.casefold() for profile in rule.profiles}
                if rule_profiles and rule_profiles.isdisjoint(profiles_filter_norm):
                    continue
            rules.append(rule)
    return rules


def merge_rules(primary: List[Rule], additional: Sequence[Rule]) -> List[Rule]:
    existing_ids = {rule.id for rule in primary}
    merged = list(primary)
    for rule in additional:
        if rule.id in existing_ids:
            continue
        merged.append(rule)
        existing_ids.add(rule.id)
    return merged


def collect_entries(result: Dict[str, List[Dict[str, object]]]) -> List[Dict[str, object]]:
    combined: List[Dict[str, object]] = []
    combined.extend(result.get("issues", []))
    combined.extend(result.get("missing", []))
    combined.extend(result.get("ok", []))
    combined.extend(result.get("missing_summary", []))
    return combined


def summarize_compliance(
    entries: Sequence[Dict[str, object]],
    min_severity: str,
) -> Dict[str, object]:
    summary = {
        "total": 0,
        "ok": 0,
        "issues": 0,
        "missing": 0,
        "by_severity": {},
        "min_severity": min_severity,
    }

    for entry in entries:
        if entry.get("origin") != "compliance":
            continue
        status = entry.get("status")
        severity_key = (entry.get("severity") or "unspecified").casefold()
        severity_data = summary["by_severity"].setdefault(
            severity_key,
            {"total": 0, "ok": 0, "issues": 0, "missing": 0},
        )
        summary["total"] += 1
        severity_data["total"] += 1
        if status == "OK":
            summary["ok"] += 1
            severity_data["ok"] += 1
        elif status == "Не найдено":
            summary["missing"] += 1
            severity_data["missing"] += 1
        else:
            summary["issues"] += 1
            severity_data["issues"] += 1

    if summary["total"]:
        summary["score"] = round(summary["ok"] / summary["total"] * 100, 1)
    else:
        summary["score"] = 0.0
    return summary


def print_compliance_summary(summary: Dict[str, object], use_color: bool) -> None:
    total = summary.get("total", 0)
    if not total:
        return

    score = summary.get("score", 0.0)
    ok = summary.get("ok", 0)
    issues = summary.get("issues", 0)
    missing = summary.get("missing", 0)
    min_severity = summary.get("min_severity", "")

    header = (
        "Комплаенс (≥ {min}): OK {ok}/{total}, Не ОК {issues}, Не найдено {missing}, "
        "доля соответствия {score:.1f}%"
    ).format(
        min=min_severity.capitalize() if min_severity else "",
        ok=ok,
        total=total,
        issues=issues,
        missing=missing,
        score=score,
    )
    print(_color_text(header, COLOR_HEADER, use_color))

    severity_items = summary.get("by_severity", {})
    if not severity_items:
        return

    def severity_sort_key(item: tuple) -> int:
        name = item[0]
        return SEVERITY_ORDER.get(name, len(SEVERITY_ORDER))

    for severity_name, data in sorted(severity_items.items(), key=severity_sort_key):
        label = severity_name.capitalize()
        line = (
            f"  {label}: OK {data['ok']}/{data['total']}"
            f", Не ОК {data['issues']}, Не найдено {data['missing']}"
        )
        print(_color_text(line, COLOR_DETAIL, use_color))


def parse_report(report_path: Path) -> List[Dict[str, str]]:
    raw_text = report_path.read_text(encoding="utf-16")
    name_pattern = re.compile(r"<td[^>]*class=\"gponame\">(.*?)</td>", re.IGNORECASE | re.DOTALL)

    matches = list(name_pattern.finditer(raw_text))
    gpos: List[Dict[str, str]] = []

    for idx, match in enumerate(matches):
        name_raw = match.group(1)
        name = html.unescape(name_raw).strip()
        if not name:
            continue

        table_start = raw_text.rfind("<table", 0, match.start())
        if table_start == -1:
            table_start = match.start()
        section_end = matches[idx + 1].start() if idx + 1 < len(matches) else len(raw_text)
        content = raw_text[table_start:section_end]

        gpos.append(
            {
                "name": name,
                "name_norm": normalize_key(name),
                "content": content,
            }
        )

    return gpos


def run_compare(compare: CompareConfig, raw_value: str, normalized: str) -> bool:
    raw_collapsed = re.sub(r"\s+", " ", raw_value.strip()).casefold()
    norm_value = normalized.casefold()
    if compare.type == "smbv1_disabled":
        if "0x0" in raw_collapsed:
            return True
        if re.search(r"\b0\b", raw_collapsed):
            return True
        if "disabled" in raw_collapsed or "отключ" in raw_collapsed:
            return True
        return False
    if compare.type == "ipv6_source_routing":
        if "disabled" in raw_collapsed or "отключ" in raw_collapsed:
            return True
        value = get_first_int(raw_value)
        return value is not None and value >= 2
    if compare.type == "text_any":
        for token in compare.tokens:
            t = token.casefold()
            if t.isdigit():
                if re.search(rf"\b{re.escape(t)}\b", raw_collapsed):
                    return True
            else:
                if t in raw_collapsed:
                    return True
        return False
    if compare.type == "text_nonempty":
        return bool(raw_value.strip())
    if compare.type == "text_success_failure":
        success = any(tok in raw_collapsed for tok in ("success", "успех"))
        failure = any(tok in raw_collapsed for tok in ("failure", "отказ"))
        return success and failure
    if compare.type == "int_min":
        value = get_first_int(raw_value)
        return value is not None and value >= int(compare.value)
    if compare.type == "int_max":
        value = get_first_int(raw_value)
        return value is not None and value <= int(compare.value)
    if compare.type == "int_equals":
        value = get_first_int(raw_value)
        return value is not None and value == int(compare.value)
    if compare.type == "int_range":
        value = get_first_int(raw_value)
        if value is None:
            return False
        if compare.min is not None and value < int(compare.min):
            return False
        if compare.max is not None and value > int(compare.max):
            return False
        return True
    if compare.type == "int_in":
        value = get_first_int(raw_value)
        return value is not None and value in (compare.values or [])
    if compare.type == "print_security_prompts":
        text = re.sub(r"\s+", " ", raw_value.strip()).casefold()
        install = re.search(r"installing drivers for a new connection:\s*(.+?)(?:when updating|$)", text)
        update = re.search(r"when updating drivers for an existing connection:\s*(.+)$", text)
        phrases = [
            "show warning and elevation prompt",
            "показывать предупреждение и запрос повышения",
            "показывать предупреждение и запрашивать повышение",
        ]
        ok_install = False
        ok_update = False
        if install:
            val = install.group(1).strip()
            ok_install = any(p in val for p in phrases)
        if update:
            val = update.group(1).strip()
            ok_update = any(p in val for p in phrases)
        return ok_install and ok_update
    return False


def apply_rule(rule: Rule, content: str) -> Dict[str, object]:
    found_value: Optional[str] = None
    for pattern in rule.patterns:
        match = pattern.search(content)
        if match:
            group_value = match.group(1)
            if isinstance(group_value, str):
                found_value = html.unescape(group_value).strip()
            else:
                found_value = str(group_value)
            break
    if not found_value:
        return {
            "status": "Не найдено",
            "found": "",
            "note": "Параметр не обнаружен",
        }

    normalized = normalize_text(found_value, rule.normalize_code)
    ok = False
    if rule.compare:
        ok = run_compare(rule.compare, found_value, normalized)
    else:
        if rule.expected_regex:
            for regex in rule.expected_regex:
                if regex.search(found_value):
                    ok = True
                    break
        if not ok and rule.desired_norm:
            for expected in rule.desired_norm:
                if expected and expected in normalized:
                    ok = True
                    break

    note = "" if ok else "Значение отличается от рекомендуемого"
    return {
        "status": "OK" if ok else "Не ОК",
        "found": truncate_value(found_value),
        "note": note,
    }


def evaluate_rules(
    gpos: List[Dict[str, str]],
    rules: List[Rule],
    profiles_filter: Optional[Sequence[str]] = None,
    include_ok: bool = False,
    include_missing: bool = False,
    missing_details: bool = False,
) -> Dict[str, List[Dict[str, object]]]:
    issues: List[Dict[str, object]] = []
    missing: List[Dict[str, object]] = []
    ok_items: List[Dict[str, object]] = []

    base_missing_tracker: Dict[str, Dict[str, object]] = {}
    base_missing_record_count = 0
    aggregated_missing_entries: List[Dict[str, object]] = []
    missing_summary_entries: List[Dict[str, object]] = []
    missing_aggregated_count = 0
    hidden_missing_records = 0

    profile_filter_norm = None
    if profiles_filter:
        profile_filter_norm = {p.casefold() for p in profiles_filter}

    base_rules: List[Rule] = []
    compliance_rules: List[Rule] = []
    for rule in rules:
        if rule.origin == "compliance":
            compliance_rules.append(rule)
        else:
            base_rules.append(rule)

    def profile_matches(rule: Rule) -> bool:
        if profile_filter_norm is None:
            return True
        rule_profiles = {p.casefold() for p in rule.profiles}
        if rule_profiles and rule_profiles.isdisjoint(profile_filter_norm):
            return False
        return True

    for gpo in gpos:
        content = gpo["content"]
        gpo_name = gpo["name"]
        for rule in base_rules:
            if not profile_matches(rule):
                continue
            result = apply_rule(rule, content)
            status = result["status"]

            if status == "OK":
                if include_ok:
                    entry = {
                        "rule_id": rule.id,
                        "title": rule.title,
                        "category": rule.category,
                        "severity": rule.severity,
                        "profiles": rule.profiles,
                        "origin": rule.origin,
                        "gpo": gpo_name,
                        "found": result["found"],
                        "expected_display": rule.desired_display,
                        "status": status,
                        "recommendation": rule.recommendation,
                        "fix": rule.fix,
                        "notes": rule.notes if status == "OK" else result["note"] or rule.notes,
                    }
                    ok_items.append(entry)
                continue

            if status == "Не найдено":
                tracker = base_missing_tracker.setdefault(
                    rule.id,
                    {
                        "rule": rule,
                        "gpos": [],
                    },
                )
                tracker["gpos"].append(gpo_name)
                base_missing_record_count += 1
                if include_missing and missing_details:
                    entry = {
                        "rule_id": rule.id,
                        "title": rule.title,
                        "category": rule.category,
                        "severity": rule.severity,
                        "profiles": rule.profiles,
                        "origin": rule.origin,
                        "gpo": gpo_name,
                        "found": result["found"],
                        "expected_display": rule.desired_display,
                        "status": status,
                        "recommendation": rule.recommendation,
                        "fix": rule.fix,
                        "notes": result["note"] or rule.notes,
                    }
                    missing.append(entry)
                continue

            entry = {
                "rule_id": rule.id,
                "title": rule.title,
                "category": rule.category,
                "severity": rule.severity,
                "profiles": rule.profiles,
                "origin": rule.origin,
                "gpo": gpo_name,
                "found": result["found"],
                "expected_display": rule.desired_display,
                "status": status,
                "recommendation": rule.recommendation,
                "fix": rule.fix,
                "notes": rule.notes if status == "OK" else result["note"] or rule.notes,
            }
            issues.append(entry)

    # Построение агрегированного списка для базовых правил
    for tracker in base_missing_tracker.values():
        rule: Rule = tracker["rule"]  # type: ignore[assignment]
        gpo_list: List[str] = tracker["gpos"]  # type: ignore[assignment]
        count = len(gpo_list)
        sample = gpo_list[:3]
        sample_display = ", ".join(sample)
        if count > len(sample):
            sample_display = sample_display + (", …" if sample_display else "…")
        if count <= 1 and sample_display:
            gpo_display = sample_display
        else:
            gpo_display = "Несколько GPO"
        summary_note = (
            f"Параметр не обнаружен в {count} GPO"
            + (f" (например: {', '.join(sample[:3])})" if sample else "")
        )
        aggregated_entry = {
            "rule_id": rule.id,
            "title": rule.title,
            "category": rule.category,
            "severity": rule.severity,
            "profiles": rule.profiles,
            "origin": rule.origin,
            "gpo": gpo_display,
            "found": "",
            "expected_display": rule.desired_display,
            "status": "Не найдено",
            "recommendation": rule.recommendation,
            "fix": rule.fix,
            "notes": summary_note,
            "missing_count": count,
            "missing_examples": sample,
        }
        aggregated_missing_entries.append(aggregated_entry)
    missing_aggregated_count += len(aggregated_missing_entries)

    if include_missing:
        if missing_details:
            missing_summary_entries.extend(aggregated_missing_entries)
        else:
            missing.extend(aggregated_missing_entries)
    else:
        missing_summary_entries.extend(aggregated_missing_entries)

    if not include_missing or not missing_details:
        hidden_missing_records += base_missing_record_count

    total_gpos = len(gpos)

    for rule in compliance_rules:
        if not profile_matches(rule):
            continue
        found_any = False
        note_missing = "Параметр не обнаружен ни в одном GPO"
        for gpo in gpos:
            content = gpo["content"]
            gpo_name = gpo["name"]
            result = apply_rule(rule, content)
            if result["status"] == "Не найдено":
                continue
            found_any = True
            entry = {
                "rule_id": rule.id,
                "title": rule.title,
                "category": rule.category,
                "severity": rule.severity,
                "profiles": rule.profiles,
                "origin": rule.origin,
                "gpo": gpo_name,
                "found": result["found"],
                "expected_display": rule.desired_display,
                "status": result["status"],
                "recommendation": rule.recommendation,
                "fix": rule.fix,
                "notes": rule.notes if result["status"] == "OK" else result["note"] or rule.notes,
            }
            if result["status"] == "OK":
                if include_ok:
                    ok_items.append(entry)
            elif result["status"] == "Не найдено":
                if include_missing and missing_details:
                    missing.append(entry)
            else:
                issues.append(entry)
        if not found_any:
            comp_entry = {
                "rule_id": rule.id,
                "title": rule.title,
                "category": rule.category,
                "severity": rule.severity,
                "profiles": rule.profiles,
                "origin": rule.origin,
                "gpo": "—",
                "found": "",
                "expected_display": rule.desired_display,
                "status": "Не найдено",
                "recommendation": rule.recommendation,
                "fix": rule.fix,
                "notes": rule.notes or note_missing,
                "missing_count": total_gpos,
                "missing_examples": [],
            }
            missing_aggregated_count += 1
            if include_missing and not missing_details:
                missing.append(comp_entry)
            else:
                missing_summary_entries.append(comp_entry)
            if not missing_details:
                hidden_missing_records += total_gpos

    return {
        "issues": issues,
        "missing": missing,
        "ok": ok_items,
        "missing_summary": missing_summary_entries,
        "missing_stats": {
            "aggregated_rules": missing_aggregated_count,
            "hidden_details": hidden_missing_records,
        },
    }


def format_expected(entry: Dict[str, object]) -> str:
    if entry.get("expected_display"):
        return entry["expected_display"]
    return ""


def _color_text(text: str, color: str, enable: bool) -> str:
    if not enable or not color:
        return text
    return f"{color}{text}{COLOR_RESET}"


def print_console_report(
    issues: List[Dict[str, object]],
    missing: List[Dict[str, object]],
    ok: List[Dict[str, object]],
    include_ok: bool,
    include_missing: bool,
    missing_details: bool,
    missing_summary: Sequence[Dict[str, object]],
    missing_stats: Dict[str, object],
    missing_limit: Optional[int],
) -> None:
    status_meta = {
        "Не ОК": {"label": "Не ОК", "icon": "⛔", "color": COLOR_ERROR, "order": 0},
        "Не найдено": {"label": "Не найдено", "icon": "⚠️", "color": COLOR_WARNING, "order": 1},
        "OK": {"label": "OK", "icon": "✅", "color": COLOR_SUCCESS, "order": 2},
    }

    items: List[Dict[str, object]] = []
    items.extend(issues)
    items.extend(missing)
    if include_ok:
        items.extend(ok)

    use_color = sys.stdout.isatty()

    if not items:
        print(_color_text("Несоответствия не обнаружены.", COLOR_SUCCESS, use_color))
        return

    def weight(entry: Dict[str, object]) -> tuple:
        meta = status_meta.get(entry.get("status"), {"order": 99})
        severity_rank = severity_weight(entry.get("severity", ""))
        return (
            meta.get("order", 99),
            severity_rank,
            entry.get("gpo", ""),
            entry.get("title", ""),
        )

    items.sort(key=weight)

    current_gpo = None
    for entry in items:
        gpo_name = entry.get("gpo", "Все GPO")
        if gpo_name != current_gpo:
            if current_gpo is not None:
                print()
            header = f"=== {gpo_name} ==="
            print(_color_text(header, COLOR_HEADER, use_color))
            current_gpo = gpo_name

        meta = status_meta.get(entry.get("status"), {"label": entry.get("status"), "icon": "•", "color": COLOR_DETAIL})
        severity = entry.get("severity")
        category = entry.get("category")
        parts = [meta["icon"], f"[{meta['label']}]"]
        if severity:
            parts.append(f"[{severity}]")
        if category:
            parts.append(f"[{category}]")
        title = entry.get("title")
        if title:
            parts.append(title)
        main_line = " ".join(parts)
        print(_color_text(main_line, meta.get("color", COLOR_DETAIL), use_color))

        print(_color_text(f"  Правило: {entry.get('rule_id')}", COLOR_DETAIL, use_color))
        origin = entry.get("origin")
        if origin and origin != "rules":
            origin_label = "Комплаенс" if origin == "compliance" else origin
            print(_color_text(f"  Источник: {origin_label}", COLOR_DETAIL, use_color))
        if entry.get("found"):
            print(_color_text(f"  Найдено:   {entry['found']}", COLOR_DETAIL, use_color))
        expected_str = format_expected(entry)
        if expected_str:
            print(_color_text(f"  Ожидается: {expected_str}", COLOR_DETAIL, use_color))
        if entry.get("notes"):
            print(_color_text(f"  Примечание: {entry['notes']}", COLOR_NOTE, use_color))
        if entry.get("recommendation"):
            print(_color_text(f"  Рекомендация: {entry['recommendation']}", COLOR_NOTE, use_color))
        if entry.get("fix"):
            print(_color_text(f"  Как исправить: {entry['fix']}", COLOR_FIX, use_color))

    summary_entries = list(missing_summary)
    summary_entries.sort(
        key=lambda entry: (
            severity_weight(entry.get("severity", "")),
            entry.get("title", ""),
        )
    )
    limit = None if missing_limit is None or missing_limit < 1 else missing_limit
    truncated = False
    if limit is not None and len(summary_entries) > limit:
        summary_entries_to_show = summary_entries[:limit]
        truncated = True
    else:
        summary_entries_to_show = summary_entries
    if summary_entries and not include_missing:
        print()
        print(_color_text("Правила без совпадений (агрегировано)", COLOR_HEADER, use_color))
        for entry in summary_entries_to_show:
            line_parts = [f"- {entry.get('rule_id')}"]
            title = entry.get("title")
            if title:
                line_parts.append(f"{title}")
            missing_count = entry.get("missing_count")
            if isinstance(missing_count, int):
                line_parts.append(f"— не найдено в {missing_count} GPO")
            else:
                line_parts.append("— не найдено")
            severity = entry.get("severity")
            if severity:
                line_parts.append(f"[{severity}]")
            print(_color_text(" ".join(line_parts), COLOR_WARNING, use_color))
            examples = entry.get("missing_examples")
            if isinstance(examples, Sequence) and examples:
                sample_text = ", ".join(map(str, examples[:3]))
                print(_color_text(f"  Например: {sample_text}", COLOR_DETAIL, use_color))
        if truncated:
            remaining = len(summary_entries) - len(summary_entries_to_show)
            print(_color_text(f"  … и ещё {remaining} правил. Используйте --missing-limit 0 для полного списка.", COLOR_DETAIL, use_color))

    hidden_details = int(missing_stats.get("hidden_details", 0) or 0)
    if hidden_details:
        print()
        if include_missing:
            hint = "--missing-details"
        else:
            hint = "--include-missing --missing-details"
        note_text = (
            f"Детали по {hidden_details} сочетаниям правило/GPO скрыты. Используйте {hint}."
        )
        print(_color_text(note_text, COLOR_DETAIL, use_color))


def export_csv(path: Path, rows: Sequence[Dict[str, object]]) -> None:
    fieldnames = [
        "status",
        "rule_id",
        "title",
        "category",
        "severity",
        "origin",
        "gpo",
        "found",
        "expected_display",
        "recommendation",
        "fix",
        "notes",
    ]
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            writer.writerow({key: row.get(key, "") for key in fieldnames})


def build_cli() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Сравнение настроек GPO (AllGPOs.htm) с правилами лучших практик.",
    )
    parser.add_argument("--report", required=True, help="Путь к AllGPOs.htm, экспортированному из GPMC.")
    parser.add_argument("--rules", help="JSON-файл с правилами. По умолчанию gpo_rules.json рядом со скриптом.")
    parser.add_argument("--csv", help="Путь для сохранения CSV-отчёта.")
    parser.add_argument("--include-ok", action="store_true", help="Включать соответствующие правила в вывод.")
    parser.add_argument(
        "--include-missing",
        "--include-not-found",
        action="store_true",
        dest="include_missing",
        help="Показывать записи со статусом 'Не найдено' (по умолчанию скрыты).",
    )
    parser.add_argument(
        "--missing-details",
        action="store_true",
        help="Выводить записи 'Не найдено' по каждому GPO (по умолчанию агрегируются по правилу).",
    )
    parser.add_argument(
        "--missing-limit",
        type=int,
        default=10,
        help="Сколько агрегированных записей 'Не найдено' показывать (0 — без ограничений).",
    )
    parser.add_argument(
        "--profiles",
        nargs="*",
        help="Фильтр по профилям правил (например: Base Firewall Defender).",
    )
    parser.add_argument(
        "--compliance",
        action="append",
        help=(
            "Дополнительный JSON с проверками комплаенса. Можно указать несколько; "
            "по умолчанию используется best_practices.json рядом со скриптом, если не задан --no-compliance."
        ),
    )
    parser.add_argument(
        "--no-compliance",
        action="store_true",
        help="Не подключать встроенный набор проверок комплаенса.",
    )
    parser.add_argument(
        "--compliance-min-severity",
        choices=SEVERITY_LEVELS,
        default="high",
        help="Минимальная критичность (critical/high/medium/low/info) для встроенных проверок комплаенса.",
    )
    parser.add_argument(
        "--compliance-profiles",
        nargs="*",
        help="Ограничить встроенные проверки комплаенса указанными профилями.",
    )
    return parser


def main() -> int:
    parser = build_cli()
    args = parser.parse_args()

    report_path = Path(args.report)
    if not report_path.exists():
        parser.error(f"Не найден файл отчёта: {report_path}")

    if args.rules:
        rules_path = Path(args.rules)
    else:
        rules_path = Path(__file__).with_name("gpo_rules.json")

    if not rules_path.exists():
        parser.error(f"Не найден файл правил: {rules_path}")

    try:
        rules = load_rules(rules_path)
    except Exception as exc:  # pragma: no cover
        parser.error(f"Не удалось загрузить правила: {exc}")

    compliance_paths: List[Path] = []
    compliance_rules: List[Rule] = []

    if not args.no_compliance:
        raw_paths: List[str] = []
        if args.compliance:
            for value in args.compliance:
                if value:
                    raw_paths.append(value)
        else:
            default_compliance = Path(__file__).with_name("best_practices.json")
            if default_compliance.exists():
                raw_paths.append(str(default_compliance))

        for raw in raw_paths:
            path = Path(raw)
            if not path.exists():
                parser.error(f"Не найден файл комплаенса: {path}")
            compliance_paths.append(path)

    if compliance_paths:
        try:
            compliance_rules = load_compliance_rules(
                compliance_paths,
                min_severity=args.compliance_min_severity,
                profiles_filter=args.compliance_profiles,
            )
        except Exception as exc:  # pragma: no cover
            parser.error(f"Не удалось загрузить проверки комплаенса: {exc}")
        if compliance_rules:
            rules = merge_rules(rules, compliance_rules)

    try:
        gpos = parse_report(report_path)
    except Exception as exc:  # pragma: no cover
        parser.error(f"Не удалось разобрать отчёт: {exc}")

    evaluation = evaluate_rules(
        gpos,
        rules,
        profiles_filter=args.profiles,
        include_ok=args.include_ok,
        include_missing=args.include_missing,
        missing_details=args.missing_details,
    )

    total_gpos = len(gpos)
    print(f"Обработано GPO: {total_gpos}")
    print()

    print_console_report(
        evaluation["issues"],
        evaluation["missing"],
        evaluation["ok"],
        include_ok=args.include_ok,
        include_missing=args.include_missing,
        missing_details=args.missing_details,
        missing_summary=evaluation.get("missing_summary", []),
        missing_stats=evaluation.get("missing_stats", {}),
        missing_limit=args.missing_limit if args.missing_limit is not None else 10,
    )

    combined_entries = collect_entries(evaluation)
    if any(entry.get("origin") == "compliance" for entry in combined_entries):
        print()
        compliance_summary = summarize_compliance(combined_entries, args.compliance_min_severity)
        print_compliance_summary(compliance_summary, sys.stdout.isatty())

    issue_count = len(evaluation["issues"])
    missing_rule_total = len(evaluation.get("missing", [])) + len(evaluation.get("missing_summary", []))
    missing_display = str(missing_rule_total)
    hidden_details = int(evaluation.get("missing_stats", {}).get("hidden_details", 0) or 0)
    if hidden_details:
        if args.include_missing and not args.missing_details:
            hint = "--missing-details"
        elif not args.include_missing:
            hint = "--include-missing --missing-details"
        else:
            hint = "--missing-details"
        missing_display += f" (детали скрыты для {hidden_details}; используйте {hint})"
    ok_count = len(evaluation["ok"])

    summary_text = "Итог: Не ОК: {issues}; Не найдено: {missing}; OK: {ok}".format(
        issues=issue_count,
        missing=missing_display,
        ok=ok_count,
    )
    print()
    print(_color_text(summary_text, COLOR_HEADER, sys.stdout.isatty()))

    if args.csv:
        rows = []
        rows.extend(evaluation["issues"])
        rows.extend(evaluation["missing"])
        if args.include_ok:
            rows.extend(evaluation["ok"])
        export_csv(Path(args.csv), rows)
        print(_color_text(f"CSV-отчёт сохранён: {args.csv}", COLOR_HEADER, sys.stdout.isatty()))

    if evaluation["issues"] or evaluation["missing"]:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
