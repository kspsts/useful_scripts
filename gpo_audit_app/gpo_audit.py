#!/usr/bin/env python3
"""Аудит GPMC HTML/XML-отчётов по правилам из gpo_audit.ps1 (Python-версия)."""
import argparse
import csv
import html
import json
import re
import sys
from dataclasses import dataclass, field
from datetime import datetime
from html.parser import HTMLParser
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Set, Tuple
from xml.etree import ElementTree as ET

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


def _html_escape(value: object, limit: Optional[int] = 800) -> str:
    if value is None:
        return ""
    if isinstance(value, (list, tuple, set)):
        value = ", ".join(str(v) for v in value if str(v).strip())
    text = str(value)
    if limit is not None and limit > 0 and len(text) > limit:
        text = truncate_value(text, limit)
    escaped = html.escape(text, quote=True)
    return escaped.replace("\n", "<br>")


def _collapse_ws(value: str) -> str:
    return re.sub(r"\s+", " ", value or "").strip()


def detect_report_format(raw_bytes: bytes, path: Path) -> str:
    sniff = raw_bytes[:4096]
    sniff_no_null = sniff.replace(b"\x00", b"").lower()
    if b"<?xml" in sniff_no_null or b"<gpo" in sniff_no_null or b"<gpos" in sniff_no_null:
        return "xml"
    if b"<html" in sniff_no_null or b"<!doctype html" in sniff_no_null:
        return "html"
    suffix = path.suffix.lower()
    if suffix in (".xml", ".gpreport"):
        return "xml"
    return "html"


def read_text_auto(path: Path, forced_encoding: Optional[str] = None) -> Tuple[str, str]:
    data = path.read_bytes()
    if forced_encoding:
        return data.decode(forced_encoding), forced_encoding

    encoding = ""
    if data.startswith(b"\xff\xfe") or data.startswith(b"\xfe\xff"):
        encoding = "utf-16"
    elif data.startswith(b"\xef\xbb\xbf"):
        encoding = "utf-8-sig"

    if encoding:
        return data.decode(encoding), encoding

    for candidate in ("utf-16", "utf-8", "cp1251"):
        try:
            return data.decode(candidate), candidate
        except UnicodeDecodeError:
            continue

    return data.decode("utf-8", errors="replace"), "utf-8?"


class _HTMLTextExtractor(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self._parts: List[str] = []
        self._skip = 0

    def handle_starttag(self, tag: str, attrs: List[Tuple[str, Optional[str]]]) -> None:
        tag = tag.lower()
        if tag in ("script", "style"):
            self._skip += 1
            return
        if tag in ("br", "p", "div", "tr", "td", "li"):
            self._parts.append(" ")

    def handle_endtag(self, tag: str) -> None:
        tag = tag.lower()
        if tag in ("script", "style") and self._skip:
            self._skip -= 1
            return
        if tag in ("p", "div", "tr", "li"):
            self._parts.append(" ")

    def handle_data(self, data: str) -> None:
        if self._skip:
            return
        if data:
            self._parts.append(data)

    def get_text(self) -> str:
        return _collapse_ws(html.unescape("".join(self._parts)))


class _HTMLTableExtractor(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self._skip = 0
        self._in_td = False
        self._current: List[str] = []
        self._row: List[str] = []
        self.pairs: List[Tuple[str, str]] = []

    def handle_starttag(self, tag: str, attrs: List[Tuple[str, Optional[str]]]) -> None:
        tag = tag.lower()
        if tag in ("script", "style"):
            self._skip += 1
            return
        if self._skip:
            return
        if tag == "td":
            self._in_td = True
            self._current = []
        elif tag == "br" and self._in_td:
            self._current.append(" ")

    def handle_endtag(self, tag: str) -> None:
        tag = tag.lower()
        if tag in ("script", "style") and self._skip:
            self._skip -= 1
            return
        if self._skip:
            return
        if tag == "td" and self._in_td:
            cell = _collapse_ws(html.unescape("".join(self._current)))
            self._row.append(cell)
            self._in_td = False
        elif tag == "tr":
            if len(self._row) >= 2:
                name = self._row[0]
                value = self._row[1]
                if name:
                    self.pairs.append((name, value))
            self._row = []

    def handle_data(self, data: str) -> None:
        if self._skip or not self._in_td:
            return
        if data:
            self._current.append(data)


def html_to_text(raw_html: str) -> str:
    parser = _HTMLTextExtractor()
    parser.feed(raw_html)
    return parser.get_text()


def extract_td_pairs(raw_html: str) -> List[Tuple[str, str]]:
    parser = _HTMLTableExtractor()
    parser.feed(raw_html)
    return parser.pairs


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
    policy_names: List[str]
    scope: str
    scope_allowlist: List[str]
    scope_regex: str
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
    policy_names_norm: List[str] = field(init=False)
    scope_allowlist_norm: Set[str] = field(init=False)
    scope_pattern: Optional[re.Pattern] = field(init=False)

    def __post_init__(self) -> None:
        flags = re.IGNORECASE | re.DOTALL
        self.patterns = [re.compile(pat, flags) for pat in self.patterns_raw]
        self.desired_norm = [normalize_text(str(val), self.normalize_code) for val in self.desired_raw if str(val).strip()]
        self.expected_regex = [re.compile(pat, re.IGNORECASE) for pat in self.expected_regex_raw]
        self.expected_display = self.desired_text or " / ".join(str(v) for v in self.desired_raw if str(v).strip())
        self.policy_names_norm = [normalize_key(name) for name in self.policy_names if name]
        self._refresh_scope_compiled()
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

    def _refresh_scope_compiled(self) -> None:
        self.scope_allowlist_norm = {normalize_key(name) for name in self.scope_allowlist if name}
        if self.scope_regex:
            self.scope_pattern = re.compile(self.scope_regex, re.IGNORECASE)
        else:
            self.scope_pattern = None

    def update_scope(self, scope: str, allowlist: Sequence[str], regex: str) -> None:
        self.scope = scope
        self.scope_allowlist = [str(name) for name in allowlist if str(name).strip()]
        self.scope_regex = regex or ""
        self._refresh_scope_compiled()

    @property
    def desired_display(self) -> str:
        return self.expected_display


def build_table_pattern(policy_name: str) -> str:
    escaped = re.escape(policy_name)
    return rf"<td[^>]*>\s*{escaped}\s*</td>\s*<td[^>]*>\s*([^<]*)\s*</td>"


def _normalize_profiles(raw_profiles: Optional[Sequence[str]]) -> List[str]:
    if raw_profiles:
        return [str(profile) for profile in raw_profiles if str(profile).strip()]
    return ["Base"]


def _hydrate_rule(entry: Dict[str, Any], origin: str = "rules") -> Rule:
    if not isinstance(entry, dict):
        raise ValueError("rule entry must be a dictionary")

    patterns: List[str]
    desired_values: List[str]
    policy_names: List[str] = []

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
        policy_names = list(names)
        patterns = [build_table_pattern(name) for name in names]
        desired_values = entry.get("expected") or []

    rule_id = entry.get("id") or entry.get("policy")
    if not rule_id:
        raise ValueError("rule entry missing 'id' and 'policy'")

    title = entry.get("title") or entry.get("policy") or str(rule_id)

    scope = str(entry.get("scope", "any_gpo") or "any_gpo")
    scope_allowlist = [str(name) for name in entry.get("scope_allowlist", []) if str(name).strip()]
    scope_regex = str(entry.get("scope_regex", "") or "")

    return Rule(
        id=str(rule_id),
        title=str(title),
        category=str(entry.get("category", "Custom")),
        severity=str(entry.get("severity", "")),
        profiles=_normalize_profiles(entry.get("profiles")),
        policy_names=policy_names,
        scope=scope,
        scope_allowlist=scope_allowlist,
        scope_regex=scope_regex,
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
    existing = {rule.id: rule for rule in primary}
    merged = list(primary)
    for rule in additional:
        if rule.id in existing:
            current = existing[rule.id]
            current_scope = (current.scope or "any_gpo").casefold()
            new_scope = (rule.scope or "any_gpo").casefold()
            if current_scope == "any_gpo" and new_scope != "any_gpo":
                current.update_scope(rule.scope, rule.scope_allowlist, rule.scope_regex)
            continue
        merged.append(rule)
        existing[rule.id] = rule
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


def _strip_ns(tag: str) -> str:
    if "}" in tag:
        return tag.split("}", 1)[1]
    return tag


def _extract_policy_pairs_from_xml(node: ET.Element) -> List[Tuple[str, str]]:
    name_tags = {
        "name",
        "policy",
        "setting",
        "settingname",
        "valuename",
        "keyname",
        "key",
    }
    value_tags = {
        "state",
        "value",
        "settingnumber",
        "settingstring",
        "settingboolean",
        "settingvalue",
        "data",
        "type",
        "valuevalue",
    }
    pairs: List[Tuple[str, str]] = []

    for parent in node.iter():
        children = list(parent)
        for idx, child in enumerate(children):
            tag = _strip_ns(child.tag).lower()
            if tag not in name_tags:
                continue
            name = _collapse_ws(child.text or "")
            if not name:
                continue
            value = ""
            for j in range(idx + 1, min(idx + 4, len(children))):
                sibling = children[j]
                s_tag = _strip_ns(sibling.tag).lower()
                if s_tag in value_tags and (sibling.text or "").strip():
                    value = _collapse_ws(sibling.text or "")
                    break
            pairs.append((name, value))

    for elem in node.iter():
        attrib = {k.lower(): v for k, v in elem.attrib.items()}
        name = attrib.get("name") or attrib.get("policy")
        if name:
            val = attrib.get("value") or attrib.get("state") or attrib.get("data") or ""
            pairs.append((_collapse_ws(name), _collapse_ws(val)))

    return pairs


def _find_gpo_name(node: ET.Element) -> str:
    preferred_tags = {"name", "displayname", "gponame"}
    for child in list(node):
        tag = _strip_ns(child.tag).lower()
        if tag in preferred_tags and (child.text or "").strip():
            return _collapse_ws(child.text or "")
    for attr_key in ("name", "displayname"):
        if attr_key in node.attrib and node.attrib[attr_key].strip():
            return _collapse_ws(node.attrib[attr_key])
    return "GPO"


def parse_xml_report(raw_bytes: bytes) -> List[Dict[str, object]]:
    root = ET.fromstring(raw_bytes)
    root_tag = _strip_ns(root.tag).lower()
    if root_tag == "gpo":
        gpo_nodes = [root]
    else:
        gpo_nodes = list(root.findall(".//GPO")) or list(root.findall(".//gpo"))
        if not gpo_nodes:
            gpo_nodes = [root]

    gpos: List[Dict[str, object]] = []
    for gpo in gpo_nodes:
        name = _find_gpo_name(gpo)
        content_text = _collapse_ws(" ".join(text for text in gpo.itertext() if text and text.strip()))
        pairs = _extract_policy_pairs_from_xml(gpo)
        policy_text = _collapse_ws(" ".join(f"{name}: {value}" for name, value in pairs if name))
        policy_map: Dict[str, List[str]] = {}
        for policy_name, value in pairs:
            key = normalize_key(policy_name)
            if not key:
                continue
            policy_map.setdefault(key, []).append(value)
        gpos.append(
            {
                "name": name,
                "name_norm": normalize_key(name),
                "content": content_text,
                "content_text": content_text,
                "policy_text": policy_text,
                "policy_map": policy_map,
                "format": "xml",
            }
        )
    return gpos


def parse_html_report(raw_text: str) -> List[Dict[str, object]]:
    name_pattern = re.compile(r"<td[^>]*class=\"gponame\">(.*?)</td>", re.IGNORECASE | re.DOTALL)

    matches = list(name_pattern.finditer(raw_text))
    gpos: List[Dict[str, object]] = []

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
        pairs = extract_td_pairs(content)
        policy_text = _collapse_ws(" ".join(f"{name}: {value}" for name, value in pairs if name))
        policy_map: Dict[str, List[str]] = {}
        for policy_name, value in pairs:
            key = normalize_key(policy_name)
            if not key:
                continue
            policy_map.setdefault(key, []).append(value)

        gpos.append(
            {
                "name": name,
                "name_norm": normalize_key(name),
                "content": content,
                "content_text": html_to_text(content),
                "policy_text": policy_text,
                "policy_map": policy_map,
                "format": "html",
            }
        )

    return gpos


def parse_report(report_path: Path, forced_encoding: Optional[str] = None) -> Tuple[List[Dict[str, object]], Dict[str, object]]:
    raw_bytes = report_path.read_bytes()
    report_format = detect_report_format(raw_bytes, report_path)
    encoding = "n/a"
    if report_format == "xml":
        gpos = parse_xml_report(raw_bytes)
    else:
        text, encoding = read_text_auto(report_path, forced_encoding=forced_encoding)
        gpos = parse_html_report(text)
        if not gpos:
            policy_text = ""
            gpos = [
                {
                    "name": report_path.stem,
                    "name_norm": normalize_key(report_path.stem),
                    "content": text,
                    "content_text": html_to_text(text),
                    "policy_text": policy_text,
                    "policy_map": {},
                    "format": "html",
                }
            ]
    meta = {
        "path": str(report_path),
        "format": report_format,
        "encoding": encoding,
    }
    return gpos, meta


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
        if compare.value is None:
            return False
        value = get_first_int(raw_value)
        return value is not None and value >= int(compare.value)
    if compare.type == "int_max":
        if compare.value is None:
            return False
        value = get_first_int(raw_value)
        return value is not None and value <= int(compare.value)
    if compare.type == "int_equals":
        if compare.value is None:
            return False
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


def _search_patterns(patterns: Sequence[re.Pattern], text: str) -> Optional[str]:
    for pattern in patterns:
        match = pattern.search(text)
        if match:
            group_value = match.group(1)
            if isinstance(group_value, str):
                return html.unescape(group_value).strip()
            return str(group_value)
    return None


def _lookup_policy_value(rule: Rule, policy_map: Dict[str, List[str]]) -> Optional[str]:
    if not policy_map or not rule.policy_names_norm:
        return None
    for key in rule.policy_names_norm:
        if key in policy_map:
            values = [val for val in policy_map.get(key, []) if val is not None]
            if not values:
                return ""
            return " | ".join(values)
    return None


def apply_rule(rule: Rule, gpo: Dict[str, object]) -> Dict[str, object]:
    content = str(gpo.get("content", "") or "")
    content_text = str(gpo.get("content_text", "") or "")
    policy_text = str(gpo.get("policy_text", "") or "")
    policy_map = gpo.get("policy_map", {}) or {}

    found_value = _search_patterns(rule.patterns, content)
    if found_value is None and content_text:
        found_value = _search_patterns(rule.patterns, content_text)
    if found_value is None and policy_text:
        found_value = _search_patterns(rule.patterns, policy_text)
    if found_value is None:
        found_value = _lookup_policy_value(rule, policy_map)

    if found_value is None:
        return {
            "status": "Не найдено",
            "found": "",
            "note": "Параметр не обнаружен",
        }

    normalized = normalize_text(found_value, rule.normalize_code)
    special_note: Optional[str] = None
    norm_lower = normalized.casefold()
    if rule.id == "LDAP.Server.CBT":
        if "если поддерживается" in norm_lower or "if supported" in norm_lower:
            special_note = "Выбрано 'Если поддерживается'; рекомендуется 'Требуется'."
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

    if ok:
        note = ""
    else:
        note = special_note or "Значение отличается от рекомендуемого"
    return {
        "status": "OK" if ok else "Не ОК",
        "found": truncate_value(found_value),
        "note": note,
    }


def gpo_in_scope(rule: Rule, gpo: Dict[str, object]) -> bool:
    gpo_name = str(gpo.get("name", "") or "")
    gpo_norm = normalize_key(gpo_name)

    if rule.scope_allowlist_norm:
        if gpo_norm not in rule.scope_allowlist_norm:
            return False

    if rule.scope_pattern and not rule.scope_pattern.search(gpo_name):
        return False

    scope = (rule.scope or "any_gpo").casefold()
    if scope == "domain_password_policy":
        return bool(
            re.search(
                r"(default[_\\s]?domain[_\\s]?policy|политика[_\\s]?по[_\\s]?умолчанию[_\\s]?домена)",
                gpo_name,
                re.IGNORECASE,
            )
        )
    if scope == "dc_only":
        return bool(
            re.search(
                r"(domain[_\\s]?controllers|domain controller|контроллер(ы|а) домена)",
                gpo_name,
                re.IGNORECASE,
            )
        )
    if scope == "gpo_allowlist":
        return bool(rule.scope_allowlist_norm)
    return True


def summarize_scope_status(rule: Rule, stats: Dict[str, int]) -> Tuple[str, str]:
    scope = (rule.scope or "any_gpo").casefold()
    in_scope = stats.get("in_scope", 0)
    ok = stats.get("ok", 0)
    issues = stats.get("issues", 0)
    missing = stats.get("missing", 0)

    if in_scope == 0:
        return "Не найдено", "Нет GPO в области применения"

    if scope in ("all_gpos", "gpo_allowlist"):
        if issues > 0:
            return "Не ОК", "Есть несоответствия в области применения"
        if missing > 0:
            return "Не найдено", "Правило не задано во всех GPO области применения"
        return "OK", ""

    # any_gpo / dc_only
    if ok > 0:
        return "OK", ""
    if issues > 0:
        return "Не ОК", "Найдены несоответствия, но нет корректных совпадений"
    return "Не найдено", "Параметр не обнаружен в области применения"


def evaluate_rules(
    gpos: List[Dict[str, object]],
    rules: List[Rule],
    profiles_filter: Optional[Sequence[str]] = None,
    include_ok: bool = False,
    include_missing: bool = False,
    missing_details: bool = False,
    show_sources: bool = False,
) -> Dict[str, List[Dict[str, object]]]:
    issues: List[Dict[str, object]] = []
    missing: List[Dict[str, object]] = []
    ok_items: List[Dict[str, object]] = []
    scope_summary: List[Dict[str, object]] = []
    scope_stats: Dict[str, Dict[str, int]] = {}

    base_missing_tracker: Dict[str, Dict[str, object]] = {}
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
        scope_stats[rule.id] = {
            "ok": 0,
            "issues": 0,
            "missing": 0,
            "in_scope": 0,
        }

    def profile_matches(rule: Rule) -> bool:
        if profile_filter_norm is None:
            return True
        rule_profiles = {p.casefold() for p in rule.profiles}
        if rule_profiles and rule_profiles.isdisjoint(profile_filter_norm):
            return False
        return True

    for gpo in gpos:
        gpo_name = gpo["name"]
        source_label = gpo.get("source")
        if show_sources and source_label:
            gpo_display = f"{gpo_name} ({source_label})"
        else:
            gpo_display = gpo_name
        for rule in base_rules:
            if not profile_matches(rule):
                continue
            result = apply_rule(rule, gpo)
            status = result["status"]

            if gpo_in_scope(rule, gpo):
                scope_stats[rule.id]["in_scope"] += 1
                if status == "OK":
                    scope_stats[rule.id]["ok"] += 1
                elif status == "Не ОК":
                    scope_stats[rule.id]["issues"] += 1
                else:
                    scope_stats[rule.id]["missing"] += 1

            if status == "OK":
                tracker = base_missing_tracker.setdefault(
                    rule.id,
                    {
                        "rule": rule,
                        "gpos": [],
                        "details": [],
                        "found": 0,
                    },
                )
                tracker["found"] = tracker.get("found", 0) + 1
                if include_ok:
                    entry = {
                        "rule_id": rule.id,
                        "title": rule.title,
                        "category": rule.category,
                        "severity": rule.severity,
                        "profiles": rule.profiles,
                        "origin": rule.origin,
                        "gpo": gpo_display,
                        "report": source_label,
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
                        "details": [],
                        "found": 0,
                    },
                )
                if gpo_in_scope(rule, gpo):
                    tracker["gpos"].append(gpo_display)
                if include_missing and missing_details:
                    if gpo_in_scope(rule, gpo):
                        detail_entry = {
                            "rule_id": rule.id,
                            "title": rule.title,
                            "category": rule.category,
                            "severity": rule.severity,
                            "profiles": rule.profiles,
                            "origin": rule.origin,
                            "gpo": gpo_display,
                            "report": source_label,
                            "found": result["found"],
                            "expected_display": rule.desired_display,
                            "status": status,
                            "recommendation": rule.recommendation,
                            "fix": rule.fix,
                            "notes": result["note"] or rule.notes,
                        }
                        tracker.setdefault("details", []).append(detail_entry)
                continue

            tracker = base_missing_tracker.setdefault(
                rule.id,
                {
                    "rule": rule,
                    "gpos": [],
                    "details": [],
                    "found": 0,
                },
            )
            tracker["found"] = tracker.get("found", 0) + 1
            entry = {
                "rule_id": rule.id,
                "title": rule.title,
                "category": rule.category,
                "severity": rule.severity,
                "profiles": rule.profiles,
                "origin": rule.origin,
                "gpo": gpo_display,
                "report": source_label,
                "found": result["found"],
                "expected_display": rule.desired_display,
                "status": status,
                "recommendation": rule.recommendation,
                "fix": rule.fix,
                "notes": rule.notes if status == "OK" else result["note"] or rule.notes,
            }
            issues.append(entry)

    # Построение агрегированного списка для базовых правил
    total_gpos = len(gpos)

    for tracker in base_missing_tracker.values():
        rule: Rule = tracker["rule"]  # type: ignore[assignment]
        gpo_list: List[str] = tracker["gpos"]  # type: ignore[assignment]
        count = len(gpo_list)
        if total_gpos == 0 or count == 0:
            continue
        sample = gpo_list[:3]
        sample_display = ", ".join(sample)
        if count > len(sample):
            sample_display = sample_display + (", …" if sample_display else "…")
        if total_gpos == 1 and gpo_list:
            gpo_display = gpo_list[0]
        elif count == total_gpos:
            gpo_display = "Все GPO"
        else:
            gpo_display = sample_display or "Несколько GPO"
        if count == total_gpos:
            summary_note = (
                f"Параметр не обнаружен ни в одном из {count} GPO"
                + (f" (например: {', '.join(sample[:3])})" if sample else "")
            )
        else:
            summary_note = (
                f"Параметр не обнаружен в {count} из {total_gpos} GPO"
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
        missing_summary_entries.append(aggregated_entry)
        missing_aggregated_count += 1
        details = tracker.get("details", [])
        if include_missing:
            if missing_details and details:
                missing.extend(details)
            elif not missing_details:
                missing.append(aggregated_entry)
        if not (include_missing and missing_details and details):
            hidden_missing_records += count

    for rule in compliance_rules:
        if not profile_matches(rule):
            continue
        found_any = False
        note_missing = "Параметр не обнаружен ни в одном GPO"
        for gpo in gpos:
            gpo_name = gpo["name"]
            source_label = gpo.get("source")
            if show_sources and source_label:
                gpo_display = f"{gpo_name} ({source_label})"
            else:
                gpo_display = gpo_name
            result = apply_rule(rule, gpo)
            if gpo_in_scope(rule, gpo):
                scope_stats[rule.id]["in_scope"] += 1
                if result["status"] == "OK":
                    scope_stats[rule.id]["ok"] += 1
                elif result["status"] == "Не ОК":
                    scope_stats[rule.id]["issues"] += 1
                else:
                    scope_stats[rule.id]["missing"] += 1
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
                "gpo": gpo_display,
                "report": source_label,
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
            else:
                issues.append(entry)
        if not found_any:
            gpo_infos = []
            for gpo in gpos:
                name = gpo["name"]
                source_label = gpo.get("source")
                if show_sources and source_label:
                    display_name = f"{name} ({source_label})"
                else:
                    display_name = name
                if gpo_in_scope(rule, gpo):
                    gpo_infos.append((display_name, source_label))
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
                "missing_examples": [info[0] for info in gpo_infos[:3]],
            }
            missing_aggregated_count += 1
            missing_summary_entries.append(comp_entry)
            if include_missing:
                if missing_details:
                    detail_entries = []
                    for gpo_display, source_label in gpo_infos:
                        detail_entries.append(
                            {
                                "rule_id": rule.id,
                                "title": rule.title,
                                "category": rule.category,
                                "severity": rule.severity,
                                "profiles": rule.profiles,
                                "origin": rule.origin,
                                "gpo": gpo_display,
                                "report": source_label,
                                "found": "",
                                "expected_display": rule.desired_display,
                                "status": "Не найдено",
                                "recommendation": rule.recommendation,
                                "fix": rule.fix,
                                "notes": rule.notes or note_missing,
                            }
                        )
                    missing.extend(detail_entries)
                else:
                    missing.append(comp_entry)
            if not (include_missing and missing_details):
                hidden_missing_records += total_gpos

    for rule in rules:
        stats = scope_stats.get(rule.id, {})
        status, note = summarize_scope_status(rule, stats)
        in_scope = stats.get("in_scope", 0)
        ok = stats.get("ok", 0)
        issues_count = stats.get("issues", 0)
        missing_count = stats.get("missing", 0)
        never_found = in_scope > 0 and ok == 0 and issues_count == 0
        conflict = ok > 0 and issues_count > 0
        scope_name = (rule.scope or "any_gpo").casefold()
        scope_missing_display: object = missing_count
        if scope_name in ("any_gpo", "dc_only", "domain_password_policy"):
            scope_missing_display = "—"
        scope_summary.append(
            {
                "rule_id": rule.id,
                "title": rule.title,
                "category": rule.category,
                "severity": rule.severity,
                "profiles": rule.profiles,
                "origin": rule.origin,
                "scope": rule.scope or "any_gpo",
                "scope_in": in_scope,
                "scope_ok": ok,
                "scope_issues": issues_count,
                "scope_missing_display": scope_missing_display,
                "never_found": "Да" if never_found else "Нет",
                "conflict": "Да" if conflict else "Нет",
                "status": status,
                "notes": note or rule.notes,
            }
        )

    return {
        "issues": issues,
        "missing": missing,
        "ok": ok_items,
        "missing_summary": missing_summary_entries,
        "missing_stats": {
            "aggregated_rules": missing_aggregated_count,
            "hidden_details": hidden_missing_records,
        },
        "scope_summary": scope_summary,
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
        print(_color_text("Правила без совпадений / частично отсутствующие (агрегировано)", COLOR_HEADER, use_color))
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


def export_html(
    path: Path,
    evaluation: Dict[str, Sequence[Dict[str, object]]],
    *,
    include_ok: bool,
    include_missing: bool,
    missing_details: bool,
    total_gpos: int,
    report_meta: Sequence[Dict[str, object]],
    view: str,
    compliance_summary: Optional[Dict[str, object]] = None,
    compliance_min_severity: Optional[str] = None,
) -> None:
    def render_table(
        title: str,
        rows: Sequence[Dict[str, object]],
        columns: Sequence[Sequence[object]],
        empty_message: str = "Нет записей.",
    ) -> str:
        if not rows:
            return (
                "<section class='block'>"
                f"<h2>{html.escape(title, quote=True)}</h2>"
                f"<p>{html.escape(empty_message, quote=True)}</p>"
                "</section>"
            )

        header_cells = []
        for column in columns:
            key = column[0]
            header = column[1]
            header_cells.append(f"<th data-key='{html.escape(str(key), quote=True)}'>{_html_escape(header, None)}</th>")

        body_rows: List[str] = []
        status_map = {
            "не ок": "status-issue",
            "не найдено": "status-missing",
            "ok": "status-ok",
        }
        for row in rows:
            severity_value = (row.get("severity") or "").casefold()
            status_value = (row.get("status") or "").casefold()
            classes: List[str] = []
            if severity_value:
                classes.append(f"severity-{severity_value}")
            if status_value in status_map:
                classes.append(status_map[status_value])
            class_attr = f" class='{' '.join(classes)}'" if classes else ""

            cells: List[str] = []
            for column in columns:
                key = column[0]
                limit = 800
                if len(column) > 2 and column[2] is not None:
                    limit = int(column[2]) or 0
                elif len(column) > 2 and column[2] is None:
                    limit = 0
                value = row.get(key, "")
                effective_limit = None if limit == 0 else limit
                cells.append(f"<td>{_html_escape(value, effective_limit)}</td>")
            body_rows.append(f"<tr{class_attr}>{''.join(cells)}</tr>")

        return (
            "<section class='block'>"
            f"<h2>{html.escape(title, quote=True)}</h2>"
            "<div class='table-wrapper'>"
            "<table>"
            f"<thead><tr>{''.join(header_cells)}</tr></thead>"
            f"<tbody>{''.join(body_rows)}</tbody>"
            "</table>"
            "</div>"
            "</section>"
        )

    issues = evaluation.get("issues", [])
    missing = evaluation.get("missing", [])
    ok_items = evaluation.get("ok", [])
    scope_summary = evaluation.get("scope_summary", []) or []
    missing_stats = evaluation.get("missing_stats", {}) or {}
    hidden_details = int(missing_stats.get("hidden_details", 0) or 0)

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    report_list = []
    for meta in report_meta:
        label = str(meta.get("path", ""))
        fmt = meta.get("format")
        enc = meta.get("encoding")
        details = []
        if fmt:
            details.append(str(fmt))
        if enc and enc != "n/a":
            details.append(str(enc))
        if details:
            label = f"{label} ({', '.join(details)})"
        report_list.append(label)

    issues_count = len(issues)
    missing_count = len(missing)
    ok_count = len(ok_items)

    css = """
body { font-family: Arial, sans-serif; margin: 24px; color: #222; }
h1 { margin-bottom: 0.5em; }
section.block { margin-bottom: 32px; }
.meta { margin: 0; padding-left: 18px; }
.meta li { margin: 4px 0; }
.table-wrapper { overflow-x: auto; }
table { border-collapse: collapse; width: 100%; margin-top: 12px; font-size: 14px; }
th, td { border: 1px solid #d0d7de; padding: 8px 10px; vertical-align: top; text-align: left; }
thead th { background: #f6f8fa; }
tbody tr:nth-child(even) { background: #fbfbfb; }
tbody tr.status-issue { background: #fff3f3; }
tbody tr.status-missing { background: #fffaf0; }
tbody tr.status-ok { background: #f2fbf2; }
.severity-critical td:first-child, .severity-high td:first-child { font-weight: bold; }
code { background: #f6f8fa; padding: 2px 4px; border-radius: 4px; }
.sources { padding-left: 18px; }
.note { color: #6e7781; }
""".strip()

    summary_items = [
        f"<li><strong>Дата формирования:</strong> {html.escape(timestamp, quote=True)}</li>",
        f"<li><strong>Количество файлов отчёта:</strong> {len(report_list)}</li>",
        f"<li><strong>Обработано GPO:</strong> {total_gpos}</li>",
        f"<li><strong>Несоответствий:</strong> {issues_count}</li>",
    ]
    if include_missing:
        summary_items.append(f"<li><strong>Записей 'Не найдено':</strong> {missing_count}</li>")
        if not missing_details:
            summary_items.append(
                "<li class='note'>Записи 'Не найдено' агрегированы по правилам. Используйте --missing-details для детализации.</li>"
            )
    if include_ok:
        summary_items.append(f"<li><strong>Соответствий (OK):</strong> {ok_count}</li>")
    if hidden_details:
        hint = "--missing-details" if include_missing else "--include-missing --missing-details"
        summary_items.append(
            f"<li class='note'>Детали для {hidden_details} сочетаний правило/GPO скрыты. Запустите скрипт с {html.escape(hint, quote=True)} для полного вывода.</li>"
        )

    sources_html = "".join(f"<li>{html.escape(item, quote=True)}</li>" for item in report_list) or "<li>—</li>"

    issues_table = ""
    if view in ("full", "both"):
        issues_table = render_table(
            "Правила с несоответствиями",
            issues,
            [
                ("severity", "Критичность", 0),
                ("status", "Статус", 0),
                ("rule_id", "Правило"),
                ("origin", "Набор правил"),
                ("category", "Категория"),
                ("title", "Название"),
                ("gpo", "GPO"),
                ("found", "Найдено", 800),
                ("expected_display", "Ожидалось", 600),
                ("recommendation", "Рекомендация", 700),
                ("fix", "Как исправить", 700),
                ("notes", "Примечание", 700),
            ],
            empty_message="Несоответствий не обнаружено.",
        )

    missing_table = ""
    if include_missing and view in ("full", "both"):
        missing_table = render_table(
            "Подробности по статусу 'Не найдено'",
            missing,
            [
                ("severity", "Критичность", 0),
                ("status", "Статус", 0),
                ("rule_id", "Правило"),
                ("origin", "Набор правил"),
                ("category", "Категория"),
                ("title", "Название"),
                ("gpo", "GPO"),
                ("expected_display", "Ожидалось", 600),
                ("recommendation", "Рекомендация", 700),
                ("fix", "Как исправить", 700),
                ("notes", "Примечание", 700),
            ],
            empty_message="Нет записей со статусом 'Не найдено'.",
        )

    ok_table = ""
    if include_ok and view in ("full", "both"):
        ok_table = render_table(
            "Совпадения (OK)",
            ok_items,
            [
                ("severity", "Критичность", 0),
                ("status", "Статус", 0),
                ("rule_id", "Правило"),
                ("origin", "Набор правил"),
                ("category", "Категория"),
                ("title", "Название"),
                ("gpo", "GPO"),
                ("found", "Найдено", 800),
                ("expected_display", "Ожидалось", 600),
                ("notes", "Примечание", 700),
            ],
            empty_message="Совпадения отсутствуют (или не были включены).",
        )

    scope_table = render_table(
        "Сводка по правилам (scope)",
        scope_summary,
        [
            ("severity", "Критичность", 0),
            ("status", "Статус", 0),
            ("rule_id", "Правило"),
            ("origin", "Набор правил"),
            ("category", "Категория"),
            ("title", "Название"),
            ("scope", "Scope"),
            ("scope_in", "GPO в scope", 0),
            ("scope_ok", "OK", 0),
            ("scope_issues", "Не ОК", 0),
            ("scope_missing_display", "Не найдено", 0),
            ("never_found", "Ни разу не найдено", 0),
            ("conflict", "Конфликт", 0),
            ("notes", "Примечание", 700),
        ],
        empty_message="Нет сводки по правилам.",
    )

    compliance_block = ""
    if compliance_summary:
        by_severity = compliance_summary.get("by_severity", {}) or {}
        rows = []
        for severity_name, data in by_severity.items():
            rows.append(
                {
                    "severity": severity_name,
                    "total": data.get("total", 0),
                    "ok": data.get("ok", 0),
                    "issues": data.get("issues", 0),
                    "missing": data.get("missing", 0),
                }
            )
        rows.sort(key=lambda item: SEVERITY_ORDER.get(str(item.get("severity", "")).casefold(), len(SEVERITY_ORDER)))
        compliance_table = render_table(
            "Комплаенс",
            rows,
            [
                ("severity", "Критичность", 0),
                ("total", "Всего проверок", 0),
                ("ok", "OK", 0),
                ("issues", "Не ОК", 0),
                ("missing", "Не найдено", 0),
            ],
            empty_message="Нет проверок комплаенса в текущем отчёте.",
        )
        score = compliance_summary.get("score")
        min_sev = compliance_min_severity or compliance_summary.get("min_severity", "")
        compliance_meta = []
        if score is not None:
            compliance_meta.append(f"<li><strong>Итоговый балл:</strong> {score}%</li>")
        if min_sev:
            compliance_meta.append(
                f"<li><strong>Минимальная критичность:</strong> {html.escape(str(min_sev), quote=True)}</li>"
            )
        compliance_block = (
            "<section class='block'>"
            "<h2>Комплаенс (дополнительные проверки)</h2>"
            f"<ul class='meta'>{''.join(compliance_meta) or '<li>—</li>'}</ul>"
            f"{compliance_table}"
            "</section>"
        )

    html_parts = [
        "<!DOCTYPE html>",
        "<html lang='ru'>",
        "<head>",
        "<meta charset='utf-8'>",
        "<title>GPO Audit Report</title>",
        f"<style>{css}</style>",
        "</head>",
        "<body>",
        "<h1>Отчёт по аудиту GPO</h1>",
        "<section class='block'>",
        "<h2>Сводка</h2>",
        f"<ul class='meta'>{''.join(summary_items)}</ul>",
        "<h3>Источники отчётов</h3>",
        f"<ul class='sources'>{sources_html}</ul>",
        "</section>",
        issues_table,
        missing_table,
        ok_table,
        scope_table,
        compliance_block,
        "<footer class='note'>Отчёт сформирован скриптом gpo_audit.py.</footer>",
        "</body>",
        "</html>",
    ]

    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(html_parts), encoding="utf-8")


def build_cli() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Сравнение настроек GPO (HTML/XML отчёты GPMC) с правилами лучших практик.",
    )
    parser.add_argument(
        "--report",
        required=True,
        nargs="+",
        help="Путь(и) к отчётам GPMC (HTML/XML, можно несколько).",
    )
    parser.add_argument("--rules", help="JSON-файл с правилами. По умолчанию gpo_rules.json рядом со скриптом.")
    parser.add_argument("--csv", help="Путь для сохранения CSV-отчёта.")
    parser.add_argument("--html", help="Путь для сохранения HTML-отчёта.")
    parser.add_argument(
        "--encoding",
        help="Принудительная кодировка HTML-отчётов (например: utf-16, utf-8, cp1251). Для XML игнорируется.",
    )
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
    parser.add_argument(
        "--view",
        choices=("full", "compliance", "both"),
        default="both",
        help="Режим вывода: full (матрица rule×GPO), compliance (только сводка по правилам), both (по умолчанию).",
    )
    return parser


def main() -> int:
    parser = build_cli()
    args = parser.parse_args()

    report_paths = [Path(p) for p in args.report]
    for report_path in report_paths:
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

    gpos: List[Dict[str, object]] = []
    report_meta: List[Dict[str, object]] = []
    for report_path in report_paths:
        try:
            parsed, meta = parse_report(report_path, forced_encoding=args.encoding)
        except Exception as exc:  # pragma: no cover
            parser.error(f"Не удалось разобрать отчёт {report_path}: {exc}")
        report_meta.append(meta)
        for item in parsed:
            entry = dict(item)
            entry.setdefault("source", report_path.name)
            gpos.append(entry)

    evaluation = evaluate_rules(
        gpos,
        rules,
        profiles_filter=args.profiles,
        include_ok=args.include_ok,
        include_missing=args.include_missing,
        missing_details=args.missing_details,
        show_sources=len(report_paths) > 1,
    )

    total_gpos = len(gpos)
    print(f"Обработано GPO: {total_gpos}")
    print()

    if args.view in ("full", "both"):
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
    compliance_summary: Optional[Dict[str, object]] = None
    if any(entry.get("origin") == "compliance" for entry in combined_entries):
        print()
        compliance_summary = summarize_compliance(combined_entries, args.compliance_min_severity)
        print_compliance_summary(compliance_summary, sys.stdout.isatty())

    scope_summary = evaluation.get("scope_summary", []) or []
    if scope_summary:
        status_counts = {"OK": 0, "Не ОК": 0, "Не найдено": 0}
        for entry in scope_summary:
            status = entry.get("status")
            if status in status_counts:
                status_counts[status] += 1
        print()
        scope_line = (
            "Сводка по правилам (scope): OK {ok}, Не ОК {issues}, Не найдено {missing}, Всего {total}"
        ).format(
            ok=status_counts["OK"],
            issues=status_counts["Не ОК"],
            missing=status_counts["Не найдено"],
            total=len(scope_summary),
        )
        print(_color_text(scope_line, COLOR_HEADER, sys.stdout.isatty()))

    issue_count = len(evaluation["issues"])
    if args.include_missing and args.missing_details:
        missing_rule_total = len(evaluation.get("missing", []))
    else:
        missing_rule_total = len(evaluation.get("missing_summary", [])) or len(evaluation.get("missing", []))
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

    if args.html:
        export_html(
            Path(args.html),
            evaluation,
            include_ok=args.include_ok,
            include_missing=args.include_missing,
            missing_details=args.missing_details,
            total_gpos=total_gpos,
            report_meta=report_meta,
            view=args.view,
            compliance_summary=compliance_summary,
            compliance_min_severity=args.compliance_min_severity,
        )
        print(_color_text(f"HTML-отчёт сохранён: {args.html}", COLOR_HEADER, sys.stdout.isatty()))

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
