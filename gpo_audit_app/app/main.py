from __future__ import annotations

import csv
import io
from datetime import datetime
from pathlib import Path
from typing import Optional
from collections import Counter

from fastapi import FastAPI, File, Form, Request, UploadFile
from fastapi.responses import HTMLResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from sqlalchemy.exc import OperationalError

from .config import DEFAULT_RULES_PATH
from .db import Base, engine, get_session
from .models import ReportRun, RuleResult, ScopeSummary
from .parser import parse_and_evaluate
from .services import ResultFilters, query_results, query_scope_summary

APP_ROOT = Path(__file__).resolve().parent
UPLOAD_ROOT = APP_ROOT / "uploads"
UPLOAD_ROOT.mkdir(parents=True, exist_ok=True)

app = FastAPI(title="GPO Audit")
app.mount("/static", StaticFiles(directory=APP_ROOT / "static"), name="static")
templates = Jinja2Templates(directory=str(APP_ROOT / "templates"))


@app.on_event("startup")
def _init_db() -> None:
    try:
        Base.metadata.create_all(engine)
    except Exception as exc:
        print(f"[WARN] DB init failed: {exc}")


@app.get("/", response_class=HTMLResponse)
def index(request: Request, focus_run_id: Optional[int] = None):
    try:
        with get_session() as session:
            runs = session.query(ReportRun).order_by(ReportRun.created_at.desc()).all()
            dashboard = None
            focus_run = None
            if runs:
                if focus_run_id:
                    focus_run = session.get(ReportRun, focus_run_id)
                if focus_run is None:
                    focus_run = runs[0]
                dashboard = _build_home_dashboard(session, focus_run.id)
    except OperationalError as exc:
        return _db_error_page(request, exc)
    return templates.TemplateResponse(
        "index.html",
        {
            "request": request,
            "runs": runs,
            "active_tab": "runs",
            "focus_run": focus_run,
            "dashboard": dashboard,
        },
    )


@app.get("/upload", response_class=HTMLResponse)
def upload_form(request: Request):
    return templates.TemplateResponse(
        "upload.html",
        {
            "request": request,
            "default_rules": DEFAULT_RULES_PATH.name,
            "active_tab": "upload",
        },
    )


@app.get("/help", response_class=HTMLResponse)
def help_page(request: Request):
    return templates.TemplateResponse(
        "help.html",
        {"request": request, "active_tab": "help"},
    )


@app.post("/upload")
def upload_report(
    request: Request,
    report_file: UploadFile = File(...),
    rules_file: Optional[UploadFile] = File(None),
    name: str = Form(""),
    include_ok: Optional[bool] = Form(False),
    include_missing: Optional[bool] = Form(False),
    missing_details: Optional[bool] = Form(False),
):
    run_name = name.strip() or f"Run {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')}"

    run_dir = UPLOAD_ROOT / datetime.utcnow().strftime("%Y%m%d%H%M%S%f")
    run_dir.mkdir(parents=True, exist_ok=True)

    report_path = run_dir / report_file.filename
    report_path.write_bytes(report_file.file.read())

    if rules_file is not None:
        rules_path = run_dir / rules_file.filename
        rules_path.write_bytes(rules_file.file.read())
    else:
        rules_path = DEFAULT_RULES_PATH

    evaluation, total_gpos = parse_and_evaluate(
        report_path,
        rules_path,
        include_ok=bool(include_ok),
        include_missing=bool(include_missing),
        missing_details=bool(missing_details),
    )

    try:
        with get_session() as session:
            run = ReportRun(
                name=run_name,
                report_filename=str(report_path),
                ruleset_filename=str(rules_path),
                total_gpos=total_gpos,
                include_ok=int(bool(include_ok)),
                include_missing=int(bool(include_missing)),
                missing_details=int(bool(missing_details)),
            )
            session.add(run)
            session.flush()
            run_id = run.id

            for entry in evaluation.get("issues", []):
                session.add(RuleResult(run_id=run.id, **_row_to_result(entry)))
            for entry in evaluation.get("missing", []):
                session.add(RuleResult(run_id=run.id, **_row_to_result(entry)))
            for entry in evaluation.get("ok", []):
                session.add(RuleResult(run_id=run.id, **_row_to_result(entry)))

            for entry in evaluation.get("scope_summary", []):
                session.add(ScopeSummary(run_id=run.id, **_row_to_scope(entry)))
    except OperationalError as exc:
        return _db_error_page(request, exc)

    return RedirectResponse(url=f"/runs/{run_id}", status_code=303)


def _row_to_result(row: dict) -> dict:
    return {
        "status": row.get("status", ""),
        "rule_id": row.get("rule_id", ""),
        "title": row.get("title", ""),
        "category": row.get("category", ""),
        "severity": row.get("severity", ""),
        "origin": row.get("origin", ""),
        "gpo": row.get("gpo", ""),
        "found": str(row.get("found", "")),
        "expected_display": str(row.get("expected_display", "")),
        "recommendation": str(row.get("recommendation", "")),
        "fix": str(row.get("fix", "")),
        "notes": str(row.get("notes", "")),
    }


def _row_to_scope(row: dict) -> dict:
    return {
        "status": row.get("status", ""),
        "rule_id": row.get("rule_id", ""),
        "title": row.get("title", ""),
        "category": row.get("category", ""),
        "severity": row.get("severity", ""),
        "origin": row.get("origin", ""),
        "scope": row.get("scope", ""),
        "scope_in": int(row.get("scope_in", 0) or 0),
        "scope_ok": int(row.get("scope_ok", 0) or 0),
        "scope_issues": int(row.get("scope_issues", 0) or 0),
        "scope_missing_display": str(row.get("scope_missing_display", "")),
        "never_found": str(row.get("never_found", "")),
        "conflict": str(row.get("conflict", "")),
        "notes": str(row.get("notes", "")),
    }


@app.get("/runs/{run_id}", response_class=HTMLResponse)
def view_run(
    request: Request,
    run_id: int,
    status: Optional[str] = None,
    severity: Optional[str] = None,
    category: Optional[str] = None,
    rule_id: Optional[str] = None,
    gpo: Optional[str] = None,
    only_issues: Optional[int] = 0,
    only_missing: Optional[int] = 0,
    critical_only: Optional[int] = 0,
    with_fix: Optional[int] = 0,
    page: Optional[int] = 1,
    page_size: Optional[int] = 100,
):
    try:
        with get_session() as session:
            run = session.get(ReportRun, run_id)
            if run is None:
                return HTMLResponse("Not found", status_code=404)

            filters_obj = ResultFilters(
                status=status,
                severity=severity,
                category=category,
                rule_id=rule_id,
                gpo=gpo,
                only_issues=bool(only_issues),
                only_missing=bool(only_missing),
                critical_only=bool(critical_only),
                with_fix=bool(with_fix),
            )
            results, total_filtered = query_results(
                session,
                run_id,
                filters_obj,
                page=int(page or 1),
                page_size=int(page_size or 100),
            )
            scope = query_scope_summary(session, run_id)
    except OperationalError as exc:
        return _db_error_page(request, exc)

    current_page = max(1, int(page or 1))
    current_size = max(10, min(int(page_size or 100), 500))
    page_count = max(1, (total_filtered + current_size - 1) // current_size)

    return templates.TemplateResponse(
        "run.html",
        {
            "request": request,
            "run": run,
            "results": results,
            "scope": scope,
            "summary": _build_summary(results, scope, total_filtered=total_filtered),
            "filters": {
                "status": status or "",
                "severity": severity or "",
                "category": category or "",
                "rule_id": rule_id or "",
                "gpo": gpo or "",
                "only_issues": int(bool(only_issues)),
                "only_missing": int(bool(only_missing)),
                "critical_only": int(bool(critical_only)),
                "with_fix": int(bool(with_fix)),
                "page_size": current_size,
            },
            "pagination": {
                "page": current_page,
                "page_size": current_size,
                "total_filtered": total_filtered,
                "page_count": page_count,
                "has_prev": current_page > 1,
                "has_next": current_page < page_count,
                "prev_page": max(1, current_page - 1),
                "next_page": min(page_count, current_page + 1),
            },
        },
    )


@app.get("/runs/{run_id}/export")
def export_run(
    run_id: int,
    kind: str = "results",
    status: Optional[str] = None,
    severity: Optional[str] = None,
    category: Optional[str] = None,
    rule_id: Optional[str] = None,
    gpo: Optional[str] = None,
    only_issues: Optional[int] = 0,
    only_missing: Optional[int] = 0,
    critical_only: Optional[int] = 0,
    with_fix: Optional[int] = 0,
):
    try:
        with get_session() as session:
            run = session.get(ReportRun, run_id)
            if run is None:
                return HTMLResponse("Not found", status_code=404)

            output = io.StringIO()
            writer = csv.writer(output)

            if kind == "scope":
                rows = session.query(ScopeSummary).filter(ScopeSummary.run_id == run_id).all()
                writer.writerow(
                    [
                        "status",
                        "rule_id",
                        "title",
                        "severity",
                        "category",
                        "scope",
                        "scope_in",
                        "scope_ok",
                        "scope_issues",
                        "scope_missing",
                        "never_found",
                        "conflict",
                        "notes",
                    ]
                )
                for row in rows:
                    writer.writerow(
                        [
                            row.status,
                            row.rule_id,
                            row.title,
                            row.severity,
                            row.category,
                            row.scope,
                            row.scope_in,
                            row.scope_ok,
                            row.scope_issues,
                            row.scope_missing_display,
                            row.never_found,
                            row.conflict,
                            row.notes,
                        ]
                    )
                filename = f"run_{run_id}_scope.csv"
            else:
                filters_obj = ResultFilters(
                    status=status,
                    severity=severity,
                    category=category,
                    rule_id=rule_id,
                    gpo=gpo,
                    only_issues=bool(only_issues),
                    only_missing=bool(only_missing),
                    critical_only=bool(critical_only),
                    with_fix=bool(with_fix),
                )
                rows, _ = query_results(
                    session,
                    run_id,
                    filters_obj,
                    page=1,
                    page_size=50000,
                )
                writer.writerow(
                    [
                        "status",
                        "rule_id",
                        "title",
                        "severity",
                        "category",
                        "gpo",
                        "found",
                        "expected",
                        "action",
                        "notes",
                    ]
                )
                for row in rows:
                    writer.writerow(
                        [
                            _status_human(row.status),
                            row.rule_id,
                            row.title,
                            row.severity,
                            row.category,
                            row.gpo,
                            row.found,
                            row.expected_display,
                            row.fix or row.recommendation or "",
                            row.notes,
                        ]
                    )
                filename = f"run_{run_id}_results.csv"

            return Response(
                content=output.getvalue(),
                media_type="text/csv; charset=utf-8",
                headers={"Content-Disposition": f'attachment; filename="{filename}"'},
            )
    except OperationalError:
        return HTMLResponse("Database error", status_code=500)


@app.get("/runs/{run_id}/export/pdf", response_class=HTMLResponse)
def export_run_pdf(
    request: Request,
    run_id: int,
    kind: str = "results",
    status: Optional[str] = None,
    severity: Optional[str] = None,
    category: Optional[str] = None,
    rule_id: Optional[str] = None,
    gpo: Optional[str] = None,
    only_issues: Optional[int] = 0,
    only_missing: Optional[int] = 0,
    critical_only: Optional[int] = 0,
    with_fix: Optional[int] = 0,
):
    try:
        with get_session() as session:
            run = session.get(ReportRun, run_id)
            if run is None:
                return HTMLResponse("Not found", status_code=404)

            if kind == "scope":
                scope_rows = session.query(ScopeSummary).filter(ScopeSummary.run_id == run_id).all()
                return templates.TemplateResponse(
                    "export_pdf.html",
                    {
                        "request": request,
                        "kind": "scope",
                        "run": run,
                        "generated_at": datetime.utcnow(),
                        "scope_rows": scope_rows,
                    },
                )

            filters_obj = ResultFilters(
                status=status,
                severity=severity,
                category=category,
                rule_id=rule_id,
                gpo=gpo,
                only_issues=bool(only_issues),
                only_missing=bool(only_missing),
                critical_only=bool(critical_only),
                with_fix=bool(with_fix),
            )
            result_rows, _ = query_results(
                session,
                run_id,
                filters_obj,
                page=1,
                page_size=50000,
            )
            return templates.TemplateResponse(
                "export_pdf.html",
                {
                    "request": request,
                    "kind": "results",
                    "run": run,
                    "generated_at": datetime.utcnow(),
                    "result_rows": result_rows,
                },
            )
    except OperationalError as exc:
        return _db_error_page(request, exc)


@app.get("/compare", response_class=HTMLResponse)
def compare_runs(request: Request, run_a: int, run_b: int):
    try:
        with get_session() as session:
            a = session.get(ReportRun, run_a)
            b = session.get(ReportRun, run_b)
            if a is None or b is None:
                return HTMLResponse("Not found", status_code=404)

            a_scope = {row.rule_id: row for row in session.query(ScopeSummary).filter(ScopeSummary.run_id == run_a).all()}
            b_scope = {row.rule_id: row for row in session.query(ScopeSummary).filter(ScopeSummary.run_id == run_b).all()}
    except OperationalError as exc:
        return _db_error_page(request, exc)

    changes = []
    all_ids = sorted(set(a_scope) | set(b_scope))
    for rid in all_ids:
        ra = a_scope.get(rid)
        rb = b_scope.get(rid)
        if not ra or not rb:
            changes.append({
                "rule_id": rid,
                "from": ra.status if ra else "—",
                "to": rb.status if rb else "—",
                "title": rb.title if rb else (ra.title if ra else ""),
                "severity": rb.severity if rb else (ra.severity if ra else ""),
                "category": rb.category if rb else (ra.category if ra else ""),
            })
            continue
        if ra.status != rb.status:
            changes.append({
                "rule_id": rid,
                "from": ra.status,
                "to": rb.status,
                "title": rb.title,
                "severity": rb.severity,
                "category": rb.category,
            })

    return templates.TemplateResponse(
        "compare.html",
        {
            "request": request,
            "run_a": a,
            "run_b": b,
            "changes": changes,
        },
    )


def _db_error_page(request: Request, exc: Exception) -> HTMLResponse:
    message = (
        "База данных недоступна. Проверьте, что Postgres запущен и переменная DATABASE_URL настроена."
    )
    details = str(exc)
    return templates.TemplateResponse(
        "db_error.html",
        {"request": request, "message": message, "details": details},
        status_code=500,
    )


def _build_home_dashboard(session, run_id: int) -> dict:
    scope_rows = session.query(ScopeSummary).filter(ScopeSummary.run_id == run_id).all()
    status_counts = Counter(row.status for row in scope_rows)
    total_rules = len(scope_rows)

    problem_scope_rows = [
        row for row in scope_rows if row.status in ("Не ОК", "Не найдено", "Конфликт")
    ]
    severity_counts = Counter(
        _normalize_severity(row.severity) for row in problem_scope_rows
    )
    total_problems = len(problem_scope_rows)

    severity_order = ["Critical", "High", "Medium", "Low", "Info", "Unknown"]
    severity_chart = []
    for severity in severity_order:
        count = severity_counts.get(severity, 0)
        if not count:
            continue
        severity_chart.append(
            {
                "label": severity,
                "count": count,
                "pct": round((count / total_problems) * 100, 1) if total_problems else 0.0,
            }
        )

    status_labels = [
        ("Не ОК", "Неверно", "bad"),
        ("Не найдено", "Не задано", "warn"),
        ("Конфликт", "Конфликт", "bad"),
        ("OK", "Соответствует", "ok"),
    ]
    status_chart = []
    for key, label, tone in status_labels:
        count = status_counts.get(key, 0)
        status_chart.append(
            {
                "key": key,
                "label": label,
                "count": count,
                "tone": tone,
                "pct": round((count / total_rules) * 100, 1) if total_rules else 0.0,
            }
        )

    detail_rows = (
        session.query(RuleResult)
        .filter(
            RuleResult.run_id == run_id,
            RuleResult.status.in_(["Не ОК", "Не найдено"]),
        )
        .order_by(RuleResult.rule_id, RuleResult.gpo)
        .all()
    )
    details_by_rule: dict[str, dict] = {}
    for row in detail_rows:
        details = details_by_rule.setdefault(
            row.rule_id,
            {
                "gpos": [],
                "found_values": [],
                "expected_values": [],
                "actions": [],
                "notes": [],
            },
        )
        _append_unique(details["gpos"], row.gpo, limit=8)
        _append_unique(details["found_values"], row.found, limit=4)
        _append_unique(details["expected_values"], row.expected_display, limit=3)
        _append_unique(details["actions"], row.fix or row.recommendation, limit=2)
        _append_unique(details["notes"], row.notes, limit=2)

    action_items = []
    sorted_problem_rows = sorted(
        problem_scope_rows,
        key=lambda row: (
            _severity_rank(row.severity),
            0 if row.status == "Не ОК" else 1,
            row.rule_id or "",
        ),
    )
    for row in sorted_problem_rows:
        details = details_by_rule.get(row.rule_id, {})
        gpos = details.get("gpos", [])
        found_values = details.get("found_values", [])
        expected_values = details.get("expected_values", [])
        actions = details.get("actions", [])
        notes = details.get("notes", [])
        gpo_display = ", ".join(gpos[:3]) if gpos else "В scope не найдено"
        if len(gpos) > 3:
            gpo_display += f" (+{len(gpos) - 3})"
        action_items.append(
            {
                "priority": _priority_label(row.severity, row.status),
                "status": _status_human(row.status),
                "severity": _normalize_severity(row.severity),
                "rule_id": row.rule_id,
                "title": row.title,
                "gpo": gpo_display,
                "found": " | ".join(found_values[:2]) if found_values else "Не задано",
                "expected": " | ".join(expected_values[:2]) if expected_values else "См. baseline",
                "action": (actions[0] if actions else "") or (notes[0] if notes else "Проверьте базовый baseline для этого правила."),
            }
        )

    return {
        "total_rules": total_rules,
        "status_counts": {
            "ok": status_counts.get("OK", 0),
            "issue": status_counts.get("Не ОК", 0),
            "missing": status_counts.get("Не найдено", 0),
            "conflict": status_counts.get("Конфликт", 0),
        },
        "total_problems": total_problems,
        "severity_chart": severity_chart,
        "status_chart": status_chart,
        "action_items": action_items[:30],
        "more_actions": max(0, len(action_items) - 30),
    }


def _append_unique(items: list[str], value: Optional[str], limit: int = 5) -> None:
    text = (value or "").strip()
    if not text:
        return
    if text in items:
        return
    if len(items) >= limit:
        return
    items.append(text)


def _normalize_severity(severity: Optional[str]) -> str:
    sev = (severity or "").strip().lower()
    if sev.startswith("crit"):
        return "Critical"
    if sev == "high":
        return "High"
    if sev == "medium":
        return "Medium"
    if sev == "low":
        return "Low"
    if sev == "info":
        return "Info"
    return "Unknown"


def _severity_rank(severity: Optional[str]) -> int:
    sev = _normalize_severity(severity)
    order = {
        "Critical": 0,
        "High": 1,
        "Medium": 2,
        "Low": 3,
        "Info": 4,
        "Unknown": 5,
    }
    return order.get(sev, 5)


def _priority_label(severity: Optional[str], status: str) -> str:
    rank = _severity_rank(severity)
    if status == "Не ОК" and rank <= 1:
        return "Срочно"
    if rank <= 2:
        return "Высокий"
    return "Плановый"


def _build_summary(results: list[RuleResult], scope: list[ScopeSummary], total_filtered: int = 0) -> dict:
    result_status = Counter(r.status for r in results)
    scope_status = Counter(s.status for s in scope)
    severities = Counter(r.severity for r in results)
    critical_missing = 0
    optional_missing = 0
    for s in scope:
        if s.status != "Не найдено":
            continue
        sev = (s.severity or "").lower()
        if sev in ("critical", "high") or sev.startswith("crit"):
            critical_missing += 1
        elif sev in ("low", "info"):
            optional_missing += 1
    return {
        "result_status": result_status,
        "scope_status": scope_status,
        "severities": severities,
        "result_total": len(results),
        "total_filtered": total_filtered,
        "scope_total": len(scope),
        "critical_missing": critical_missing,
        "optional_missing": optional_missing,
    }


def _status_human(status: str) -> str:
    if status == "OK":
        return "Соответствует"
    if status == "Не ОК":
        return "Неверно"
    if status == "Не найдено":
        return "Не задано"
    return status
