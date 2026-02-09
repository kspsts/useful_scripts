from __future__ import annotations

import os
from datetime import datetime
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, File, Form, Request, UploadFile
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from .db import Base, engine, get_session
from .models import ReportRun, RuleResult, ScopeSummary
from .parser import parse_and_evaluate

APP_ROOT = Path(__file__).resolve().parent
UPLOAD_ROOT = APP_ROOT / "uploads"
UPLOAD_ROOT.mkdir(parents=True, exist_ok=True)
DEFAULT_RULES = Path(__file__).resolve().parents[2] / "best_practices.json"

app = FastAPI(title="GPO Audit")
app.mount("/static", StaticFiles(directory=APP_ROOT / "static"), name="static")
templates = Jinja2Templates(directory=str(APP_ROOT / "templates"))

Base.metadata.create_all(engine)


@app.get("/", response_class=HTMLResponse)
def index(request: Request):
    with get_session() as session:
        runs = session.query(ReportRun).order_by(ReportRun.created_at.desc()).all()
    return templates.TemplateResponse("index.html", {"request": request, "runs": runs})


@app.get("/upload", response_class=HTMLResponse)
def upload_form(request: Request):
    return templates.TemplateResponse(
        "upload.html",
        {
            "request": request,
            "default_rules": str(DEFAULT_RULES),
        },
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
        rules_path = DEFAULT_RULES

    evaluation, total_gpos = parse_and_evaluate(
        report_path,
        rules_path,
        include_ok=bool(include_ok),
        include_missing=bool(include_missing),
        missing_details=bool(missing_details),
    )

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

        for entry in evaluation.get("issues", []):
            session.add(RuleResult(run_id=run.id, **_row_to_result(entry)))
        for entry in evaluation.get("missing", []):
            session.add(RuleResult(run_id=run.id, **_row_to_result(entry)))
        for entry in evaluation.get("ok", []):
            session.add(RuleResult(run_id=run.id, **_row_to_result(entry)))

        for entry in evaluation.get("scope_summary", []):
            session.add(ScopeSummary(run_id=run.id, **_row_to_scope(entry)))

    return RedirectResponse(url=f"/runs/{run.id}", status_code=303)


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
):
    with get_session() as session:
        run = session.get(ReportRun, run_id)
        if run is None:
            return HTMLResponse("Not found", status_code=404)

        query = session.query(RuleResult).filter(RuleResult.run_id == run_id)
        if status:
            query = query.filter(RuleResult.status == status)
        if severity:
            query = query.filter(RuleResult.severity == severity)
        if category:
            query = query.filter(RuleResult.category == category)
        if rule_id:
            query = query.filter(RuleResult.rule_id == rule_id)
        if gpo:
            query = query.filter(RuleResult.gpo.ilike(f"%{gpo}%"))

        results = query.order_by(RuleResult.status, RuleResult.severity, RuleResult.rule_id).all()
        scope = session.query(ScopeSummary).filter(ScopeSummary.run_id == run_id).all()

    return templates.TemplateResponse(
        "run.html",
        {
            "request": request,
            "run": run,
            "results": results,
            "scope": scope,
            "filters": {
                "status": status or "",
                "severity": severity or "",
                "category": category or "",
                "rule_id": rule_id or "",
                "gpo": gpo or "",
            },
        },
    )


@app.get("/compare", response_class=HTMLResponse)
def compare_runs(request: Request, run_a: int, run_b: int):
    with get_session() as session:
        a = session.get(ReportRun, run_a)
        b = session.get(ReportRun, run_b)
        if a is None or b is None:
            return HTMLResponse("Not found", status_code=404)

        a_scope = {row.rule_id: row for row in session.query(ScopeSummary).filter(ScopeSummary.run_id == run_a).all()}
        b_scope = {row.rule_id: row for row in session.query(ScopeSummary).filter(ScopeSummary.run_id == run_b).all()}

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
