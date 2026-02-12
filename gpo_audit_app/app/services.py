from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from sqlalchemy import and_, case, func, or_, select
from sqlalchemy.orm import Session

from .models import RuleResult, ScopeSummary


@dataclass
class ResultFilters:
    status: Optional[str] = None
    severity: Optional[str] = None
    category: Optional[str] = None
    rule_id: Optional[str] = None
    gpo: Optional[str] = None
    only_issues: bool = False
    only_missing: bool = False
    critical_only: bool = False
    with_fix: bool = False


def query_results(
    session: Session,
    run_id: int,
    filters: ResultFilters,
    page: int = 1,
    page_size: int = 100,
) -> tuple[list[RuleResult], int]:
    conditions = [RuleResult.run_id == run_id]
    if filters.status:
        conditions.append(RuleResult.status == filters.status)
    if filters.severity:
        conditions.append(RuleResult.severity == filters.severity)
    if filters.category:
        conditions.append(RuleResult.category == filters.category)
    if filters.rule_id:
        conditions.append(RuleResult.rule_id == filters.rule_id)
    if filters.gpo:
        conditions.append(RuleResult.gpo.ilike(f"%{filters.gpo}%"))
    if filters.only_issues:
        conditions.append(RuleResult.status == "Не ОК")
    if filters.only_missing:
        conditions.append(RuleResult.status == "Не найдено")
    if filters.critical_only:
        conditions.append(RuleResult.severity.in_(["Critical", "High", "critical", "high"]))
    if filters.with_fix:
        conditions.append(
            or_(
                and_(RuleResult.fix.is_not(None), RuleResult.fix != ""),
                and_(RuleResult.recommendation.is_not(None), RuleResult.recommendation != ""),
            )
        )

    status_order = case(
        (RuleResult.status == "Не ОК", 0),
        (RuleResult.status == "Не найдено", 1),
        (RuleResult.status == "OK", 2),
        else_=99,
    )
    severity_order = case(
        (RuleResult.severity.in_(["Critical", "critical"]), 0),
        (RuleResult.severity.in_(["High", "high"]), 1),
        (RuleResult.severity.in_(["Medium", "medium"]), 2),
        (RuleResult.severity.in_(["Low", "low"]), 3),
        (RuleResult.severity.in_(["Info", "info"]), 4),
        else_=99,
    )

    total = session.scalar(select(func.count()).select_from(RuleResult).where(*conditions)) or 0
    safe_page = max(1, page)
    safe_size = max(10, min(page_size, 500))
    offset = (safe_page - 1) * safe_size
    rows = (
        session.query(RuleResult)
        .filter(*conditions)
        .order_by(status_order, severity_order, RuleResult.rule_id, RuleResult.gpo)
        .offset(offset)
        .limit(safe_size)
        .all()
    )
    return rows, int(total)


def query_scope_summary(session: Session, run_id: int) -> list[ScopeSummary]:
    return (
        session.query(ScopeSummary)
        .filter(ScopeSummary.run_id == run_id)
        .order_by(ScopeSummary.status, ScopeSummary.severity, ScopeSummary.rule_id)
        .all()
    )
