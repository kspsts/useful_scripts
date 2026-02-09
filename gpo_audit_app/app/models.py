from __future__ import annotations

from datetime import datetime
from sqlalchemy import DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .db import Base


class ReportRun(Base):
    __tablename__ = "report_runs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(200))
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    report_filename: Mapped[str] = mapped_column(String(400))
    ruleset_filename: Mapped[str] = mapped_column(String(400))
    total_gpos: Mapped[int] = mapped_column(Integer, default=0)
    include_ok: Mapped[int] = mapped_column(Integer, default=0)
    include_missing: Mapped[int] = mapped_column(Integer, default=0)
    missing_details: Mapped[int] = mapped_column(Integer, default=0)

    rule_results: Mapped[list[RuleResult]] = relationship(back_populates="run", cascade="all, delete-orphan")
    scope_summaries: Mapped[list[ScopeSummary]] = relationship(back_populates="run", cascade="all, delete-orphan")


class RuleResult(Base):
    __tablename__ = "rule_results"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    run_id: Mapped[int] = mapped_column(ForeignKey("report_runs.id", ondelete="CASCADE"))
    status: Mapped[str] = mapped_column(String(40))
    rule_id: Mapped[str] = mapped_column(String(200))
    title: Mapped[str] = mapped_column(String(400))
    category: Mapped[str] = mapped_column(String(200))
    severity: Mapped[str] = mapped_column(String(40))
    origin: Mapped[str] = mapped_column(String(40))
    gpo: Mapped[str] = mapped_column(String(400))
    found: Mapped[str] = mapped_column(Text)
    expected_display: Mapped[str] = mapped_column(Text)
    recommendation: Mapped[str] = mapped_column(Text)
    fix: Mapped[str] = mapped_column(Text)
    notes: Mapped[str] = mapped_column(Text)

    run: Mapped[ReportRun] = relationship(back_populates="rule_results")


class ScopeSummary(Base):
    __tablename__ = "scope_summaries"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    run_id: Mapped[int] = mapped_column(ForeignKey("report_runs.id", ondelete="CASCADE"))
    status: Mapped[str] = mapped_column(String(40))
    rule_id: Mapped[str] = mapped_column(String(200))
    title: Mapped[str] = mapped_column(String(400))
    category: Mapped[str] = mapped_column(String(200))
    severity: Mapped[str] = mapped_column(String(40))
    origin: Mapped[str] = mapped_column(String(40))
    scope: Mapped[str] = mapped_column(String(40))
    scope_in: Mapped[int] = mapped_column(Integer, default=0)
    scope_ok: Mapped[int] = mapped_column(Integer, default=0)
    scope_issues: Mapped[int] = mapped_column(Integer, default=0)
    scope_missing_display: Mapped[str] = mapped_column(String(40))
    never_found: Mapped[str] = mapped_column(String(10))
    conflict: Mapped[str] = mapped_column(String(10))
    notes: Mapped[str] = mapped_column(Text)

    run: Mapped[ReportRun] = relationship(back_populates="scope_summaries")
