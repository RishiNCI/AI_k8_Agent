"""Investigation report models and serialization."""

from datetime import datetime, timezone
import json
import uuid
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field

from k8s_agent.models.evidence import EvidenceItem
from k8s_agent.models.failure_modes import FailureCategory, Severity


class TimelineEvent(BaseModel):
    timestamp: Optional[datetime] = None
    phase: str = "Investigation"
    description: str
    severity: Severity = Severity.INFO
    evidence_lines: List[int] = Field(default_factory=list)
    source_component: Optional[str] = None

    @property
    def formatted_timestamp(self) -> str:
        return self.timestamp.isoformat() if self.timestamp else "Unknown Time"


class RootCause(BaseModel):
    category: FailureCategory
    severity: Severity = Severity.CRITICAL
    title: str
    summary: str
    confidence_score: float = Field(default=0.85, ge=0.0, le=1.0)
    is_primary: bool = True
    contributing_factors: List[str] = Field(default_factory=list)
    impact: str = ""

    @property
    def confidence_percent(self) -> int:
        return int(self.confidence_score * 100)


class RemediationAction(BaseModel):
    phase: str  # "Immediate Mitigation", "Diagnostic Verification", "Long-Term Prevention"
    title: str
    description: str
    kubectl_command: Optional[str] = None


class InvestigationReport(BaseModel):
    incident_id: str = Field(default_factory=lambda: f"INC-{uuid.uuid4().hex[:8].upper()}")
    analyzed_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    source_name: str = "kubernetes-logs"
    total_lines_analyzed: int = 0
    error_count: int = 0
    warning_count: int = 0
    primary_root_cause: Optional[RootCause] = None
    secondary_root_causes: List[RootCause] = Field(default_factory=list)
    timeline: List[TimelineEvent] = Field(default_factory=list)
    evidence: List[EvidenceItem] = Field(default_factory=list)
    remediations: List[RemediationAction] = Field(default_factory=list)
    executive_summary: str = ""
    llm_enhanced: bool = False
    llm_insights: Optional[str] = None

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.model_dump(mode="json"), indent=indent, default=str)

    def to_markdown(self) -> str:
        """Render a comprehensive GitHub-flavored Markdown report."""
        lines = []
        lines.append(f"# 🛡️ Kubernetes Investigation Report: `{self.incident_id}`")
        lines.append(f"**Generated:** {self.analyzed_at.strftime('%Y-%m-%d %H:%M:%S UTC')}  ")
        lines.append(f"**Target:** `{self.source_name}`  ")
        lines.append(
            f"**Log Volume:** {self.total_lines_analyzed} lines | "
            f"🚨 **Errors:** {self.error_count} | ⚠️ **Warnings:** {self.warning_count}"
        )
        lines.append("")

        # Executive Summary
        lines.append("## 📌 Executive Summary")
        lines.append(self.executive_summary)
        lines.append("")

        # Primary Root Cause
        if self.primary_root_cause:
            rc = self.primary_root_cause
            lines.append("## 🎯 Root Cause Analysis")
            badge = f"**[{rc.severity.value}]**"
            lines.append(f"### {badge} {rc.title} ({rc.confidence_percent}% Confidence)")
            lines.append(f"**Category:** `{rc.category.value}`")
            lines.append("")
            lines.append(f"**Description:**  \n{rc.summary}")
            lines.append("")
            if rc.impact:
                lines.append(f"**Impact:**  \n{rc.impact}")
                lines.append("")
            if rc.contributing_factors:
                lines.append("**Contributing Factors:**")
                for f in rc.contributing_factors:
                    lines.append(f"- {f}")
                lines.append("")

        # Secondary / Cascading Failures
        if self.secondary_root_causes:
            lines.append("### 🔗 Cascading / Secondary Failures")
            for src in self.secondary_root_causes:
                lines.append(f"- **{src.title}** (`{src.category.value}`) — {src.summary}")
            lines.append("")

        # AI Insights if LLM was used
        if self.llm_insights:
            lines.append("## 🤖 Agentic AI Synthesis")
            lines.append(self.llm_insights)
            lines.append("")

        # Chronological Incident Timeline
        if self.timeline:
            lines.append("## ⏱️ Chronological Incident Timeline")
            lines.append("| Timestamp | Phase | Event Description | Lines |")
            lines.append("|---|---|---|---|")
            for t in self.timeline:
                ts = t.formatted_timestamp
                ev_lines = ", ".join(f"L{l}" for l in t.evidence_lines) if t.evidence_lines else "—"
                lines.append(f"| `{ts}` | **{t.phase}** | {t.description} | {ev_lines} |")
            lines.append("")

        # Supporting Evidence
        lines.append("## 🔍 Supporting Evidence")
        if not self.evidence:
            lines.append("_No definitive failure indicators or anomalies detected in the provided log stream._")
        else:
            lines.append(f"Found **{len(self.evidence)} key evidence items**:")
            lines.append("")
            for idx, ev in enumerate(self.evidence, 1):
                ts = ev.formatted_timestamp()
                smoking = " 💥 *Smoking Gun Evidence*" if ev.is_smoking_gun else ""
                lines.append(
                    f"#### Evidence #{idx}: Line {ev.line_number} [{ev.failure_category.value}]{smoking}"
                )
                lines.append(f"- **Timestamp:** `{ts}`")
                lines.append(f"- **Trigger Pattern:** `{ev.matched_pattern}`")
                lines.append(f"- **Analysis:** {ev.explanation}")
                lines.append("```log")
                if ev.context_before:
                    lines.append(f"# [Context before]\n{ev.context_before}")
                lines.append(f">>> {ev.raw_excerpt}")
                if ev.context_after:
                    lines.append(f"# [Context after]\n{ev.context_after}")
                lines.append("```")
                lines.append("")

        # Actionable Remediation Plan
        lines.append("## 🛠️ Actionable Remediation Plan")
        if not self.remediations:
            lines.append("No immediate remediation steps suggested.")
        else:
            current_phase = ""
            for rem in self.remediations:
                if rem.phase != current_phase:
                    current_phase = rem.phase
                    lines.append(f"### {current_phase}")
                lines.append(f"**{rem.title}**")
                lines.append(f"{rem.description}")
                if rem.kubectl_command:
                    lines.append("```bash")
                    lines.append(rem.kubectl_command)
                    lines.append("```")
                lines.append("")

        lines.append("---")
        lines.append(
            "_Generated by Kubernetes Investigation Agent (AI-K8-Agent)._"
        )
        return "\n".join(lines)
