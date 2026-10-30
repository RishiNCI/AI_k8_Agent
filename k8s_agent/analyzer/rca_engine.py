"""Root Cause Analysis (RCA) engine coordinating log evaluation and correlation."""

from collections import defaultdict
from typing import List, Optional

from k8s_agent.analyzer.correlation import CorrelationEngine
from k8s_agent.analyzer.rules import ALL_RULES, BaseRule
from k8s_agent.models.evidence import EvidenceItem
from k8s_agent.models.failure_modes import Severity
from k8s_agent.models.log_entry import LogEntry
from k8s_agent.models.report import InvestigationReport


class RCAEngine:
    """Core deterministic diagnostic engine for Kubernetes log analysis."""

    def __init__(self, rules: Optional[List[BaseRule]] = None):
        self.rules = rules or ALL_RULES
        self.correlation_engine = CorrelationEngine(self.rules)

    def analyze(self, entries: List[LogEntry], source_name: str = "kubernetes-logs") -> InvestigationReport:
        """Execute complete rule-based analysis and correlation across parsed log entries."""
        report = InvestigationReport(
            source_name=source_name,
            total_lines_analyzed=len(entries),
        )

        if not entries:
            report.executive_summary = "Provided log stream was empty. No events or errors to investigate."
            return report

        # Count errors and warnings
        error_count = sum(1 for e in entries if e.level.is_error_or_higher)
        warning_count = sum(1 for e in entries if e.level == e.level.WARN)
        report.error_count = error_count
        report.warning_count = warning_count

        # Extract Evidence with Context Windows
        raw_evidence: List[EvidenceItem] = []
        for idx, entry in enumerate(entries):
            # Extract surrounding context (up to 2 lines before and after)
            context_before_lines = [
                entries[i].raw for i in range(max(0, idx - 2), idx)
            ]
            context_after_lines = [
                entries[i].raw for i in range(idx + 1, min(len(entries), idx + 3))
            ]
            context_before = "\n".join(context_before_lines)
            context_after = "\n".join(context_after_lines)

            for rule in self.rules:
                matches = rule.evaluate(entry, context_before=context_before, context_after=context_after)
                if matches:
                    raw_evidence.extend(matches)

        # Deduplicate evidence to prevent log spam while retaining critical distinct signals
        deduped_evidence = self._deduplicate_evidence(raw_evidence)
        report.evidence = deduped_evidence

        # Correlation & Root Cause Synthesis
        primary_rc, secondary_rcs, timeline, remediations = self.correlation_engine.correlate(
            deduped_evidence,
            total_lines=len(entries),
        )

        report.primary_root_cause = primary_rc
        report.secondary_root_causes = secondary_rcs
        report.timeline = timeline
        report.remediations = remediations

        # Formulate Executive Summary
        report.executive_summary = self._generate_executive_summary(report)

        return report

    def _deduplicate_evidence(self, evidence: List[EvidenceItem]) -> List[EvidenceItem]:
        """Keep up to 3 occurrences of identical trigger patterns to avoid log spam."""
        pattern_counts = defaultdict(int)
        filtered: List[EvidenceItem] = []

        for ev in evidence:
            key = (ev.failure_category, ev.matched_pattern)
            if pattern_counts[key] < 3:
                pattern_counts[key] += 1
                filtered.append(ev)

        return filtered

    def _generate_executive_summary(self, report: InvestigationReport) -> str:
        """Formulate a concise executive summary based on findings."""
        if not report.primary_root_cause:
            if report.error_count == 0:
                return (
                    f"Investigation examined {report.total_lines_analyzed} log lines. "
                    "No critical Kubernetes failures, fatal panics, or operational anomalies were found. "
                    "Workload appears healthy."
                )
            return (
                f"Investigation examined {report.total_lines_analyzed} log lines and found {report.error_count} "
                "generic errors, but no definitive Kubernetes platform failure patterns were identified."
            )

        rc = report.primary_root_cause
        secondary_str = ""
        if report.secondary_root_causes:
            sec_names = ", ".join(f"`{s.category.value}`" for s in report.secondary_root_causes)
            secondary_str = f" This subsequently triggered secondary failures in {sec_names}."

        evidence_count = len(report.evidence)
        return (
            f"Investigation analyzed {report.total_lines_analyzed} log entries ({report.error_count} errors, "
            f"{report.warning_count} warnings) and identified **{rc.title}** as the primary root cause "
            f"with {rc.confidence_percent}% confidence.{secondary_str} "
            f"A total of {evidence_count} supporting evidence artifacts were extracted."
        )
