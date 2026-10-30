"""Base rule class for Kubernetes log pattern analysis."""

from abc import ABC, abstractmethod
import re
from typing import List, Optional, Pattern

from k8s_agent.models.evidence import EvidenceItem
from k8s_agent.models.failure_modes import FailureCategory, Severity
from k8s_agent.models.log_entry import LogEntry
from k8s_agent.models.report import RemediationAction, RootCause


class PatternMatcher:
    """Helper to associate regex patterns with descriptions, severities, and weights."""

    def __init__(
        self,
        pattern: str,
        explanation: str,
        severity: Severity = Severity.HIGH,
        weight: float = 0.8,
        is_smoking_gun: bool = False,
        case_sensitive: bool = False,
    ):
        flags = 0 if case_sensitive else re.IGNORECASE
        self.compiled: Pattern = re.compile(pattern, flags)
        self.pattern_str = pattern
        self.explanation = explanation
        self.severity = severity
        self.weight = weight
        self.is_smoking_gun = is_smoking_gun

    def matches(self, text: str) -> bool:
        return bool(self.compiled.search(text))


class BaseRule(ABC):
    """Abstract base class for all failure category detection rules."""

    category: FailureCategory
    matchers: List[PatternMatcher] = []

    def evaluate(
        self,
        entry: LogEntry,
        context_before: str = "",
        context_after: str = "",
    ) -> List[EvidenceItem]:
        """Inspect a log entry against defined patterns and return evidence items."""
        found_evidence: List[EvidenceItem] = []
        text_to_search = entry.raw
        if entry.stack_trace:
            text_to_search = entry.stack_trace

        for matcher in self.matchers:
            if matcher.matches(text_to_search):
                evidence = EvidenceItem(
                    id=f"{self.category.name}-{entry.line_number}",
                    line_number=entry.line_number,
                    timestamp=entry.timestamp,
                    raw_excerpt=entry.message or entry.raw,
                    failure_category=self.category,
                    matched_pattern=matcher.pattern_str,
                    explanation=matcher.explanation,
                    severity=matcher.severity,
                    weight=matcher.weight,
                    is_smoking_gun=matcher.is_smoking_gun,
                    context_before=context_before,
                    context_after=context_after,
                )
                found_evidence.append(evidence)

        return found_evidence

    @abstractmethod
    def synthesize_root_cause(self, evidence_list: List[EvidenceItem]) -> RootCause:
        """Create a synthesized RootCause based on the collected evidence."""
        pass

    @abstractmethod
    def generate_remediations(self, evidence_list: List[EvidenceItem]) -> List[RemediationAction]:
        """Generate targeted remediation recommendations with kubectl commands."""
        pass
