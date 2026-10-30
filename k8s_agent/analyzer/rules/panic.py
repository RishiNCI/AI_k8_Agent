"""Rule for detecting application panics and unhandled runtime exceptions."""

from typing import List

from k8s_agent.analyzer.rules.base import BaseRule, PatternMatcher
from k8s_agent.models.evidence import EvidenceItem
from k8s_agent.models.failure_modes import FailureCategory, Severity
from k8s_agent.models.report import RemediationAction, RootCause


class PanicRule(BaseRule):
    category = FailureCategory.APPLICATION_PANIC

    def __init__(self):
        self.matchers = [
            PatternMatcher(
                r"(panic:\s*runtime error|panic:\s*.*\[recovered\])",
                "Go language runtime panic",
                severity=Severity.HIGH,
                weight=0.9,
                is_smoking_gun=True,
            ),
            PatternMatcher(
                r"(Traceback \(most recent call last\):)",
                "Python unhandled exception traceback",
                severity=Severity.HIGH,
                weight=0.85,
            ),
            PatternMatcher(
                r"(java\.lang\.NullPointerException|NullReferenceException)",
                "Null pointer dereference in application logic",
                severity=Severity.HIGH,
                weight=0.85,
            ),
            PatternMatcher(
                r"(FATAL:\s*.*|CRITICAL:\s*.*)",
                "Application emitted a fatal or critical log event",
                severity=Severity.HIGH,
                weight=0.8,
            ),
        ]

    def synthesize_root_cause(self, evidence_list: List[EvidenceItem]) -> RootCause:
        max_weight = max((e.weight for e in evidence_list), default=0.75)

        return RootCause(
            category=self.category,
            severity=Severity.HIGH,
            title="Application Runtime Panic / Unhandled Exception",
            summary=(
                "The application threw an uncaught exception or runtime panic, causing the execution "
                "thread or main process to terminate unexpectedly."
            ),
            confidence_score=min(1.0, max_weight),
            is_primary=True,
            contributing_factors=[
                "Unexpected input payload, missing null checks, or edge-case runtime condition.",
                "Process did not have a top-level recovery handler to prevent process death.",
            ],
            impact="Request failure or process termination.",
        )

    def generate_remediations(self, evidence_list: List[EvidenceItem]) -> List[RemediationAction]:
        return [
            RemediationAction(
                phase="Immediate Mitigation",
                title="Review Full Stack Trace in Logs",
                description="Extract the complete stack trace and identify the source file and line number causing the exception.",
                kubectl_command="kubectl logs <pod-name> -n <namespace> --tail=300",
            ),
            RemediationAction(
                phase="Diagnostic Verification",
                title="Check Container Restart Count",
                description="Verify if this exception caused container restarts or was isolated to an individual request handler.",
                kubectl_command="kubectl get pod <pod-name> -n <namespace> -o jsonpath='{.status.containerStatuses[*].restartCount}'",
            ),
            RemediationAction(
                phase="Long-Term Prevention",
                title="Implement Global Exception Handling",
                description="Wrap top-level request handlers in recovery middleware to catch runtime panics and return a graceful 500 error instead of killing the container.",
                kubectl_command=None,
            ),
        ]
