"""Rule for detecting Resource Starvation, Pool Exhaustion, and Deadlocks."""

from typing import List

from k8s_agent.analyzer.rules.base import BaseRule, PatternMatcher
from k8s_agent.models.evidence import EvidenceItem
from k8s_agent.models.failure_modes import FailureCategory, Severity
from k8s_agent.models.report import RemediationAction, RootCause


class ResourceDeadlockRule(BaseRule):
    category = FailureCategory.RESOURCE_STARVATION_DEADLOCK

    def __init__(self):
        self.matchers = [
            PatternMatcher(
                r"(Connection pool exhausted|HikariPool-[^\s]+ - Connection is not available, request timed out|PoolAcquisitionTimeoutException|too many connections)",
                "Database or HTTP connection pool exhausted; queries/requests blocked",
                severity=Severity.HIGH,
                weight=0.95,
                is_smoking_gun=True,
            ),
            PatternMatcher(
                r"(Deadlock detected|Deadlock found when trying to get lock|org\.hibernate\.exception\.LockAcquisitionException)",
                "Concurrent transactions resulted in a database deadlock",
                severity=Severity.HIGH,
                weight=0.9,
            ),
            PatternMatcher(
                r"(Too many open files|EMFILE|ENFILE)",
                "Container or OS file descriptor quota exhausted (ulimit / fs.file-max)",
                severity=Severity.CRITICAL,
                weight=0.95,
                is_smoking_gun=True,
            ),
            PatternMatcher(
                r"(Thread starvation|ThreadPoolExecutor.*capacity exceeded|TaskRejectedException)",
                "Application thread pool queue is saturated, rejecting incoming work",
                severity=Severity.HIGH,
                weight=0.9,
            ),
        ]

    def synthesize_root_cause(self, evidence_list: List[EvidenceItem]) -> RootCause:
        is_pool = any("pool" in e.matched_pattern.lower() or "connections" in e.matched_pattern.lower() for e in evidence_list)
        is_files = any("open files" in e.matched_pattern.lower() or "emfile" in e.matched_pattern.lower() for e in evidence_list)

        title = "Resource Starvation / Pool Exhaustion"
        factors = []
        if is_pool:
            title = "Database Connection Pool Exhaustion"
            factors.append("Active connections reached maximum pool size, causing subsequent requests to time out.")
            factors.append("Check for unclosed connections, long-running queries, or transaction leaks.")
        elif is_files:
            title = "OS File Descriptor Limit Exceeded (EMFILE)"
            factors.append("The container reached the process open file descriptor ceiling (ulimit -n).")
            factors.append("Often caused by socket leaks, unclosed file streams, or unclosed HTTP response bodies.")

        max_weight = max((e.weight for e in evidence_list), default=0.8)

        return RootCause(
            category=self.category,
            severity=Severity.HIGH,
            title=title,
            summary=(
                "The container exhausted critical internal operating resources such as database connection pools, "
                "worker thread capacities, or kernel file descriptors, causing requests to stall or reject."
            ),
            confidence_score=min(1.0, max_weight),
            is_primary=True,
            contributing_factors=factors,
            impact="Request timeouts, cascading 504 Gateway errors, backpressure on upstream callers.",
        )

    def generate_remediations(self, evidence_list: List[EvidenceItem]) -> List[RemediationAction]:
        return [
            RemediationAction(
                phase="Immediate Mitigation",
                title="Increase Connection Pool Size or Pod Replicas",
                description="Scale the deployment or increase connection pool capacity and database server max_connections.",
                kubectl_command="kubectl scale deployment <deployment-name> -n <namespace> --replicas=<count>",
            ),
            RemediationAction(
                phase="Diagnostic Verification",
                title="Inspect Container Resource Usage",
                description="Monitor container CPU and memory metrics for throttling or high utilization.",
                kubectl_command="kubectl top pod <pod-name> -n <namespace>",
            ),
            RemediationAction(
                phase="Long-Term Prevention",
                title="Audit Connection Lifecycle and File Descriptors",
                description="Ensure application code uses try-with-resources / context managers to safely close database handles and network sockets.",
                kubectl_command=None,
            ),
        ]
