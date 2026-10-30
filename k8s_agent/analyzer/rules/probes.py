"""Rule for detecting Readiness, Liveness, and Startup probe failures."""

from typing import List

from k8s_agent.analyzer.rules.base import BaseRule, PatternMatcher
from k8s_agent.models.evidence import EvidenceItem
from k8s_agent.models.failure_modes import FailureCategory, Severity
from k8s_agent.models.report import RemediationAction, RootCause


class ProbeRule(BaseRule):
    category = FailureCategory.PROBE_FAILURE

    def __init__(self):
        self.matchers = [
            PatternMatcher(
                r"(Liveness probe failed:\s*HTTP probe failed with statuscode:\s*5\d\d|Container .* failed liveness probe, will be restarted)",
                "Liveness probe returned HTTP 5xx error; Kubelet scheduled container restart",
                severity=Severity.HIGH,
                weight=0.95,
                is_smoking_gun=True,
            ),
            PatternMatcher(
                r"(Readiness probe failed:\s*HTTP probe failed with statuscode:\s*5\d\d)",
                "Readiness probe returned HTTP 5xx error; pod marked unready and removed from endpoints",
                severity=Severity.HIGH,
                weight=0.9,
                is_smoking_gun=True,
            ),
            PatternMatcher(
                r"((?:Liveness|Readiness|Startup) probe failed:.*connect: connection refused)",
                "Health check probe failed: container application not listening on designated port",
                severity=Severity.HIGH,
                weight=0.9,
            ),
            PatternMatcher(
                r"((?:Liveness|Readiness|Startup) probe failed:.*timed out after)",
                "Health check probe exceeded timeout threshold without completing",
                severity=Severity.HIGH,
                weight=0.85,
            ),
            PatternMatcher(
                r"(Startup probe failed:)",
                "Startup probe failed; application exceeded initial boot window",
                severity=Severity.HIGH,
                weight=0.9,
            ),
        ]

    def synthesize_root_cause(self, evidence_list: List[EvidenceItem]) -> RootCause:
        is_liveness = any("liveness" in e.matched_pattern.lower() for e in evidence_list)
        is_readiness = any("readiness" in e.matched_pattern.lower() for e in evidence_list)
        is_timeout = any("timed out" in e.explanation.lower() for e in evidence_list)
        is_refused = any("connection refused" in e.explanation.lower() for e in evidence_list)

        title = "Health Check Failure: Kubernetes Probe Unhealthy"
        factors = []
        if is_liveness:
            title = "Liveness Probe Failure: Container Restarts Triggered"
            factors.append("Kubelet received recurring liveness probe failures, forcing container SIGTERM/restart cycles.")
        elif is_readiness:
            title = "Readiness Probe Failure: Traffic Removed From Endpoints"
            factors.append("Readiness probe failing, resulting in Pod being marked NotReady (0/1) and removed from Service mesh.")

        if is_timeout:
            factors.append("Health check endpoint took longer than probe timeoutSeconds to respond (thread contention or heavy load).")
        if is_refused:
            factors.append("Connection refused on health check port - application process may have crashed or not finished binding.")

        max_weight = max((e.weight for e in evidence_list), default=0.8)

        return RootCause(
            category=self.category,
            severity=Severity.HIGH,
            title=title,
            summary=(
                "Kubernetes kubelet health probes (readiness/liveness/startup) are failing. "
                "If readiness fails, the pod is isolated from service routing; if liveness fails, "
                "kubelet terminates and restarts the container."
            ),
            confidence_score=min(1.0, max_weight),
            is_primary=False,  # Probes are often secondary symptoms of deeper underlying issues
            contributing_factors=factors,
            impact="Loss of serving capacity, sudden 502/503 Bad Gateway errors, service flapping.",
        )

    def generate_remediations(self, evidence_list: List[EvidenceItem]) -> List[RemediationAction]:
        return [
            RemediationAction(
                phase="Immediate Mitigation",
                title="Review Probe Configuration & Thresholds",
                description="Adjust initialDelaySeconds, periodSeconds, timeoutSeconds, or failureThreshold in the pod spec to allow sufficient warm-up time.",
                kubectl_command="kubectl describe pod <pod-name> -n <namespace> | grep -E '(Liveness|Readiness|Startup):' -A 3",
            ),
            RemediationAction(
                phase="Diagnostic Verification",
                title="Test Health Check Endpoint Directly",
                description="Port-forward or exec into the pod to manually test the health endpoint and verify response code.",
                kubectl_command="kubectl exec -it <pod-name> -n <namespace> -- curl -iv http://localhost:<port>/<health-path>",
            ),
            RemediationAction(
                phase="Long-Term Prevention",
                title="Decouple Deep Dependency Checks from Liveness Probes",
                description="Liveness probes should only check process viability, not downstream database or third-party API connectivity, to prevent cascading cluster-wide restarts.",
                kubectl_command=None,
            ),
        ]
