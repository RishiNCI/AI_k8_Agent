"""Rule for detecting CrashLoopBackOff and fatal process exits."""

from typing import List

from k8s_agent.analyzer.rules.base import BaseRule, PatternMatcher
from k8s_agent.models.evidence import EvidenceItem
from k8s_agent.models.failure_modes import FailureCategory, Severity
from k8s_agent.models.report import RemediationAction, RootCause


class CrashLoopRule(BaseRule):
    category = FailureCategory.CRASH_LOOP_BACKOFF

    def __init__(self):
        self.matchers = [
            PatternMatcher(
                r"(Back-off restarting failed container|CrashLoopBackOff)",
                "Kubelet detected repeated container termination; backoff delay triggered",
                severity=Severity.CRITICAL,
                weight=1.0,
                is_smoking_gun=True,
            ),
            PatternMatcher(
                r"(exit(?:ed with)? code [1-9]\d*|status [1-9]\d*)",
                "Application process terminated with non-zero exit code",
                severity=Severity.HIGH,
                weight=0.85,
            ),
            PatternMatcher(
                r"(Segmentation fault \(core dumped\)|signal 11|SIGSEGV|SIGBUS)",
                "Process crashed due to memory segmentation fault (SIGSEGV)",
                severity=Severity.CRITICAL,
                weight=0.95,
                is_smoking_gun=True,
            ),
            PatternMatcher(
                r"(Application startup failed|Fatal error during initialization|Failed to start server)",
                "Application initialization failed during boot phase",
                severity=Severity.HIGH,
                weight=0.9,
            ),
            PatternMatcher(
                r"(exec: \"[^\"]+\": executable file not found in \$PATH|standard_init_linux\.go:\d+: exec user process caused)",
                "Container entrypoint or command binary missing from image filesystem",
                severity=Severity.CRITICAL,
                weight=0.95,
                is_smoking_gun=True,
            ),
            PatternMatcher(
                r"(ModuleNotFoundError: No module named|ImportError: cannot import name|Cannot find module)",
                "Missing library dependency or corrupted container build layer",
                severity=Severity.HIGH,
                weight=0.9,
            ),
        ]

    def synthesize_root_cause(self, evidence_list: List[EvidenceItem]) -> RootCause:
        factors = []
        is_binary_missing = any("executable file not found" in e.explanation for e in evidence_list)
        is_segfault = any("segmentation fault" in e.explanation for e in evidence_list)

        title = "CrashLoopBackOff: Repeated Container Initialization Failure"
        if is_binary_missing:
            title = "CrashLoopBackOff: Container Command / Binary Not Found"
            factors.append("The command specified in the pod spec or Dockerfile ENTRYPOINT does not exist in the container image.")
        elif is_segfault:
            title = "CrashLoopBackOff: Native Process Segmentation Fault (SIGSEGV)"
            factors.append("Memory violation or incompatible native shared library binary caused a segmentation fault.")

        factors.append("Container process exited prematurely immediately after start.")
        factors.append("Kubernetes kubelet is backing off container restarts with exponential delay.")

        max_weight = max((e.weight for e in evidence_list), default=0.8)

        return RootCause(
            category=self.category,
            severity=Severity.CRITICAL,
            title=title,
            summary=(
                "The container is trapped in a CrashLoopBackOff cycle. The process crashes immediately upon startup, "
                "preventing the pod from transitioning to 'Running' or 'Ready' state. Kubelet enforces an exponential "
                "restart back-off timer (up to 5 minutes)."
            ),
            confidence_score=min(1.0, max_weight + 0.05),
            is_primary=True,
            contributing_factors=factors,
            impact="Pod remains unavailable to serve traffic; service endpoints drop the pod replica.",
        )

    def generate_remediations(self, evidence_list: List[EvidenceItem]) -> List[RemediationAction]:
        return [
            RemediationAction(
                phase="Immediate Mitigation",
                title="Inspect Previous Container Termination Logs",
                description="Fetch the stdout/stderr logs from the previous instance of the crashed container before restart.",
                kubectl_command="kubectl logs <pod-name> -n <namespace> --previous --tail=100",
            ),
            RemediationAction(
                phase="Diagnostic Verification",
                title="Inspect Pod Last State and Exit Code",
                description="Inspect the pod state, exit code, and reason from the container status object.",
                kubectl_command="kubectl get pod <pod-name> -n <namespace> -o jsonpath='{.status.containerStatuses[*].lastState}'",
            ),
            RemediationAction(
                phase="Long-Term Prevention",
                title="Validate Entrypoint & Startup Dependencies",
                description="Verify that required environment variables, secrets, configuration files, and downstream databases are reachable before startup, or add an initContainer to wait for dependencies.",
                kubectl_command="kubectl describe pod <pod-name> -n <namespace>",
            ),
        ]
