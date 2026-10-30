"""Rule for detecting Out-Of-Memory (OOM) failures."""

from typing import List

from k8s_agent.analyzer.rules.base import BaseRule, PatternMatcher
from k8s_agent.models.evidence import EvidenceItem
from k8s_agent.models.failure_modes import FailureCategory, Severity
from k8s_agent.models.report import RemediationAction, RootCause


class OOMRule(BaseRule):
    category = FailureCategory.OOM_KILLED

    def __init__(self):
        self.matchers = [
            PatternMatcher(
                r"(exit(?:ed with)? code 137|status 137|command terminated with exit code 137)",
                "Process terminated with Exit Code 137 (SIGKILL issued by Linux kernel OOM Killer)",
                severity=Severity.CRITICAL,
                weight=1.0,
                is_smoking_gun=True,
            ),
            PatternMatcher(
                r"(OOMKilled:\s*true|reason:\s*OOMKilled|reason=OOMKilling)",
                "Kubernetes container status explicitly marked as OOMKilled",
                severity=Severity.CRITICAL,
                weight=1.0,
                is_smoking_gun=True,
            ),
            PatternMatcher(
                r"(cgroup out of memory|Memory cgroup out of memory|invoked oom-killer)",
                "Linux cgroup memory controller triggered kernel OOM-killer",
                severity=Severity.CRITICAL,
                weight=0.95,
                is_smoking_gun=True,
            ),
            PatternMatcher(
                r"(java\.lang\.OutOfMemoryError:\s*(?:Java heap space|GC overhead limit exceeded|Metaspace))",
                "JVM heap memory exhausted - application threw OutOfMemoryError",
                severity=Severity.CRITICAL,
                weight=0.95,
                is_smoking_gun=True,
            ),
            PatternMatcher(
                r"(fatal error:\s*runtime:\s*out of memory|fatal error:\s*cannot allocate memory)",
                "Go runtime exhausted available virtual or physical memory",
                severity=Severity.CRITICAL,
                weight=0.95,
                is_smoking_gun=True,
            ),
            PatternMatcher(
                r"(JavaScript heap out of memory|Fatal error in V8: .*allocation failed)",
                "Node.js V8 JavaScript engine heap limit exceeded",
                severity=Severity.CRITICAL,
                weight=0.95,
                is_smoking_gun=True,
            ),
            PatternMatcher(
                r"(Memory limit exceeded|Memory cgroup limit reached|oom_reaper)",
                "Container memory limit reached or memory cgroup exceeded threshold",
                severity=Severity.HIGH,
                weight=0.85,
            ),
            PatternMatcher(
                r"(\bKilled\b|\bprocess was killed by signal 9\b)",
                "Process killed abruptly via SIGKILL (frequent sign of kernel OOM reaper)",
                severity=Severity.HIGH,
                weight=0.7,
            ),
        ]

    def synthesize_root_cause(self, evidence_list: List[EvidenceItem]) -> RootCause:
        # Determine specific subtype: JVM vs Go vs Kernel cgroup
        has_jvm = any("java.lang.OutOfMemoryError" in e.explanation for e in evidence_list)
        has_node = any("Node.js" in e.explanation for e in evidence_list)
        has_exit_137 = any("137" in e.explanation for e in evidence_list)

        title = "OOMKilled: Container Memory Limit Exceeded"
        factors = []
        if has_jvm:
            title = "OOMKilled: Java Virtual Machine Heap Exhaustion"
            factors.append("JVM heap allocation exceeded pod memory cgroup limit (-Xmx mismatch).")
        elif has_node:
            title = "OOMKilled: Node.js V8 Heap Exhaustion"
            factors.append("Node.js default heap limit (typically 1.4-2GB) was exhausted.")

        if has_exit_137:
            factors.append("Container received SIGKILL (Exit code 137) from OS kernel memory controller.")
        factors.append("Current memory request/limit is insufficient for the current application workload.")

        max_weight = max((e.weight for e in evidence_list), default=0.8)

        return RootCause(
            category=self.category,
            severity=Severity.CRITICAL,
            title=title,
            summary=(
                "The container process exceeded its memory cgroup boundaries (spec.resources.limits.memory) "
                "or runtime heap limits, prompting the Linux kernel OOM-killer to send SIGKILL (exit code 137). "
                "This caused abrupt container termination and pod restarts."
            ),
            confidence_score=min(1.0, max_weight + 0.05),
            is_primary=True,
            contributing_factors=factors,
            impact="Pod restarts, disrupted user traffic, dropped connections, and potential cascade to CrashLoopBackOff.",
        )

    def generate_remediations(self, evidence_list: List[EvidenceItem]) -> List[RemediationAction]:
        return [
            RemediationAction(
                phase="Immediate Mitigation",
                title="Increase Pod Memory Limits in Deployment Spec",
                description="Increase resources.limits.memory and resources.requests.memory in the deployment manifest (e.g. from 512Mi to 1Gi or 2Gi).",
                kubectl_command="kubectl set resources deployment <deployment-name> -n <namespace> --limits=memory=2Gi --requests=memory=1Gi",
            ),
            RemediationAction(
                phase="Diagnostic Verification",
                title="Verify Container Memory Limits and OOM Events",
                description="Check container last termination reason, memory usage, and cluster OOM events.",
                kubectl_command="kubectl describe pod <pod-name> -n <namespace> | grep -E 'OOMKilled|Exit Code|Limits|Requests'",
            ),
            RemediationAction(
                phase="Long-Term Prevention",
                title="Configure Application Runtime Heap Limits & Memory Leak Profiling",
                description="Align JVM heap options (-XX:MaxRAMPercentage=75.0 or -Xmx) or Node.js (--max-old-space-size) with container limits. Set up heap dumps on OOM (-XX:+HeapDumpOnOutOfMemoryError).",
                kubectl_command="kubectl top pod <pod-name> -n <namespace> --containers",
            ),
        ]
