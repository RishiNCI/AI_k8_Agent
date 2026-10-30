"""Rule for detecting Storage and Volume mount failures."""

from typing import List

from k8s_agent.analyzer.rules.base import BaseRule, PatternMatcher
from k8s_agent.models.evidence import EvidenceItem
from k8s_agent.models.failure_modes import FailureCategory, Severity
from k8s_agent.models.report import RemediationAction, RootCause


class StorageRule(BaseRule):
    category = FailureCategory.STORAGE_VOLUME_FAILURE

    def __init__(self):
        self.matchers = [
            PatternMatcher(
                r"(MountVolume\.SetUp failed for volume|FailedMount|VolumeSubpathInitializationFailed)",
                "Kubelet volume manager failed to mount or format requested volume",
                severity=Severity.HIGH,
                weight=0.95,
                is_smoking_gun=True,
            ),
            PatternMatcher(
                r"(persistentvolumeclaim\s*\"[^\"]+\"\s*not found|unbound Immediate PersistentVolumeClaims)",
                "PersistentVolumeClaim (PVC) requested by pod does not exist or is unbound",
                severity=Severity.HIGH,
                weight=0.95,
                is_smoking_gun=True,
            ),
            PatternMatcher(
                r"(no space left on device|DiskPressure|out of disk)",
                "Underlying node or volume disk space completely exhausted",
                severity=Severity.CRITICAL,
                weight=0.95,
                is_smoking_gun=True,
            ),
            PatternMatcher(
                r"(Read-only file system|filesystem is read-only)",
                "Filesystem mounted as read-only, preventing application writes",
                severity=Severity.HIGH,
                weight=0.9,
            ),
            PatternMatcher(
                r"(volume is already used by pod|Multi-Attach error for volume)",
                "ReadWriteOnce (RWO) volume is already attached to another node",
                severity=Severity.HIGH,
                weight=0.95,
            ),
        ]

    def synthesize_root_cause(self, evidence_list: List[EvidenceItem]) -> RootCause:
        is_disk_full = any("no space left on device" in e.matched_pattern.lower() or "diskpressure" in e.matched_pattern.lower() for e in evidence_list)
        is_pvc_missing = any("not found" in e.matched_pattern.lower() or "unbound" in e.matched_pattern.lower() for e in evidence_list)
        is_multi_attach = any("multi-attach" in e.matched_pattern.lower() or "already used" in e.matched_pattern.lower() for e in evidence_list)

        title = "Storage / Volume Mount Failure"
        factors = []
        if is_disk_full:
            title = "Disk Exhaustion: No Space Left On Device"
            factors.append("Host node or mounted persistent volume is 100% full (DiskPressure condition).")
        elif is_pvc_missing:
            title = "Missing or Unbound PersistentVolumeClaim"
            factors.append("The PVC referenced in pod.spec.volumes does not exist or has no matching PV.")
        elif is_multi_attach:
            title = "Storage Multi-Attach Conflict (ReadWriteOnce)"
            factors.append("A ReadWriteOnce EBS/GPD/Ceph volume is still attached to an old node.")

        max_weight = max((e.weight for e in evidence_list), default=0.8)

        return RootCause(
            category=self.category,
            severity=Severity.HIGH,
            title=title,
            summary=(
                "Container initialization or filesystem write operations failed due to volume mounting errors, "
                "missing persistent volume claims, or node disk space exhaustion."
            ),
            confidence_score=min(1.0, max_weight),
            is_primary=True,
            contributing_factors=factors,
            impact="Pod stuck in ContainerCreating or crashing when attempting to write data/logs.",
        )

    def generate_remediations(self, evidence_list: List[EvidenceItem]) -> List[RemediationAction]:
        return [
            RemediationAction(
                phase="Immediate Mitigation",
                title="Inspect PVC and PV Status",
                description="Check if the PersistentVolumeClaim is bound, pending, or missing.",
                kubectl_command="kubectl get pvc,pv -n <namespace>",
            ),
            RemediationAction(
                phase="Diagnostic Verification",
                title="Inspect Storage Events & Node Disk Status",
                description="Examine storage controller events and node DiskPressure status.",
                kubectl_command="kubectl describe node <node-name> | grep -E 'DiskPressure|Allocatable' -A 3",
            ),
            RemediationAction(
                phase="Long-Term Prevention",
                title="Configure Disk Quotas and PVC Auto-expansion",
                description="Enable allowVolumeExpansion in StorageClass and configure volume monitoring alerts.",
                kubectl_command=None,
            ),
        ]
