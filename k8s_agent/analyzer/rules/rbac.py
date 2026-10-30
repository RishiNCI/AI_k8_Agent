"""Rule for detecting RBAC and API authorization failures."""

from typing import List

from k8s_agent.analyzer.rules.base import BaseRule, PatternMatcher
from k8s_agent.models.evidence import EvidenceItem
from k8s_agent.models.failure_modes import FailureCategory, Severity
from k8s_agent.models.report import RemediationAction, RootCause


class RbacRule(BaseRule):
    category = FailureCategory.RBAC_PERMISSION_FAILURE

    def __init__(self):
        self.matchers = [
            PatternMatcher(
                r"(is forbidden:\s*User\s*\"[^\"]+\"\s*cannot\s+(?:get|list|watch|create|update|patch|delete)\s+resource\s*\"[^\"]+\")",
                "Kubernetes API server rejected request with 403 Forbidden due to RBAC policy",
                severity=Severity.HIGH,
                weight=1.0,
                is_smoking_gun=True,
            ),
            PatternMatcher(
                r"(403 Forbidden.*system:serviceaccount:)",
                "ServiceAccount lacks RBAC Role/RoleBinding permissions for target API resource",
                severity=Severity.HIGH,
                weight=0.95,
                is_smoking_gun=True,
            ),
            PatternMatcher(
                r"(Unauthorized:\s*user\s+cannot\s+access|cannot get path\s*\"/api)",
                "API Server authorization or authentication failure",
                severity=Severity.HIGH,
                weight=0.9,
            ),
        ]

    def synthesize_root_cause(self, evidence_list: List[EvidenceItem]) -> RootCause:
        max_weight = max((e.weight for e in evidence_list), default=0.8)

        return RootCause(
            category=self.category,
            severity=Severity.HIGH,
            title="RBAC Authorization Failure (403 Forbidden)",
            summary=(
                "The container's assigned ServiceAccount lacks required Kubernetes RBAC permissions "
                "(Role/RoleBinding or ClusterRole/ClusterRoleBinding) to interact with the Kubernetes API server."
            ),
            confidence_score=min(1.0, max_weight),
            is_primary=True,
            contributing_factors=[
                "Pod is likely bound to default ServiceAccount or an unprivileged custom ServiceAccount.",
                "Target Kubernetes API verb/resource is omitted from the Role/ClusterRole policy rules.",
            ],
            impact="Kubernetes controllers, operators, or telemetry sidecars cannot query or mutate cluster resources.",
        )

    def generate_remediations(self, evidence_list: List[EvidenceItem]) -> List[RemediationAction]:
        return [
            RemediationAction(
                phase="Immediate Mitigation",
                title="Test ServiceAccount Permissions with kubectl auth can-i",
                description="Simulate authorization checks for the pod's service account to verify missing verbs and resources.",
                kubectl_command="kubectl auth can-i <verb> <resource> --as=system:serviceaccount:<namespace>:<serviceaccount-name> -n <namespace>",
            ),
            RemediationAction(
                phase="Diagnostic Verification",
                title="List RoleBindings for Namespace",
                description="Check existing RoleBindings and ClusterRoleBindings assigned to the ServiceAccount.",
                kubectl_command="kubectl get rolebindings,clusterrolebindings -n <namespace> -o wide",
            ),
            RemediationAction(
                phase="Long-Term Prevention",
                title="Grant Principle of Least Privilege RBAC Role",
                description="Create a dedicated Role granting only the specific resources and verbs required by the workload.",
                kubectl_command=None,
            ),
        ]
