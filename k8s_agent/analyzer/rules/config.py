"""Rule for detecting ConfigMap, Secret, and configuration syntax failures."""

from typing import List

from k8s_agent.analyzer.rules.base import BaseRule, PatternMatcher
from k8s_agent.models.evidence import EvidenceItem
from k8s_agent.models.failure_modes import FailureCategory, Severity
from k8s_agent.models.report import RemediationAction, RootCause


class ConfigSecretRule(BaseRule):
    category = FailureCategory.CONFIG_SECRET_FAILURE

    def __init__(self):
        self.matchers = [
            PatternMatcher(
                r"(configmap(?:s)?\s*\"[^\"]+\"\s*not found|secret(?:s)?\s*\"[^\"]+\"\s*not found)",
                "Kubernetes ConfigMap or Secret referenced by container does not exist",
                severity=Severity.HIGH,
                weight=1.0,
                is_smoking_gun=True,
            ),
            PatternMatcher(
                r"(CreateContainerConfigError|CreateContainerError)",
                "Kubelet failed to create container configuration due to missing config or secret",
                severity=Severity.HIGH,
                weight=0.95,
                is_smoking_gun=True,
            ),
            PatternMatcher(
                r"(KeyError:\s*['\"][A-Z0-9_\-]+['\"]|environment variable\s+.*(?:\s+is not set|\s+missing))",
                "Application failed to initialize because a required environment variable is missing",
                severity=Severity.HIGH,
                weight=0.9,
            ),
            PatternMatcher(
                r"(yaml:\s*unmarshal errors|json:\s*cannot unmarshal|error parsing configuration|InvalidConfigurationException)",
                "Configuration file parsing syntax error (invalid YAML/JSON structure)",
                severity=Severity.HIGH,
                weight=0.9,
            ),
        ]

    def synthesize_root_cause(self, evidence_list: List[EvidenceItem]) -> RootCause:
        is_missing_cm = any("configmap" in e.matched_pattern.lower() for e in evidence_list)
        is_missing_secret = any("secret" in e.matched_pattern.lower() for e in evidence_list)
        is_env_key = any("keyerror" in e.matched_pattern.lower() or "environment variable" in e.matched_pattern.lower() for e in evidence_list)

        title = "Configuration / Secret Error"
        factors = []
        if is_missing_secret:
            title = "Missing Kubernetes Secret: Container Configuration Blocked"
            factors.append("A Secret referenced in env.valueFrom.secretKeyRef or volumes does not exist in the namespace.")
        elif is_missing_cm:
            title = "Missing Kubernetes ConfigMap: Container Configuration Blocked"
            factors.append("A ConfigMap referenced in envFrom or volumes does not exist in the namespace.")
        elif is_env_key:
            title = "Missing Required Application Environment Variable"
            factors.append("Application code crashed on startup trying to read an unpopulated environment variable.")

        max_weight = max((e.weight for e in evidence_list), default=0.8)

        return RootCause(
            category=self.category,
            severity=Severity.HIGH,
            title=title,
            summary=(
                "Container cannot boot or crashes immediately because an expected ConfigMap, Secret, "
                "or configuration key is missing or formatted with syntax errors."
            ),
            confidence_score=min(1.0, max_weight),
            is_primary=True,
            contributing_factors=factors,
            impact="Pod stuck in CreateContainerConfigError or crashes instantly on launch.",
        )

    def generate_remediations(self, evidence_list: List[EvidenceItem]) -> List[RemediationAction]:
        return [
            RemediationAction(
                phase="Immediate Mitigation",
                title="Verify ConfigMaps and Secrets in Namespace",
                description="Check if the referenced ConfigMap or Secret exists and contains the expected keys.",
                kubectl_command="kubectl get configmaps,secrets -n <namespace>",
            ),
            RemediationAction(
                phase="Diagnostic Verification",
                title="Inspect Pod Volume Mounts and Env Definitions",
                description="Review the Pod specification to identify the exact names of missing ConfigMaps/Secrets.",
                kubectl_command="kubectl describe pod <pod-name> -n <namespace> | grep -E 'Environment|Mounts' -A 10",
            ),
            RemediationAction(
                phase="Long-Term Prevention",
                title="Use Helm/Kustomize to Manage Config Dependencies",
                description="Ensure application deployment bundles include ConfigMaps/Secrets as prerequisites before Pods are scheduled.",
                kubectl_command=None,
            ),
        ]
