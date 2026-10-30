"""Rule for detecting Image pull failures."""

from typing import List

from k8s_agent.analyzer.rules.base import BaseRule, PatternMatcher
from k8s_agent.models.evidence import EvidenceItem
from k8s_agent.models.failure_modes import FailureCategory, Severity
from k8s_agent.models.report import RemediationAction, RootCause


class ImagePullRule(BaseRule):
    category = FailureCategory.IMAGE_PULL_FAILURE

    def __init__(self):
        self.matchers = [
            PatternMatcher(
                r"(ImagePullBackOff|ErrImagePull|ErrImageNeverPull)",
                "Kubelet container runtime failed to pull container image",
                severity=Severity.HIGH,
                weight=1.0,
                is_smoking_gun=True,
            ),
            PatternMatcher(
                r"(rpc error: code = NotFound desc = failed to pull and unpack image|manifest for .* not found)",
                "Container registry reported image tag or repository does not exist (404 Not Found)",
                severity=Severity.HIGH,
                weight=0.95,
                is_smoking_gun=True,
            ),
            PatternMatcher(
                r"(unauthorized: authentication required|pull access denied, repository does not exist or may require 'docker login')",
                "Registry authentication failed: missing or invalid imagePullSecrets",
                severity=Severity.HIGH,
                weight=0.95,
                is_smoking_gun=True,
            ),
            PatternMatcher(
                r"(toomanyrequests: You have reached your pull rate limit|rate limit exceeded)",
                "Container registry rate limit exceeded (e.g. Docker Hub anonymous pull limits)",
                severity=Severity.HIGH,
                weight=0.95,
                is_smoking_gun=True,
            ),
        ]

    def synthesize_root_cause(self, evidence_list: List[EvidenceItem]) -> RootCause:
        is_auth = any("authentication required" in e.matched_pattern.lower() or "access denied" in e.matched_pattern.lower() for e in evidence_list)
        is_404 = any("not found" in e.matched_pattern.lower() for e in evidence_list)
        is_ratelimit = any("rate limit" in e.matched_pattern.lower() for e in evidence_list)

        title = "ImagePullBackOff: Container Image Cannot Be Retrieved"
        factors = []
        if is_auth:
            title = "ImagePullBackOff: Authentication / Registry Credential Error"
            factors.append("Kubelet lacks valid credentials (imagePullSecrets) to pull from private container registry.")
        elif is_404:
            title = "ImagePullBackOff: Image Tag or Repository Not Found"
            factors.append("The requested container image tag or repository does not exist in the remote registry.")
        elif is_ratelimit:
            title = "ImagePullBackOff: Registry Pull Rate Limit Exceeded"
            factors.append("Container registry (e.g. Docker Hub) blocked image pulls due to rate limits.")

        max_weight = max((e.weight for e in evidence_list), default=0.8)

        return RootCause(
            category=self.category,
            severity=Severity.HIGH,
            title=title,
            summary=(
                "The pod cannot start because the container runtime is unable to pull the container image "
                "from the registry. The pod is stuck in ImagePullBackOff."
            ),
            confidence_score=min(1.0, max_weight),
            is_primary=True,
            contributing_factors=factors,
            impact="Pod remains in 'Pending' or 'ImagePullBackOff' state; container never initializes.",
        )

    def generate_remediations(self, evidence_list: List[EvidenceItem]) -> List[RemediationAction]:
        return [
            RemediationAction(
                phase="Immediate Mitigation",
                title="Verify Image Tag and Repository Name",
                description="Check the image name and tag in the pod or deployment spec for typos or nonexistent versions.",
                kubectl_command="kubectl get pod <pod-name> -n <namespace> -o jsonpath='{.spec.containers[*].image}'",
            ),
            RemediationAction(
                phase="Diagnostic Verification",
                title="Check Pod Events and Registry Secret",
                description="Inspect the pod event log for detailed registry error response codes.",
                kubectl_command="kubectl describe pod <pod-name> -n <namespace> | grep -A 10 Events:",
            ),
            RemediationAction(
                phase="Long-Term Prevention",
                title="Configure ImagePullSecrets and Mirroring",
                description="Attach imagePullSecrets to the default ServiceAccount or use an internal enterprise artifact mirror (e.g. Harbor / Artifact Registry).",
                kubectl_command="kubectl create secret docker-registry regcred --docker-server=<server> --docker-username=<user> --docker-password=<pass> -n <namespace>",
            ),
        ]
