"""Rule for detecting Network and DNS resolution failures."""

from typing import List

from k8s_agent.analyzer.rules.base import BaseRule, PatternMatcher
from k8s_agent.models.evidence import EvidenceItem
from k8s_agent.models.failure_modes import FailureCategory, Severity
from k8s_agent.models.report import RemediationAction, RootCause


class NetworkDnsRule(BaseRule):
    category = FailureCategory.NETWORK_DNS_FAILURE

    def __init__(self):
        self.matchers = [
            PatternMatcher(
                r"(lookup\s+[a-zA-Z0-9_\-\.]+:\s*(?:no such host|i/o timeout|server misbehaving|NXDOMAIN|SERVFAIL))",
                "DNS lookup failed: unable to resolve cluster domain name via CoreDNS",
                severity=Severity.HIGH,
                weight=0.95,
                is_smoking_gun=True,
            ),
            PatternMatcher(
                r"(dial tcp (?:\[?[a-zA-Z0-9_\-\.\:]+\]?):\d+:\s*i/o timeout)",
                "TCP dial timed out waiting for connection establishment",
                severity=Severity.HIGH,
                weight=0.9,
            ),
            PatternMatcher(
                r"(dial tcp (?:\[?[a-zA-Z0-9_\-\.\:]+\]?):\d+:\s*connect:\s*connection refused)",
                "TCP connection refused by target host or port",
                severity=Severity.HIGH,
                weight=0.85,
            ),
            PatternMatcher(
                r"(read: connection reset by peer|connection reset by peer|ECONNRESET)",
                "Underlying TCP connection abruptly closed/reset by peer or middlebox",
                severity=Severity.HIGH,
                weight=0.8,
            ),
            PatternMatcher(
                r"(no route to host|network is unreachable|ETIMEDOUT)",
                "Network routing error: target IP or subnet unreachable",
                severity=Severity.HIGH,
                weight=0.9,
            ),
            PatternMatcher(
                r"(could not translate host name\s*\"[^\"]+\"|UnknownHostException)",
                "Client library DNS resolver failure",
                severity=Severity.HIGH,
                weight=0.95,
            ),
        ]

    def synthesize_root_cause(self, evidence_list: List[EvidenceItem]) -> RootCause:
        is_dns = any("dns" in e.explanation.lower() or "lookup" in e.explanation.lower() or "translate host" in e.explanation.lower() for e in evidence_list)
        is_timeout = any("dial timed out" in e.explanation.lower() for e in evidence_list)
        is_refused = any("connection refused" in e.explanation.lower() for e in evidence_list)

        title = "Network Connectivity Failure"
        factors = []
        if is_dns:
            title = "DNS Resolution Failure (CoreDNS / Service Discovery)"
            factors.append("Pod unable to resolve Kubernetes Service or external hostname through CoreDNS.")
            factors.append("Could indicate CoreDNS pod crash, conntrack table exhaustion, or misspelled service FQDN.")
        elif is_timeout:
            title = "TCP Connection Timeout: Downstream Service Unreachable"
            factors.append("Target endpoint is not answering TCP SYN packets within the timeout window.")
            factors.append("Likely caused by NetworkPolicy restrictions, dead service pod, or security group rules.")
        elif is_refused:
            title = "TCP Connection Refused: Target Port Not Bound"
            factors.append("Target host rejected connection; target service is down or listening on a different port.")

        max_weight = max((e.weight for e in evidence_list), default=0.8)

        return RootCause(
            category=self.category,
            severity=Severity.HIGH,
            title=title,
            summary=(
                "Inter-service or external network connectivity failed. Application calls are failing "
                "due to unresolvable DNS names or unreachable IP endpoints."
            ),
            confidence_score=min(1.0, max_weight),
            is_primary=True,
            contributing_factors=factors,
            impact="Downstream requests fail; upstream user calls return 500 or 504 Gateway Timeout.",
        )

    def generate_remediations(self, evidence_list: List[EvidenceItem]) -> List[RemediationAction]:
        return [
            RemediationAction(
                phase="Immediate Mitigation",
                title="Verify CoreDNS Health and Logs",
                description="Check if CoreDNS pods in kube-system are running, healthy, and not overloaded.",
                kubectl_command="kubectl get pods -n kube-system -l k8s-app=kube-dns && kubectl logs -n kube-system -l k8s-app=kube-dns --tail=50",
            ),
            RemediationAction(
                phase="Diagnostic Verification",
                title="Verify Target Service Endpoints & NetworkPolicies",
                description="Ensure the destination service has active endpoint IPs and that no NetworkPolicy is blocking ingress/egress.",
                kubectl_command="kubectl get endpoints <service-name> -n <namespace> && kubectl get networkpolicy -n <namespace>",
            ),
            RemediationAction(
                phase="Long-Term Prevention",
                title="Deploy NodeLocal DNSCache",
                description="Deploy NodeLocal DNSCache daemonset to cache DNS queries locally on every node and avoid conntrack table saturation and single CoreDNS bottlenecks.",
                kubectl_command=None,
            ),
        ]
