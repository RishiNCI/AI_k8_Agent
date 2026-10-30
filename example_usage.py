"""Example demonstration of using the Kubernetes Investigation Agent and get_pod_logs tool."""

from k8s_agent import (
    KubernetesInvestigator,
    get_pod_logs,
    register_mock_pod_logs,
)

# Simulate a Kubernetes pod experiencing a DNS & cascading probe failure
MOCK_POD_NAME = "payment-gateway-7b64-x92j"
MOCK_NAMESPACE = "production"

SIMULATED_POD_LOGS = """
2026-10-29T10:00:00.100Z [payment-gateway/api] INFO Starting payment-gateway v2.4.0
2026-10-29T10:00:02.300Z [payment-gateway/api] INFO Listening on port 8080
2026-10-29T10:04:15.510Z [payment-gateway/api] ERROR Failed to connect to Redis cache: lookup redis-cluster.cache.svc.cluster.local: i/o timeout
2026-10-29T10:04:18.000Z [payment-gateway/api] ERROR dial tcp 10.96.15.22:6379: i/o timeout
2026-10-29T10:04:22.120Z Warning  Unhealthy  12s (x2 over 20s)  kubelet  Readiness probe failed: HTTP probe failed with statuscode: 500
2026-10-29T10:04:35.000Z Warning  Unhealthy  2s (x3 over 15s)   kubelet  Liveness probe failed: HTTP probe failed with statuscode: 500
2026-10-29T10:04:36.000Z Normal   Killing    0s                 kubelet  Container api failed liveness probe, will be restarted
2026-10-29T10:04:40.000Z Warning  BackOff    1s (x3 over 30s)   kubelet  Back-off restarting failed container api in pod payment-gateway-7b64-x92j
"""

# Register mock data so this example runs independently of live cluster network access
register_mock_pod_logs(MOCK_POD_NAME, SIMULATED_POD_LOGS, namespace=MOCK_NAMESPACE)


def main():
    print("=== 1. Using the standalone get_pod_logs tool ===")
    logs = get_pod_logs(
        pod_name=MOCK_POD_NAME,
        namespace=MOCK_NAMESPACE,
        tail_lines=100,
    )
    print(f"Fetched {len(logs.splitlines())} lines from pod '{MOCK_NAMESPACE}/{MOCK_POD_NAME}'.\n")

    print("=== 2. Investigating live pod via KubernetesInvestigator ===")
    investigator = KubernetesInvestigator()

    # The agent uses get_pod_logs under the hood to fetch logs directly from the cluster pod
    report = investigator.investigate_pod(
        pod_name=MOCK_POD_NAME,
        namespace=MOCK_NAMESPACE,
        tail_lines=100,
    )

    print(f"Incident ID        : {report.incident_id}")
    print(f"Target Pod         : {report.source_name}")
    print(f"Primary Root Cause : {report.primary_root_cause.title}")
    print(f"Confidence Score   : {report.primary_root_cause.confidence_percent}%\n")

    print(f"Supporting Evidence Cited ({len(report.evidence)} items):")
    for ev in report.evidence[:3]:
        print(f"  • [Line {ev.line_number}] [{ev.failure_category.value}] {ev.explanation}")
        print(f"    Raw: {ev.raw_excerpt}")

    print("\nActionable Remediation Commands:")
    for rem in report.remediations[:2]:
        if rem.kubectl_command:
            print(f"  $ {rem.kubectl_command}")


if __name__ == "__main__":
    main()
