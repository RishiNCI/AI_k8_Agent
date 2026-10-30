import os
import subprocess
import pytest
from k8s_agent.agent.investigator import KubernetesInvestigator
from k8s_agent.models.failure_modes import FailureCategory
from k8s_agent.tools.get_pod_logs import (
    clear_mock_pod_logs,
    get_pod_logs,
    get_pod_logs_detailed,
    KubernetesToolError,
    register_mock_pod_logs,
)

SAMPLE_OOM_LOGS = """
2026-10-29T10:05:48.552Z [order-api-89k/app] WARN High memory utilization: 500MB / 512MB
2026-10-29T10:06:01.002Z [order-api-89k/app] ERROR java.lang.OutOfMemoryError: Java heap space
2026-10-29T10:06:02.198Z [order-api-89k/app] stderr F [kernel] Memory cgroup out of memory: Killed process
2026-10-29T10:06:02.210Z [order-api-89k/app] command terminated with exit code 137
"""

SAMPLE_DNS_LOGS = """
2026-10-29T14:12:30.450Z ERROR lookup postgres-service.db.svc.cluster.local: i/o timeout
2026-10-29T14:12:42.000Z Warning  Unhealthy  Readiness probe failed: HTTP probe failed with statuscode: 500
2026-10-29T14:13:00.000Z Warning  BackOff    Back-off restarting failed container
"""


@pytest.fixture(autouse=True)
def clean_mocks():
    clear_mock_pod_logs()
    yield
    clear_mock_pod_logs()


def test_get_pod_logs_mock():
    register_mock_pod_logs("order-service-pod-1", SAMPLE_OOM_LOGS, namespace="production")

    logs = get_pod_logs("order-service-pod-1", namespace="production")
    assert "OutOfMemoryError" in logs
    assert "exit code 137" in logs

    detailed = get_pod_logs_detailed("order-service-pod-1", namespace="production")
    assert detailed.success is True
    assert detailed.pod_name == "order-service-pod-1"
    assert detailed.namespace == "production"


def test_investigator_investigate_pod():
    register_mock_pod_logs("payment-gateway-pod", SAMPLE_DNS_LOGS, namespace="finance")

    investigator = KubernetesInvestigator()
    report = investigator.investigate_pod("payment-gateway-pod", namespace="finance")

    assert report.primary_root_cause is not None
    assert report.primary_root_cause.category == FailureCategory.NETWORK_DNS_FAILURE
    assert report.source_name == "pod:finance/payment-gateway-pod"
    assert len(report.evidence) > 0


def test_investigator_auto_detect_pod_target():
    # Calling investigator.investigate with a pod name string should automatically use get_pod_logs
    register_mock_pod_logs("cart-service-xyz", SAMPLE_OOM_LOGS, namespace="default")

    investigator = KubernetesInvestigator()
    report = investigator.investigate("cart-service-xyz")

    assert report.primary_root_cause is not None
    assert report.primary_root_cause.category == FailureCategory.OOM_KILLED
    assert "cart-service-xyz" in report.source_name


def test_get_pod_logs_missing_binary(monkeypatch):
    monkeypatch.setattr("os.path.exists", lambda path: False)
    monkeypatch.setattr("shutil.which", lambda bin_name: None)

    with pytest.raises(KubernetesToolError) as exc_info:
        get_pod_logs("non-existent-pod", namespace="default")
    assert "kubectl binary not found" in str(exc_info.value)


def test_cli_with_pod_argument():
    # Pass mock logs via environment variable for the subprocess
    env = os.environ.copy()
    env["K8S_MOCK_POD_NAME"] = "checkout-pod-99"
    env["K8S_MOCK_LOGS_DATA"] = SAMPLE_OOM_LOGS

    # Run CLI with --pod
    result = subprocess.run(
        [
            "/root/AI-K8-Agent/.venv/bin/python",
            "-m",
            "k8s_agent",
            "--pod",
            "checkout-pod-99",
            "--format",
            "markdown",
        ],
        cwd="/root/AI-K8-Agent",
        env=env,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0
    assert "OOMKilled" in result.stdout or "Exit Code 137" in result.stdout
    assert "## 🎯 Root Cause Analysis" in result.stdout
