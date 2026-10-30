"""Kubernetes Investigation Agent."""

__version__ = "0.2.0"

from k8s_agent.agent.investigator import KubernetesInvestigator
from k8s_agent.tools.get_pod_logs import (
    get_pod_logs,
    get_pod_logs_detailed,
    PodLogFetchResult,
    KubernetesToolError,
    register_mock_pod_logs,
    clear_mock_pod_logs,
)
from k8s_agent.models.failure_modes import FailureCategory, Severity
from k8s_agent.models.report import InvestigationReport, RootCause, TimelineEvent
from k8s_agent.models.evidence import EvidenceItem
from k8s_agent.models.log_entry import LogEntry, LogLevel

__all__ = [
    "__version__",
    "KubernetesInvestigator",
    "get_pod_logs",
    "get_pod_logs_detailed",
    "PodLogFetchResult",
    "KubernetesToolError",
    "register_mock_pod_logs",
    "clear_mock_pod_logs",
    "FailureCategory",
    "Severity",
    "InvestigationReport",
    "RootCause",
    "TimelineEvent",
    "EvidenceItem",
    "LogEntry",
    "LogLevel",
]
