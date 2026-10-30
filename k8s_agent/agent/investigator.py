"""Main Kubernetes Investigation Agent orchestrator."""

import io
from pathlib import Path
from typing import Optional, Union

from k8s_agent.agent.context_builder import ContextBuilder
from k8s_agent.agent.llm_provider import LLMProvider
from k8s_agent.analyzer.rca_engine import RCAEngine
from k8s_agent.models.report import InvestigationReport
from k8s_agent.parser.log_parser import LogParser
from k8s_agent.tools.get_pod_logs import get_pod_logs


class KubernetesInvestigator:
    """
    Autonomous Kubernetes Investigation Agent.
    Fetches logs from Kubernetes pods using get_pod_logs, parses multi-format streams,
    detects failure modes, correlates events into timelines, and generates root cause
    reports with supporting evidence.
    """

    def __init__(
        self,
        use_llm: bool = False,
        gemini_api_key: Optional[str] = None,
        llm_model: str = "gemini-2.5-flash",
    ):
        self.parser = LogParser()
        self.rca_engine = RCAEngine()
        self.use_llm = use_llm
        self.llm_provider = LLMProvider(api_key=gemini_api_key, model=llm_model) if use_llm else None

    def investigate_pod(
        self,
        pod_name: str,
        namespace: str = "default",
        container: Optional[str] = None,
        tail_lines: int = 500,
        previous: bool = False,
        timestamps: bool = True,
        include_events_on_failure: bool = True,
        kubeconfig: Optional[str] = None,
        context: Optional[str] = None,
    ) -> InvestigationReport:
        """
        Directly investigate a live Kubernetes pod using the get_pod_logs tool.

        Args:
            pod_name: Name of the pod to investigate.
            namespace: Kubernetes namespace (default: 'default').
            container: Specific container in pod (optional).
            tail_lines: Number of log lines to retrieve (default: 500).
            previous: If True, fetch previous terminated container logs.
            timestamps: Prepend RFC3339 timestamps.
            include_events_on_failure: Fallback to pod events if container not started.
            kubeconfig: Custom kubeconfig path.
            context: Custom context name.

        Returns:
            InvestigationReport: Post-investigation report with root cause and evidence.
        """
        logs = get_pod_logs(
            pod_name=pod_name,
            namespace=namespace,
            container=container,
            tail_lines=tail_lines,
            previous=previous,
            timestamps=timestamps,
            include_events_on_failure=include_events_on_failure,
            kubeconfig=kubeconfig,
            context=context,
        )
        return self.investigate(logs, source_name=f"pod:{namespace}/{pod_name}")

    def investigate(
        self,
        target: Union[str, Path, io.TextIOBase],
        source_name: Optional[str] = None,
        namespace: str = "default",
        container: Optional[str] = None,
        tail_lines: int = 500,
        previous: bool = False,
        timestamps: bool = True,
    ) -> InvestigationReport:
        """
        Investigate logs. If 'target' is a pod name, it automatically calls get_pod_logs.
        Also accepts log strings or existing file paths.

        Args:
            target: Pod name, log string, file path, or open stream.
            source_name: Descriptive name of the log source.
            namespace: Namespace to use if target is a pod name.
            container: Container name if target is a pod name.
            tail_lines: Lines to fetch if target is a pod name.
            previous: Fetch previous container logs if target is a pod name.
            timestamps: Fetch timestamps if target is a pod name.

        Returns:
            InvestigationReport: Comprehensive post-investigation report.
        """
        raw_text, inferred_source = self._read_input(
            target,
            namespace=namespace,
            container=container,
            tail_lines=tail_lines,
            previous=previous,
            timestamps=timestamps,
        )
        effective_source = source_name or inferred_source or "kubernetes-logs"

        # 1. Parse log stream into structured entries
        entries = self.parser.parse(raw_text)

        # 2. Run Root Cause Analysis and Evidence Extraction
        report = self.rca_engine.analyze(entries, source_name=effective_source)

        # 3. Optional LLM Synthesis
        if self.use_llm and self.llm_provider and self.llm_provider.is_available:
            prompt = ContextBuilder.build_sre_prompt(report)
            insights = self.llm_provider.synthesize_insights(prompt)
            if insights:
                report.llm_insights = insights
                report.llm_enhanced = True

        return report

    def _read_input(
        self,
        log_input: Union[str, Path, io.TextIOBase],
        namespace: str = "default",
        container: Optional[str] = None,
        tail_lines: int = 500,
        previous: bool = False,
        timestamps: bool = True,
    ) -> tuple[str, Optional[str]]:
        """Resolve log_input into text and source name, using get_pod_logs when appropriate."""
        if isinstance(log_input, Path):
            return log_input.read_text(encoding="utf-8", errors="replace"), log_input.name

        if isinstance(log_input, io.TextIOBase):
            name = getattr(log_input, "name", "stream")
            return log_input.read(), name

        if isinstance(log_input, str):
            # If empty or whitespace
            if not log_input.strip():
                return "", "empty-input"

            # Check if it contains newlines -> it's a raw log string
            if "\n" in log_input:
                return log_input, "raw-text-stream"

            # Check if it is an existing local file
            if len(log_input) < 512:
                path = Path(log_input)
                if path.exists() and path.is_file():
                    return path.read_text(encoding="utf-8", errors="replace"), path.name

            # Otherwise, treat log_input as a Kubernetes Pod name and fetch logs using get_pod_logs
            pod_name = log_input.strip()
            logs = get_pod_logs(
                pod_name=pod_name,
                namespace=namespace,
                container=container,
                tail_lines=tail_lines,
                previous=previous,
                timestamps=timestamps,
            )
            return logs, f"pod:{namespace}/{pod_name}"

        raise ValueError(f"Unsupported log input type: {type(log_input)}")
