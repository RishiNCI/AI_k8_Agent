"""Tool to fetch logs from a specific Kubernetes pod using kubectl."""

import logging
import os
import shutil
import subprocess
from typing import Dict, Optional, Tuple
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

# In-memory registry for mock pod logs (used during testing or offline development)
_MOCK_POD_LOGS: Dict[Tuple[str, str], str] = {}


def register_mock_pod_logs(pod_name: str, logs: str, namespace: str = "default") -> None:
    """Register mock logs for a specific pod name and namespace (useful for testing)."""
    _MOCK_POD_LOGS[(pod_name, namespace)] = logs


def clear_mock_pod_logs() -> None:
    """Clear all registered mock pod logs."""
    _MOCK_POD_LOGS.clear()


class PodLogFetchResult(BaseModel):
    pod_name: str
    namespace: str
    container: Optional[str] = None
    logs: str = ""
    used_previous: bool = False
    included_events: bool = False
    command_executed: str = ""
    success: bool = True
    error_message: Optional[str] = None


class KubernetesToolError(Exception):
    """Raised when fetching pod logs fails."""
    pass


def get_pod_logs(
    pod_name: str,
    namespace: str = "default",
    container: Optional[str] = None,
    tail_lines: int = 500,
    previous: bool = False,
    timestamps: bool = True,
    include_events_on_failure: bool = True,
    kubeconfig: Optional[str] = None,
    context: Optional[str] = None,
    kubectl_path: Optional[str] = None,
    timeout_seconds: int = 30,
) -> str:
    """
    Fetch logs of a specific Kubernetes pod.

    Args:
        pod_name: Name of the pod to fetch logs from.
        namespace: Kubernetes namespace where the pod lives (default: 'default').
        container: Specific container name inside multi-container pod (optional).
        tail_lines: Number of most recent lines to fetch (default: 500).
        previous: If True, fetch logs for previous instance of terminated container.
        timestamps: If True, prepend RFC3339 timestamps to each log line.
        include_events_on_failure: If True, automatically falls back to fetching pod
            events via 'kubectl describe pod' if container has not started yet.
        kubeconfig: Optional path to kubeconfig file.
        context: Optional kubernetes context name.
        kubectl_path: Custom path to kubectl executable if not in PATH.
        timeout_seconds: Timeout for kubectl command in seconds.

    Returns:
        str: Raw log stream from the pod.

    Raises:
        KubernetesToolError: If pod logs cannot be retrieved.
    """
    result = get_pod_logs_detailed(
        pod_name=pod_name,
        namespace=namespace,
        container=container,
        tail_lines=tail_lines,
        previous=previous,
        timestamps=timestamps,
        include_events_on_failure=include_events_on_failure,
        kubeconfig=kubeconfig,
        context=context,
        kubectl_path=kubectl_path,
        timeout_seconds=timeout_seconds,
    )

    if not result.success:
        raise KubernetesToolError(result.error_message or f"Failed to fetch logs for pod {pod_name}")

    return result.logs


def get_pod_logs_detailed(
    pod_name: str,
    namespace: str = "default",
    container: Optional[str] = None,
    tail_lines: int = 500,
    previous: bool = False,
    timestamps: bool = True,
    include_events_on_failure: bool = True,
    kubeconfig: Optional[str] = None,
    context: Optional[str] = None,
    kubectl_path: Optional[str] = None,
    timeout_seconds: int = 30,
) -> PodLogFetchResult:
    """Detailed version returning PodLogFetchResult with metadata."""
    if not pod_name or not pod_name.strip():
        return PodLogFetchResult(
            pod_name="",
            namespace=namespace,
            container=container,
            success=False,
            error_message="Pod name cannot be empty.",
        )

    # 1. Check Mock registry first (for tests or offline simulation)
    mock_key = (pod_name, namespace)
    if mock_key in _MOCK_POD_LOGS:
        return PodLogFetchResult(
            pod_name=pod_name,
            namespace=namespace,
            container=container,
            logs=_MOCK_POD_LOGS[mock_key],
            command_executed=f"mock: kubectl logs {pod_name} -n {namespace}",
            success=True,
        )

    # Check environment variable for mock pod logs (enables mock testing across subprocesses)
    if os.environ.get("K8S_MOCK_POD_NAME") == pod_name:
        mock_data = os.environ.get("K8S_MOCK_LOGS_DATA", "")
        return PodLogFetchResult(
            pod_name=pod_name,
            namespace=namespace,
            container=container,
            logs=mock_data,
            command_executed=f"env_mock: kubectl logs {pod_name} -n {namespace}",
            success=True,
        )

    mock_dir = os.environ.get("K8S_MOCK_LOGS_DIR")
    if mock_dir and os.path.isdir(mock_dir):
        for candidate in [f"{namespace}_{pod_name}.log", f"{pod_name}.log"]:
            fpath = os.path.join(mock_dir, candidate)
            if os.path.isfile(fpath):
                with open(fpath, "r", encoding="utf-8") as f:
                    return PodLogFetchResult(
                        pod_name=pod_name,
                        namespace=namespace,
                        container=container,
                        logs=f.read(),
                        command_executed=f"file_mock: {fpath}",
                        success=True,
                    )

    # 2. Locate kubectl binary
    bin_path = kubectl_path or shutil.which("kubectl") or "/usr/local/bin/kubectl"
    if not os.path.exists(bin_path):
        return PodLogFetchResult(
            pod_name=pod_name,
            namespace=namespace,
            container=container,
            success=False,
            error_message=f"kubectl binary not found at '{bin_path}' and not in PATH.",
        )

    # 3. Assemble command
    cmd = [bin_path, "logs", pod_name, "-n", namespace]
    if container:
        cmd.extend(["-c", container])
    if tail_lines and tail_lines > 0:
        cmd.extend(["--tail", str(tail_lines)])
    if previous:
        cmd.append("--previous")
    if timestamps:
        cmd.append("--timestamps")
    if kubeconfig:
        cmd.extend(["--kubeconfig", kubeconfig])
    if context:
        cmd.extend(["--context", context])

    cmd_str = " ".join(cmd)

    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
        )
    except subprocess.TimeoutExpired:
        return PodLogFetchResult(
            pod_name=pod_name,
            namespace=namespace,
            container=container,
            command_executed=cmd_str,
            success=False,
            error_message=f"Command timed out after {timeout_seconds}s: {cmd_str}",
        )
    except Exception as e:
        return PodLogFetchResult(
            pod_name=pod_name,
            namespace=namespace,
            container=container,
            command_executed=cmd_str,
            success=False,
            error_message=f"Execution error running {cmd_str}: {str(e)}",
        )

    # If successful and logs returned
    if proc.returncode == 0:
        logs_output = proc.stdout
        # If output is empty and previous was not requested, try previous automatically
        if not logs_output.strip() and not previous:
            prev_result = _try_fetch_previous(
                bin_path=bin_path,
                pod_name=pod_name,
                namespace=namespace,
                container=container,
                tail_lines=tail_lines,
                timestamps=timestamps,
                kubeconfig=kubeconfig,
                context=context,
                timeout=timeout_seconds,
            )
            if prev_result and prev_result.strip():
                return PodLogFetchResult(
                    pod_name=pod_name,
                    namespace=namespace,
                    container=container,
                    logs=prev_result,
                    used_previous=True,
                    command_executed=cmd_str + " --previous",
                    success=True,
                )

        return PodLogFetchResult(
            pod_name=pod_name,
            namespace=namespace,
            container=container,
            logs=logs_output,
            command_executed=cmd_str,
            success=True,
        )

    # 4. Handle Failure Cases (e.g. ContainerCreating, ImagePullBackOff, CrashLoopBackOff)
    stderr_output = proc.stderr.strip()

    # If container previously terminated, try --previous automatically
    if "previous terminated container" in stderr_output.lower() and not previous:
        prev_logs = _try_fetch_previous(
            bin_path=bin_path,
            pod_name=pod_name,
            namespace=namespace,
            container=container,
            tail_lines=tail_lines,
            timestamps=timestamps,
            kubeconfig=kubeconfig,
            context=context,
            timeout=timeout_seconds,
        )
        if prev_logs:
            return PodLogFetchResult(
                pod_name=pod_name,
                namespace=namespace,
                container=container,
                logs=prev_logs,
                used_previous=True,
                command_executed=cmd_str + " --previous",
                success=True,
            )

    # If pod is waiting to start or container not ready, fallback to describe pod events
    is_waiting = any(
        phrase in stderr_output.lower()
        for phrase in [
            "waiting to start",
            "containercreating",
            "imagepullbackoff",
            "errimagepull",
            "crashloopbackoff",
        ]
    )

    if is_waiting and include_events_on_failure:
        events_logs = _fetch_pod_describe_events(
            bin_path=bin_path,
            pod_name=pod_name,
            namespace=namespace,
            kubeconfig=kubeconfig,
            context=context,
            timeout=timeout_seconds,
        )
        if events_logs:
            combined_logs = (
                f"# Log fetch notice: Container was not ready ({stderr_output})\n"
                f"# Auto-retrieved Kubernetes Pod Events via 'kubectl describe pod {pod_name} -n {namespace}':\n"
                f"{events_logs}"
            )
            return PodLogFetchResult(
                pod_name=pod_name,
                namespace=namespace,
                container=container,
                logs=combined_logs,
                included_events=True,
                command_executed=f"kubectl describe pod {pod_name} -n {namespace}",
                success=True,
            )

    return PodLogFetchResult(
        pod_name=pod_name,
        namespace=namespace,
        container=container,
        logs=stderr_output,
        command_executed=cmd_str,
        success=False,
        error_message=f"kubectl logs failed with code {proc.returncode}: {stderr_output}",
    )


def _try_fetch_previous(
    bin_path: str,
    pod_name: str,
    namespace: str,
    container: Optional[str],
    tail_lines: int,
    timestamps: bool,
    kubeconfig: Optional[str],
    context: Optional[str],
    timeout: int,
) -> Optional[str]:
    """Helper to query logs from the previous container instance."""
    cmd = [bin_path, "logs", pod_name, "-n", namespace, "--previous"]
    if container:
        cmd.extend(["-c", container])
    if tail_lines:
        cmd.extend(["--tail", str(tail_lines)])
    if timestamps:
        cmd.append("--timestamps")
    if kubeconfig:
        cmd.extend(["--kubeconfig", kubeconfig])
    if context:
        cmd.extend(["--context", context])

    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        if proc.returncode == 0 and proc.stdout.strip():
            return proc.stdout
    except Exception:
        pass
    return None


def _fetch_pod_describe_events(
    bin_path: str,
    pod_name: str,
    namespace: str,
    kubeconfig: Optional[str],
    context: Optional[str],
    timeout: int,
) -> Optional[str]:
    """Helper to fetch pod events using kubectl describe pod."""
    cmd = [bin_path, "describe", "pod", pod_name, "-n", namespace]
    if kubeconfig:
        cmd.extend(["--kubeconfig", kubeconfig])
    if context:
        cmd.extend(["--context", context])

    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        if proc.returncode == 0 and proc.stdout.strip():
            # Extract the Events table section
            text = proc.stdout
            if "Events:" in text:
                return text[text.index("Events:"):]
            return text
    except Exception:
        pass
    return None
