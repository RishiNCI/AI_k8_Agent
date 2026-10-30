# 📖 How-To-Use Guide: Kubernetes Investigation Agent

Welcome to the **Kubernetes Investigation Agent** (`k8s_agent`) user guide.

This guide provides step-by-step instructions on:
1. [Prerequisites & Environment Setup](#1-prerequisites--environment-setup)
2. [Using the `get_pod_logs` Tool Standalone](#2-using-the-get_pod_logs-tool-standalone)
3. [Investigating Live Pods with the CLI](#3-investigating-live-pods-with-the-cli)
4. [Using the Agent Programmatically in Python](#4-using-the-agent-programmatically-in-python)
5. [Special Scenarios (Crashed Containers, Pending Pods, Multi-Container)](#5-special-scenarios)
6. [Enabling AI SRE Synthesis (Gemini)](#6-enabling-ai-sre-synthesis-gemini)
7. [Testing Locally Without a Cluster (Mock Mode)](#7-testing-locally-without-a-cluster-mock-mode)
8. [Interpreting the Investigation Report](#8-interpreting-the-investigation-report)

---

## 1. Prerequisites & Environment Setup

### System Requirements
- Python 3.10+
- `kubectl` installed and configured to connect to your Kubernetes cluster.

### Setup Steps
```bash
# 1. Navigate to the agent directory
cd /root/AI-K8-Agent

# 2. Activate the pre-configured virtual environment
source .venv/bin/activate

# 3. Verify the CLI is available
k8s-investigate --version
# Output: k8s-investigate 0.2.0
```

---

## 2. Using the `get_pod_logs` Tool Standalone

The `get_pod_logs` tool fetches logs from a Kubernetes pod with built-in resilience (automatic recovery of previous container logs and fallback to pod events if the container has not started yet).

### Python Usage
```python
from k8s_agent import get_pod_logs, get_pod_logs_detailed

# Basic usage: fetch 100 most recent lines with timestamps
logs = get_pod_logs(
    pod_name="payment-service-789bc",
    namespace="production",
    tail_lines=100,
)
print(logs)

# Advanced usage: fetch detailed metadata
result = get_pod_logs_detailed(
    pod_name="payment-service-789bc",
    namespace="production",
    container="web",
    previous=True,        # Fetch logs from previous crashed instance
    timestamps=True,      # Prepend RFC3339 timestamps
)

print(f"Command run: {result.command_executed}")
print(f"Success    : {result.success}")
print(f"Logs length: {len(result.logs.splitlines())} lines")
```

---

## 3. Investigating Live Pods with the CLI

The `k8s-investigate` command directly invokes the `get_pod_logs` tool, parses the logs, isolates root causes, and presents the findings.

### Example 1: Basic Investigation (Interactive Terminal UI)
```bash
k8s-investigate payment-service-789bc
```
By default, this targets the `default` namespace.

### Example 2: Target a Specific Namespace and Container
```bash
k8s-investigate order-api-89k -n production -c app
```

### Example 3: Investigate a Crashed / Restarting Pod (`--previous`)
If a pod keeps restarting in `CrashLoopBackOff`, the current container instance may be empty or newly restarted. Use `--previous` to pull logs from the instance that actually crashed:
```bash
k8s-investigate checkout-service-xyz -n production --previous
```

### Example 4: Export to GitHub-Flavored Markdown for Slack or Tickets
```bash
# Print to terminal
k8s-investigate payment-service-789bc -n production --format markdown

# Save directly to a file
k8s-investigate payment-service-789bc -n production --format markdown -o incident-report.md
```

### Example 5: Output JSON for Automation or Alert Pipelines
```bash
k8s-investigate payment-service-789bc -n production --format json
```

### Example 6: Fallback to Local Log Files or Stdin Pipe
If you already have a log file or want to pipe from an external tool:
```bash
# Investigate a log file
k8s-investigate examples/oom_killed.log

# Pipe directly from stdin
kubectl logs payment-service-789bc -n production | k8s-investigate -
```

---

## 4. Using the Agent Programmatically in Python

You can embed the investigation agent into automated Slack bots, CI/CD pipelines, or incident webhook listeners.

### Complete Example Script
```python
from k8s_agent import KubernetesInvestigator

# 1. Initialize the agent
investigator = KubernetesInvestigator()

# 2. Investigate a live pod (agent automatically uses get_pod_logs)
report = investigator.investigate_pod(
    pod_name="payment-gateway-7b64-x92j",
    namespace="production",
    tail_lines=300,
    previous=False,
)

# 3. Access Executive Summary & Incident Metadata
print(f"Incident ID : {report.incident_id}")
print(f"Target      : {report.source_name}")
print(f"Log Volume  : {report.total_lines_analyzed} lines ({report.error_count} errors)")
print(f"Summary     : {report.executive_summary}\n")

# 4. Access Root Cause Analysis
primary = report.primary_root_cause
print(f"🎯 Root Cause: {primary.title}")
print(f"Confidence  : {primary.confidence_percent}%")
print(f"Severity    : {primary.severity.value}")
print(f"Description : {primary.summary}")
print(f"Impact      : {primary.impact}")

# 5. Access Cascading Secondary Failures
if report.secondary_root_causes:
    print("\n🔗 Cascading Failures:")
    for sec in report.secondary_root_causes:
        print(f"  • {sec.title} ({sec.category.value})")

# 6. Inspect Exact Supporting Evidence
print(f"\n🔍 Supporting Evidence Cited ({len(report.evidence)} items):")
for ev in report.evidence:
    smoking = " [SMOKING GUN]" if ev.is_smoking_gun else ""
    print(f"  • Line {ev.line_number} [{ev.failure_category.value}]{smoking}")
    print(f"    Trigger : {ev.matched_pattern}")
    print(f"    Analysis: {ev.explanation}")
    print(f"    Raw Log : {ev.raw_excerpt}\n")

# 7. Get Actionable Remediation Commands
print("🛠️ Recommended Actions:")
for rem in report.remediations:
    print(f"  [{rem.phase}] {rem.title}")
    if rem.kubectl_command:
        print(f"    $ {rem.kubectl_command}")

# 8. Export to Markdown or JSON strings
markdown_text = report.to_markdown()
json_text = report.to_json()
```

---

## 5. Special Scenarios

### Scenario A: Multi-Container Pods
Pods often contain sidecars (e.g. Istio proxy, Datadog agent, fluentbit). Specify the target container with `-c`:
```bash
k8s-investigate my-pod-xyz -n prod -c main-application
```

### Scenario B: Pods in `ImagePullBackOff` or `ContainerCreating`
When a container fails to start, `kubectl logs` fails with `waiting to start: ContainerCreating` or `ImagePullBackOff`.
The `get_pod_logs` tool **automatically handles this** by falling back to `kubectl describe pod` to extract the Kubernetes Event stream. The agent then diagnoses the image pull failure, bad image tag, or missing secret seamlessly!

### Scenario C: JVM Heap vs Linux Kernel OOM
The agent distinguishes between:
- **JVM Heap Exhaustion**: `-Xmx` limit reached, throwing `java.lang.OutOfMemoryError: Java heap space`.
- **Linux Kernel cgroup Termination**: Pod memory limits exceeded, receiving `exit code 137` from the OS kernel.

---

## 6. Enabling AI SRE Synthesis (Gemini)

The agent runs completely offline by default using its deterministic rule engine. To add an executive SRE post-mortem narrative using Google Gemini:

1. Export your Gemini API key:
   ```bash
   export GEMINI_API_KEY="your-gemini-api-key"
   ```

2. Run with the `--use-llm` flag:
   ```bash
   k8s-investigate payment-service-789bc -n production --use-llm
   ```

---

## 7. Testing Locally Without a Cluster (Mock Mode)

You can test the agent or run automated tests even if no live Kubernetes cluster is currently reachable.

### In Python Code:
Use `register_mock_pod_logs`:
```python
from k8s_agent import KubernetesInvestigator, register_mock_pod_logs

# Register mock log output for a simulated pod
register_mock_pod_logs(
    pod_name="fake-pod-1",
    namespace="demo",
    logs="""
    2026-10-29T10:00:00Z ERROR lookup postgres.db.svc: i/o timeout
    2026-10-29T10:00:10Z Warning Unhealthy Readiness probe failed: HTTP probe failed with statuscode: 500
    2026-10-29T10:00:15Z Warning BackOff Back-off restarting failed container
    """,
)

# The investigator will now use the mock logs for this pod!
investigator = KubernetesInvestigator()
report = investigator.investigate_pod("fake-pod-1", namespace="demo")
print(report.primary_root_cause.title)
# Output: DNS Resolution Failure (CoreDNS / Service Discovery)
```

### In Shell / CLI:
Set `K8S_MOCK_POD_NAME` and `K8S_MOCK_LOGS_DATA`:
```bash
export K8S_MOCK_POD_NAME="demo-pod"
export K8S_MOCK_LOGS_DATA="2026-10-29T10:00:00Z command terminated with exit code 137"

k8s-investigate demo-pod
```

---

## 8. Interpreting the Investigation Report

Every generated report contains:

1. **Header & Log Volume**: Total lines scanned, error counts, warning counts.
2. **Executive Summary**: High-level incident takeaway with confidence rating.
3. **Primary Root Cause**:
   - Title, Category, and Severity badge (`CRITICAL`, `HIGH`, `MEDIUM`).
   - Confidence percentage (e.g. `95%` or `100%`).
   - Detailed systems description & impact summary.
   - Specific contributing factors.
4. **Cascading / Secondary Failures**: Downstream effects triggered by the root cause (e.g. probe timeouts following a database connection loss).
5. **Chronological Timeline**: Step-by-step progression of the failure categorized into phases (*Root Cause Trigger*, *Symptom Manifestation*, *Cascading Impact*).
6. **Supporting Evidence**:
   - Exact line numbers and timestamps.
   - Matched regex trigger patterns.
   - Diagnostic analysis of each line.
   - Syntax-highlighted log excerpt with surrounding context lines.
   - `💥 Smoking Gun Evidence` badge for conclusive indicators (like Exit code 137, missing secrets, or segfaults).
7. **Actionable Remediation Plan**:
   - **Immediate Mitigation**: Actions to stop immediate bleeding (e.g., scale pods, increase memory limits).
   - **Diagnostic Verification**: `kubectl` commands to verify the cluster state.
   - **Long-Term Prevention**: Architectural hardening suggestions.

---

## ❓ Frequently Asked Questions (FAQ)

**Q: Where can I see full demo code?**  
A: Run `/root/AI-K8-Agent/.venv/bin/python example_usage.py` to see a live demonstration of `get_pod_logs` and `investigate_pod`.

**Q: How do I run the automated test suite?**  
A: Run `/root/AI-K8-Agent/.venv/bin/pytest tests` (all 22 unit & integration tests run in under 2 seconds).

**Q: Can I customize log tail length?**  
A: Yes! Use `--tail <number>` in the CLI or `tail_lines=<number>` in Python. Default is 500 lines.
