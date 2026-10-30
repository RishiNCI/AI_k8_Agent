# 🛡️ Kubernetes Investigation Agent (`k8s_agent`)

An autonomous Kubernetes log investigation agent written in Python. It ingests container stdout/stderr, `kubectl logs`, and Kubernetes event streams, investigates system and application failures, reconstructs incident timelines, isolates root causes from cascading secondary symptoms, and produces detailed post-investigation reports with cited **supporting evidence** and actionable remediation plans.

---

## 🚀 Key Capabilities

- **Multi-Format Log Ingestion**:
  - `kubectl logs -n <ns> <pod>` with RFC3339/ISO8601 nanosecond timestamps.
  - Container runtime outputs (containerd / CRI-O `stdout F` / `stderr F`).
  - Structured JSON application logs (Zap, Logrus, Pino, Winston).
  - Kubernetes cluster events (`kubectl describe` / `kubectl get events`).
  - Multi-line stack traces (Python tracebacks, Java OutOfMemory/NullPointer, Go panics, Node.js).

- **Causality & Cascading Failure Correlation**:
  - Differentiates between the **Primary Root Cause** (e.g. CoreDNS resolution timeout) and **Secondary Cascading Failures** (e.g. Readiness probe 500 $\rightarrow$ Liveness probe failure $\rightarrow$ Pod restart $\rightarrow$ CrashLoopBackOff).
  - Causality hierarchy prevents common pitfalls where diagnostic tools mistakenly label symptoms (like CrashLoopBackOff) as the root cause.

- **Definitive Supporting Evidence Citation**:
  - Pinpoints the exact line numbers and timestamps of every smoking-gun log artifact.
  - Extracts multi-line surrounding context windows for instant human verification.
  - Cites matched trigger regex patterns and diagnostic explanations.

- **Actionable Remediation Plans**:
  - Organized by **Immediate Mitigation**, **Diagnostic Verification**, and **Long-Term Prevention**.
  - Provides copy-pasteable `kubectl` commands tailored to the diagnosed failure.

- **Pluggable Architecture**:
  - **Zero-Dependency Offline Mode**: High-performance deterministic expert rule engine works immediately out of the box without requiring API keys or external networks.
  - **Optional Agentic AI Enhancement**: Integrates with Google Gemini via `google-genai` SDK to synthesize principal SRE post-mortem narratives when configured.

---

## 📦 Supported Kubernetes Failure Taxonomy

| Failure Mode | Detected Signatures | Root Cause Isolation |
|---|---|---|
| **OOMKilled** | Exit code 137, cgroup OOM killer, JVM `OutOfMemoryError`, Go out of memory, V8 heap limit | Differentiates runtime heap limits from container cgroup boundaries |
| **CrashLoopBackOff** | Exit codes > 0, `SIGSEGV`, `Back-off restarting failed container`, missing binary | Traps startup panics, entrypoint bugs, and unhandled crashes |
| **ImagePullBackOff** | `ErrImagePull`, `manifest unknown (404)`, `401 unauthorized`, DockerHub rate limits | Distinguishes typo in image tag vs missing `imagePullSecrets` |
| **Probe Failures** | Liveness/Readiness HTTP 5xx, port connection refused, probe timeouts | Maps health check drops to downstream dependency outages |
| **Network & DNS** | CoreDNS `NXDOMAIN`/`SERVFAIL`, `dial tcp i/o timeout`, `ECONNRESET`, no route to host | Correlates DNS failures upstream of application database errors |
| **Storage & Mounts** | `FailedMount`, `MountVolume.SetUp failed`, `DiskPressure`, PVC not found | Flags unbounded PVCs and disk quota exhaustions |
| **Config & Secrets** | `CreateContainerConfigError`, `secret/configmap not found`, missing env `KeyError` | Catches missing deployment dependencies before container runs |
| **RBAC Authorization** | `403 Forbidden`, `cannot get/list/watch resource` for `system:serviceaccount` | Tests missing verbs and resources via `kubectl auth can-i` |
| **Resource Starvation** | Connection pool timeouts (HikariPool), DB lock acquisition deadlock, `EMFILE` | Identifies connection leaks and file descriptor starvation |

---

## 🛠️ Quickstart Installation

```bash
# Clone and enter the repository
cd /root/AI-K8-Agent

# Activate the virtual environment
source .venv/bin/activate

# Install the agent in editable mode with development dependencies
pip install -e ".[llm,dev]"
```

---

## 💻 CLI Usage

The agent installs a CLI binary `k8s-investigate` and can also be invoked as `python -m k8s_agent`.

### 1. Investigate a Live Kubernetes Pod (Uses `get_pod_logs` tool)
Target a live pod name directly:
```bash
# Target pod in default namespace
k8s-investigate payment-service-789bc

# Target pod in specific namespace and container
k8s-investigate order-api-89k -n production -c app

# Fetch logs from previously terminated/crashed instance
k8s-investigate checkout-service-xyz --previous -n default
```

### 2. Investigate a Log File (Fallback / Offline Mode)
```bash
k8s-investigate examples/oom_killed.log
```

### 3. Generate a Markdown Report
```bash
k8s-investigate payment-service-789bc -n production --format markdown -o incident-report.md
```

### 4. Direct tool usage via Python API
```python
from k8s_agent import get_pod_logs, KubernetesInvestigator

# Standalone tool: fetch pod logs
logs = get_pod_logs("payment-service-pod", namespace="prod", tail_lines=200)

# Autonomous Agent: fetches logs via get_pod_logs and runs investigation
investigator = KubernetesInvestigator()
report = investigator.investigate_pod("payment-service-pod", namespace="prod")
print(report.to_markdown())
```
k8s-investigate examples/complex_cascading_failure.log --format markdown -o incident-report.md
```

### 3. Piping Logs from `kubectl` (or Stdin)
```bash
kubectl logs -n prod payment-service-789 --tail=500 | k8s-investigate -
```
Or for JSON output:
```bash
cat examples/image_pull_backoff.log | k8s-investigate - --format json
```

### 4. Enable Agentic AI Synthesis (Optional)
To have Gemini generate an executive SRE post-mortem narrative on top of the deterministic evidence:
```bash
export GEMINI_API_KEY="your-api-key"
k8s-investigate examples/oom_killed.log --use-llm
```

---

## 🐍 Python Library API Usage

You can embed the investigation agent directly into automated Slack bots, CI/CD pipelines, or Prometheus alert handlers:

```python
from k8s_agent import KubernetesInvestigator

# Instantiate agent
investigator = KubernetesInvestigator()

# Sample Kubernetes log stream
log_stream = """
2026-10-29T14:12:30.450Z ERROR app.db - Failed to connect: lookup postgres-cluster.db.svc: i/o timeout
2026-10-29T14:12:42.000Z Warning  Unhealthy  10s  kubelet  Readiness probe failed: HTTP probe failed with statuscode: 500
2026-10-29T14:12:55.000Z Warning  Unhealthy  1s   kubelet  Liveness probe failed: HTTP probe failed with statuscode: 500
2026-10-29T14:13:00.000Z Warning  BackOff    2s   kubelet  Back-off restarting failed container
"""

# Run investigation
report = investigator.investigate(log_stream, source_name="payment-service")

# Access Root Cause Analysis
print("Primary Cause:", report.primary_root_cause.title)
print("Confidence:", f"{report.primary_root_cause.confidence_percent}%")

# Iterate Supporting Evidence
for ev in report.evidence:
    print(f"Line {ev.line_number} [{ev.failure_category.value}]: {ev.explanation}")

# Export to Markdown or JSON
markdown_report = report.to_markdown()
json_report = report.to_json()
```

Run the included example script:
```bash
python example_usage.py
```

---

## 📋 Sample Investigation Output

Below is an excerpt of a generated investigation report:

```markdown
# 🛡️ Kubernetes Investigation Report: `INC-9B025D32`
**Target:** `payment-gateway.log`
**Log Volume:** 10 lines | 🚨 Errors: 3 | ⚠️ Warnings: 4

## 📌 Executive Summary
Investigation analyzed 10 log entries and identified **DNS Resolution Failure (CoreDNS / Service Discovery)** as the primary root cause with 95% confidence. This subsequently triggered secondary failures in `Readiness / Liveness Probe Failure`, `CrashLoopBackOff`. A total of 8 supporting evidence artifacts were extracted.

## 🎯 Root Cause Analysis
### **[HIGH]** DNS Resolution Failure (CoreDNS / Service Discovery) (95% Confidence)
**Category:** `Network / DNS Resolution Failure`
**Description:** Inter-service network connectivity failed. Application calls are failing due to unresolvable DNS names.
**Impact:** Downstream requests fail; upstream user calls return 500 or 504 Gateway Timeout.

### 🔗 Cascading / Secondary Failures
- **Liveness Probe Failure: Container Restarts Triggered** (`Readiness / Liveness Probe Failure`)
- **CrashLoopBackOff: Repeated Container Initialization Failure** (`CrashLoopBackOff`)

## 🔍 Supporting Evidence
Found 8 key evidence items:
#### Evidence #1: Line 3 [Network / DNS Resolution Failure] 💥 Smoking Gun Evidence
- **Timestamp:** `2026-10-29T14:12:30.450Z`
- **Trigger Pattern:** `lookup\s+[a-zA-Z0-9_\-\.]+:\s*i/o timeout`
- **Analysis:** DNS lookup failed: unable to resolve cluster domain name via CoreDNS
```log
>>> app.db - Failed to connect to database: lookup postgres-cluster.db.svc.cluster.local: i/o timeout
```
```

---

## 🧪 Test Suite

Run the full pytest suite:
```bash
pytest -v tests/
```
All 17 test cases cover:
- Multi-line stack trace stitching & RFC3339/JSON timestamp parsing
- Specialized failure detection rules (OOM, Probes, DNS, Storage, Config, RBAC, Deadlocks)
- Temporal correlation & causality priority arbitration
- CLI flags, stdin piping, and Markdown/JSON report generation.
