"""Failure categories and severity definitions for Kubernetes log investigation."""

from enum import Enum
from typing import Dict, List, Optional
from pydantic import BaseModel, Field


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

    @property
    def badge_color(self) -> str:
        colors = {
            "CRITICAL": "red",
            "HIGH": "bright_red",
            "MEDIUM": "yellow",
            "LOW": "blue",
            "INFO": "green",
        }
        return colors.get(self.value, "white")


class FailureCategory(str, Enum):
    OOM_KILLED = "OOMKilled"
    CRASH_LOOP_BACKOFF = "CrashLoopBackOff"
    IMAGE_PULL_FAILURE = "ImagePullBackOff / ErrImagePull"
    PROBE_FAILURE = "Readiness / Liveness Probe Failure"
    NETWORK_DNS_FAILURE = "Network / DNS Resolution Failure"
    STORAGE_VOLUME_FAILURE = "Storage / Volume Mount Failure"
    CONFIG_SECRET_FAILURE = "ConfigMap / Secret Missing or Invalid"
    RBAC_PERMISSION_FAILURE = "RBAC / API Authorization Failure"
    RESOURCE_STARVATION_DEADLOCK = "Resource Starvation / Pool Exhaustion"
    APPLICATION_PANIC = "Application Panic / Unhandled Exception"
    UNKNOWN = "Unclassified Anomaly"


class FailureProfile(BaseModel):
    category: FailureCategory
    default_severity: Severity
    description: str
    typical_symptoms: List[str] = Field(default_factory=list)
    common_root_causes: List[str] = Field(default_factory=list)
    default_commands: List[str] = Field(default_factory=list)


FAILURE_PROFILES: Dict[FailureCategory, FailureProfile] = {
    FailureCategory.OOM_KILLED: FailureProfile(
        category=FailureCategory.OOM_KILLED,
        default_severity=Severity.CRITICAL,
        description="The container process was terminated by Linux kernel OOM-killer (exit code 137) or JVM OutOfMemoryError.",
        typical_symptoms=[
            "Container terminated with exit code 137",
            "cgroup out of memory: Killed process",
            "java.lang.OutOfMemoryError: Java heap space",
            "Memory cgroup out of memory",
        ],
        common_root_causes=[
            "Pod memory limit in spec.containers[].resources.limits.memory is set too low",
            "Application memory leak (unreleased buffers, growing caches)",
            "Bursty request load spiking memory consumption",
            "JVM heap configuration (-Xmx) exceeds container memory limit",
        ],
        default_commands=[
            "kubectl top pod <pod-name> -n <namespace> --containers",
            "kubectl describe pod <pod-name> -n <namespace> | grep -E 'OOMKilled|Limits|Requests|Last State'",
            "kubectl get events -n <namespace> --field-selector reason=OOMKilling",
        ],
    ),
    FailureCategory.CRASH_LOOP_BACKOFF: FailureProfile(
        category=FailureCategory.CRASH_LOOP_BACKOFF,
        default_severity=Severity.CRITICAL,
        description="Container is repeatedly terminating immediately after startup and entering Kubernetes exponential backoff.",
        typical_symptoms=[
            "Back-off restarting failed container",
            "Process exited with status 1 or non-zero exit code",
            "Fatal application exception during startup initialization",
        ],
        common_root_causes=[
            "Missing environment variable, configuration file, or secret",
            "Database/downstream dependency unreachable during init",
            "Invalid command or entrypoint arguments in Pod spec",
            "Missing binary or dependency in container filesystem",
        ],
        default_commands=[
            "kubectl logs <pod-name> -n <namespace> --previous",
            "kubectl describe pod <pod-name> -n <namespace>",
            "kubectl get pod <pod-name> -n <namespace> -o jsonpath='{.status.containerStatuses[*].state.waiting.message}'",
        ],
    ),
    FailureCategory.IMAGE_PULL_FAILURE: FailureProfile(
        category=FailureCategory.IMAGE_PULL_FAILURE,
        default_severity=Severity.HIGH,
        description="Kubernetes kubelet cannot fetch the container image from the container registry.",
        typical_symptoms=[
            "Failed to pull image: rpc error: code = NotFound",
            "ImagePullBackOff",
            "ErrImagePull",
            "unauthorized: authentication required",
            "toomanyrequests: You have reached your pull rate limit",
        ],
        common_root_causes=[
            "Typo in image tag or repository name",
            "Missing or expired imagePullSecrets for private registry",
            "Registry network endpoint unreachable or rate limited (e.g. Docker Hub)",
        ],
        default_commands=[
            "kubectl describe pod <pod-name> -n <namespace> | grep -A 5 -B 2 'Events:'",
            "kubectl get secrets -n <namespace> | grep -E 'dockercfg|dockerconfigjson'",
        ],
    ),
    FailureCategory.PROBE_FAILURE: FailureProfile(
        category=FailureCategory.PROBE_FAILURE,
        default_severity=Severity.HIGH,
        description="Liveness, readiness, or startup probe failed, causing Pod to be removed from Service endpoints or restarted.",
        typical_symptoms=[
            "Readiness probe failed: HTTP probe failed with statuscode: 500",
            "Liveness probe failed: dial tcp 10.x.x.x:8080: connect: connection refused",
            "Probe timed out after 1.000s",
        ],
        common_root_causes=[
            "Application startup latency exceeds startupProbe / initialDelaySeconds",
            "Dependency failure causing healthcheck endpoint (/health, /readyz) to return 5xx",
            "Probe timeout threshold is too aggressive for under-load responses",
            "Wrong port or path configured in probe definition",
        ],
        default_commands=[
            "kubectl describe pod <pod-name> -n <namespace> | grep -E 'Liveness|Readiness|Startup'",
            "kubectl get endpoints <service-name> -n <namespace>",
        ],
    ),
    FailureCategory.NETWORK_DNS_FAILURE: FailureProfile(
        category=FailureCategory.NETWORK_DNS_FAILURE,
        default_severity=Severity.HIGH,
        description="Network connection or CoreDNS domain name resolution failed.",
        typical_symptoms=[
            "no such host / lookup failed: NXDOMAIN",
            "dial tcp i/o timeout",
            "connection refused",
            "CoreDNS timeout after 5 seconds",
            "read: connection reset by peer",
        ],
        common_root_causes=[
            "CoreDNS pods overloaded or crashing in kube-system",
            "Kubernetes NetworkPolicy blocking ingress or egress traffic",
            "Incorrect service name or namespace in database connection URL",
            "Node conntrack table exhaustion or kube-proxy iptables sync failure",
        ],
        default_commands=[
            "kubectl get pods -n kube-system -l k8s-app=kube-dns",
            "kubectl logs -n kube-system -l k8s-app=kube-dns --tail=100",
            "kubectl get networkpolicies -n <namespace>",
        ],
    ),
    FailureCategory.STORAGE_VOLUME_FAILURE: FailureProfile(
        category=FailureCategory.STORAGE_VOLUME_FAILURE,
        default_severity=Severity.HIGH,
        description="Storage volume attachment, mounting, or disk quota failure.",
        typical_symptoms=[
            "MountVolume.SetUp failed for volume",
            "no space left on device",
            "Read-only file system",
            "volume is already attached to another node",
        ],
        common_root_causes=[
            "PersistentVolumeClaim (PVC) not bound or storage class misconfigured",
            "Node disk is full (DiskPressure condition)",
            "ReadWriteOnce PVC attached to a pod on a different node",
        ],
        default_commands=[
            "kubectl describe pvc -n <namespace>",
            "kubectl get events -n <namespace> --field-selector reason=FailedMount",
            "kubectl describe node <node-name> | grep -A 5 Conditions",
        ],
    ),
    FailureCategory.CONFIG_SECRET_FAILURE: FailureProfile(
        category=FailureCategory.CONFIG_SECRET_FAILURE,
        default_severity=Severity.HIGH,
        description="Missing, malformed, or unmounted ConfigMap or Secret referenced by container spec.",
        typical_symptoms=[
            "configmaps 'app-config' not found",
            "secrets 'app-secrets' not found",
            "KeyError / missing environment variable",
            "error parsing configuration YAML/JSON",
        ],
        common_root_causes=[
            "ConfigMap or Secret not created prior to Pod deployment",
            "Specified key does not exist inside the ConfigMap/Secret",
            "Syntax error in configuration file mounted into container",
        ],
        default_commands=[
            "kubectl get configmaps,secrets -n <namespace>",
            "kubectl describe pod <pod-name> -n <namespace> | grep -E 'Environment|Mounts' -A 10",
        ],
    ),
    FailureCategory.RBAC_PERMISSION_FAILURE: FailureProfile(
        category=FailureCategory.RBAC_PERMISSION_FAILURE,
        default_severity=Severity.MEDIUM,
        description="Container ServiceAccount lacks necessary RBAC permissions against Kubernetes API server.",
        typical_symptoms=[
            "403 Forbidden: User system:serviceaccount cannot list resource",
            "User unauthorized to perform action",
        ],
        common_root_causes=[
            "Pod is using 'default' ServiceAccount without required Role/ClusterRole",
            "RoleBinding or ClusterRoleBinding missing for the target namespace/resource",
        ],
        default_commands=[
            "kubectl auth can-i <verb> <resource> --as=system:serviceaccount:<namespace>:<serviceaccount>",
            "kubectl get rolebindings,clusterrolebindings -n <namespace>",
        ],
    ),
    FailureCategory.RESOURCE_STARVATION_DEADLOCK: FailureProfile(
        category=FailureCategory.RESOURCE_STARVATION_DEADLOCK,
        default_severity=Severity.HIGH,
        description="Application thread pool starvation, database connection pool exhaustion, or CPU throttling.",
        typical_symptoms=[
            "Connection pool exhausted / HikariPool timeout",
            "Deadlock detected",
            "Thread pool saturated: queue is full",
            "CPU throttling detected: container throttled",
        ],
        common_root_causes=[
            "Database connection leak or undersized connection pool (max_connections)",
            "Aggressive CPU limit causing CFS throttling and slow event loops",
            "Unindexed slow queries tying up worker threads",
        ],
        default_commands=[
            "kubectl top pod <pod-name> -n <namespace>",
            "kubectl describe pod <pod-name> -n <namespace> | grep -A 5 Limits",
        ],
    ),
    FailureCategory.APPLICATION_PANIC: FailureProfile(
        category=FailureCategory.APPLICATION_PANIC,
        default_severity=Severity.HIGH,
        description="Internal application bug, unhandled exception, or language runtime panic.",
        typical_symptoms=[
            "panic: runtime error",
            "Traceback (most recent call last):",
            "NullPointerException",
            "Segmentation fault (core dumped)",
        ],
        common_root_causes=[
            "Unhandled runtime exception in application code",
            "Incompatible library dependency or corrupt binary",
            "Unchecked nil/null pointer dereference",
        ],
        default_commands=[
            "kubectl logs <pod-name> -n <namespace> --tail=200",
        ],
    ),
    FailureCategory.UNKNOWN: FailureProfile(
        category=FailureCategory.UNKNOWN,
        default_severity=Severity.MEDIUM,
        description="Unclassified error pattern or generic log anomalies.",
        typical_symptoms=["Error observed in log stream"],
        common_root_causes=["Unknown - requires manual inspection"],
        default_commands=["kubectl logs <pod-name> -n <namespace> --tail=200"],
    ),
}
