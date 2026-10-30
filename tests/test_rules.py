from k8s_agent.analyzer.rules import (
    OOMRule,
    CrashLoopRule,
    ProbeRule,
    NetworkDnsRule,
    ImagePullRule,
    StorageRule,
    ConfigSecretRule,
    RbacRule,
)
from k8s_agent.models.failure_modes import FailureCategory, Severity
from k8s_agent.models.log_entry import LogEntry, LogLevel


def test_oom_rule():
    rule = OOMRule()
    entry = LogEntry(
        line_number=42,
        raw="2026-10-29T10:00:00Z command terminated with exit code 137",
        message="command terminated with exit code 137",
        level=LogLevel.ERROR,
    )
    evidence = rule.evaluate(entry)
    assert len(evidence) >= 1
    assert evidence[0].failure_category == FailureCategory.OOM_KILLED
    assert evidence[0].is_smoking_gun is True

    rc = rule.synthesize_root_cause(evidence)
    assert rc.category == FailureCategory.OOM_KILLED
    assert rc.confidence_percent >= 90


def test_network_dns_rule():
    rule = NetworkDnsRule()
    entry = LogEntry(
        line_number=10,
        raw="dial tcp 10.96.0.10:53: i/o timeout",
        message="dial tcp 10.96.0.10:53: i/o timeout",
        level=LogLevel.ERROR,
    )
    evidence = rule.evaluate(entry)
    assert len(evidence) >= 1
    assert evidence[0].failure_category == FailureCategory.NETWORK_DNS_FAILURE


def test_rbac_rule():
    rule = RbacRule()
    entry = LogEntry(
        line_number=8,
        raw='403 Forbidden: is forbidden: User "system:serviceaccount:default:my-sa" cannot list resource "pods"',
        message='403 Forbidden: is forbidden: User "system:serviceaccount:default:my-sa" cannot list resource "pods"',
        level=LogLevel.ERROR,
    )
    evidence = rule.evaluate(entry)
    assert len(evidence) >= 1
    assert evidence[0].failure_category == FailureCategory.RBAC_PERMISSION_FAILURE
    assert evidence[0].is_smoking_gun is True


def test_image_pull_rule():
    rule = ImagePullRule()
    entry = LogEntry(
        line_number=12,
        raw="Failed to pull image: manifest for my-registry/app:v1 not found",
        message="Failed to pull image: manifest for my-registry/app:v1 not found",
        level=LogLevel.ERROR,
    )
    evidence = rule.evaluate(entry)
    assert len(evidence) >= 1
    assert evidence[0].failure_category == FailureCategory.IMAGE_PULL_FAILURE
