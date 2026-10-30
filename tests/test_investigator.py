from pathlib import Path
from k8s_agent.agent.investigator import KubernetesInvestigator
from k8s_agent.models.failure_modes import FailureCategory


def test_investigate_oom_log():
    log_path = Path("/root/AI-K8-Agent/examples/oom_killed.log")
    investigator = KubernetesInvestigator()
    report = investigator.investigate(log_path)

    assert report.total_lines_analyzed > 5
    assert report.primary_root_cause is not None
    assert report.primary_root_cause.category == FailureCategory.OOM_KILLED
    assert len(report.evidence) > 0

    # Ensure smoking gun evidence is captured
    assert any(e.is_smoking_gun for e in report.evidence)

    # Test Markdown formatting
    md = report.to_markdown()
    assert "# 🛡️ Kubernetes Investigation Report" in md
    assert "Exit Code 137" in md or "OOMKilled" in md
    assert "## 🔍 Supporting Evidence" in md

    # Test JSON formatting
    js = report.to_json()
    assert '"OOMKilled"' in js


def test_investigate_complex_cascading_log():
    log_path = Path("/root/AI-K8-Agent/examples/complex_cascading_failure.log")
    investigator = KubernetesInvestigator()
    report = investigator.investigate(log_path)

    assert report.primary_root_cause is not None
    assert report.primary_root_cause.category == FailureCategory.NETWORK_DNS_FAILURE
    assert len(report.secondary_root_causes) >= 1
    assert any(rc.category == FailureCategory.PROBE_FAILURE for rc in report.secondary_root_causes)


def test_investigate_empty_log():
    investigator = KubernetesInvestigator()
    report = investigator.investigate("")
    assert report.total_lines_analyzed == 0
    assert report.primary_root_cause is None


def test_investigate_image_pull_log():
    log_path = Path("/root/AI-K8-Agent/examples/image_pull_backoff.log")
    investigator = KubernetesInvestigator()
    report = investigator.investigate(log_path)

    assert report.primary_root_cause is not None
    assert report.primary_root_cause.category == FailureCategory.IMAGE_PULL_FAILURE
    assert any("not found" in e.matched_pattern.lower() or "imagepullbackoff" in e.matched_pattern.lower() for e in report.evidence)


def test_investigate_config_keyerror_log():
    log_path = Path("/root/AI-K8-Agent/examples/crashloop_db_connection.log")
    investigator = KubernetesInvestigator()
    report = investigator.investigate(log_path)

    assert report.primary_root_cause is not None
    assert report.primary_root_cause.category == FailureCategory.CONFIG_SECRET_FAILURE
    assert any("keyerror" in e.matched_pattern.lower() for e in report.evidence)


def test_investigate_rbac_forbidden_log():
    log_path = Path("/root/AI-K8-Agent/examples/rbac_forbidden.log")
    investigator = KubernetesInvestigator()
    report = investigator.investigate(log_path)

    assert report.primary_root_cause is not None
    assert report.primary_root_cause.category == FailureCategory.RBAC_PERMISSION_FAILURE
    assert any("forbidden" in e.matched_pattern.lower() for e in report.evidence)
    assert any("kubectl auth can-i" in r.kubectl_command for r in report.remediations if r.kubectl_command)
