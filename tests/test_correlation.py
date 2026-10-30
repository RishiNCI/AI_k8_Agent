from k8s_agent.analyzer.correlation import CorrelationEngine
from k8s_agent.analyzer.rules import ALL_RULES
from k8s_agent.models.evidence import EvidenceItem
from k8s_agent.models.failure_modes import FailureCategory, Severity


def test_cascading_failure_primary_cause_selection():
    engine = CorrelationEngine(ALL_RULES)

    # Simulate evidence: DNS failure at line 5, Probe failure at line 10, CrashLoop at line 15
    evidence_items = [
        EvidenceItem(
            line_number=5,
            raw_excerpt="lookup postgres.default.svc: i/o timeout",
            failure_category=FailureCategory.NETWORK_DNS_FAILURE,
            matched_pattern=r"lookup.*i/o timeout",
            explanation="DNS lookup failed",
            severity=Severity.HIGH,
            weight=0.95,
            is_smoking_gun=True,
        ),
        EvidenceItem(
            line_number=10,
            raw_excerpt="Readiness probe failed: HTTP probe failed with statuscode: 500",
            failure_category=FailureCategory.PROBE_FAILURE,
            matched_pattern=r"Readiness probe failed",
            explanation="Probe failed",
            severity=Severity.HIGH,
            weight=0.9,
            is_smoking_gun=False,
        ),
        EvidenceItem(
            line_number=15,
            raw_excerpt="Back-off restarting failed container",
            failure_category=FailureCategory.CRASH_LOOP_BACKOFF,
            matched_pattern=r"Back-off restarting",
            explanation="CrashLoopBackOff",
            severity=Severity.CRITICAL,
            weight=0.9,
            is_smoking_gun=False,
        ),
    ]

    primary_rc, secondary_rcs, timeline, remediations = engine.correlate(
        evidence_items, total_lines=20
    )

    assert primary_rc is not None
    # Must correctly pick DNS failure as primary!
    assert primary_rc.category == FailureCategory.NETWORK_DNS_FAILURE
    assert primary_rc.is_primary is True

    # Secondary should contain probe and crashloop
    sec_cats = {s.category for s in secondary_rcs}
    assert FailureCategory.PROBE_FAILURE in sec_cats
    assert FailureCategory.CRASH_LOOP_BACKOFF in sec_cats

    # Timeline has events
    assert len(timeline) >= 3
    assert timeline[0].phase == "Root Cause Trigger"

    # Remediations should include CoreDNS checks
    assert any("CoreDNS" in r.title for r in remediations)
