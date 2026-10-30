"""Temporal correlation and cascading failure analysis engine."""

from collections import defaultdict
from datetime import datetime
from typing import Dict, List, Optional, Tuple

from k8s_agent.analyzer.rules.base import BaseRule
from k8s_agent.models.evidence import EvidenceItem
from k8s_agent.models.failure_modes import FailureCategory, Severity
from k8s_agent.models.report import RemediationAction, RootCause, TimelineEvent

# Primary causality priority: lower number means higher likelihood of being the primary root cause
CAUSALITY_PRIORITY: Dict[FailureCategory, int] = {
    FailureCategory.CONFIG_SECRET_FAILURE: 1,      # Missing config/secret happens before app even starts
    FailureCategory.IMAGE_PULL_FAILURE: 1,         # Image can't pull before app starts
    FailureCategory.STORAGE_VOLUME_FAILURE: 2,     # Storage mount fails before/during boot
    FailureCategory.RBAC_PERMISSION_FAILURE: 3,     # RBAC blocks API access
    FailureCategory.NETWORK_DNS_FAILURE: 4,        # Downstream network/DNS fails
    FailureCategory.RESOURCE_STARVATION_DEADLOCK: 5, # DB pool exhausted / thread lock
    FailureCategory.OOM_KILLED: 6,                 # Memory limit reached
    FailureCategory.APPLICATION_PANIC: 7,          # Code-level unhandled bug
    FailureCategory.PROBE_FAILURE: 8,              # Probes fail because of app error
    FailureCategory.CRASH_LOOP_BACKOFF: 9,         # Backoff happens after process crashes
    FailureCategory.UNKNOWN: 10,
}


class CorrelationEngine:
    """Correlates evidence items into a coherent failure timeline and identifies root cause."""

    def __init__(self, rules: List[BaseRule]):
        self.rules_by_category = {rule.category: rule for rule in rules}

    def correlate(
        self,
        evidence_items: List[EvidenceItem],
        total_lines: int,
    ) -> Tuple[Optional[RootCause], List[RootCause], List[TimelineEvent], List[RemediationAction]]:
        """
        Synthesizes raw evidence into:
        1. Primary Root Cause
        2. Secondary / Cascading Root Causes
        3. Chronological Timeline
        4. Remediation Plan
        """
        if not evidence_items:
            return None, [], [], []

        # 1. Group evidence by FailureCategory
        grouped_evidence: Dict[FailureCategory, List[EvidenceItem]] = defaultdict(list)
        for ev in evidence_items:
            grouped_evidence[ev.failure_category].append(ev)

        # 2. Build synthesized root causes per category
        category_causes: List[RootCause] = []
        for cat, ev_list in grouped_evidence.items():
            rule = self.rules_by_category.get(cat)
            if rule:
                rc = rule.synthesize_root_cause(ev_list)
                category_causes.append(rc)

        # 3. Determine Primary vs Secondary Root Causes
        # Criteria:
        # A) Explicit smoking gun evidence (e.g. exit code 137, missing secret)
        # B) Temporal order (which failure appeared earliest in the log stream)
        # C) Causality hierarchy priority
        primary_category = self._select_primary_category(grouped_evidence)

        primary_root_cause: Optional[RootCause] = None
        secondary_root_causes: List[RootCause] = []

        for rc in category_causes:
            if rc.category == primary_category:
                rc.is_primary = True
                primary_root_cause = rc
            else:
                rc.is_primary = False
                secondary_root_causes.append(rc)

        # 4. Generate Chronological Timeline
        timeline = self._build_timeline(evidence_items, primary_category)

        # 5. Generate Deduplicated Action Plan
        remediations = self._build_remediations(primary_category, secondary_root_causes, grouped_evidence)

        return primary_root_cause, secondary_root_causes, timeline, remediations

    def _select_primary_category(
        self,
        grouped_evidence: Dict[FailureCategory, List[EvidenceItem]],
    ) -> FailureCategory:
        """Determines the primary root cause among all detected failure categories."""
        categories = list(grouped_evidence.keys())
        if len(categories) == 1:
            return categories[0]

        # Score each category
        def score_category(cat: FailureCategory) -> Tuple[int, int, float, int]:
            ev_list = grouped_evidence[cat]
            has_smoking_gun = any(e.is_smoking_gun for e in ev_list)
            # Earliest line number where this failure was observed
            earliest_line = min((e.line_number for e in ev_list), default=999999)
            # Max confidence weight
            max_weight = max((e.weight for e in ev_list), default=0.0)
            # Hierarchy priority (lower is better, so invert for sorting)
            priority = CAUSALITY_PRIORITY.get(cat, 10)

            # (-priority: higher is better, smoking_gun: 1 or 0, max_weight: higher is better, -earliest_line: higher is earlier)
            return (
                -priority,
                1 if has_smoking_gun else 0,
                max_weight,
                -earliest_line,
            )

        best_category = max(categories, key=score_category)
        return best_category

    def _build_timeline(
        self,
        evidence_items: List[EvidenceItem],
        primary_cat: FailureCategory,
    ) -> List[TimelineEvent]:
        """Constructs an orderly timeline of events showing the failure progression."""
        # Sort evidence items by timestamp if available, else by line number
        def sort_key(e: EvidenceItem):
            if e.timestamp:
                return (0, e.timestamp, e.line_number)
            return (1, datetime.min, e.line_number)

        sorted_evidence = sorted(evidence_items, key=sort_key)
        timeline: List[TimelineEvent] = []

        seen_patterns = set()

        for idx, ev in enumerate(sorted_evidence):
            # Avoid duplicate consecutive noise
            key = (ev.failure_category, ev.matched_pattern)
            if key in seen_patterns and len(seen_patterns) > 1:
                continue
            seen_patterns.add(key)

            phase = "Investigation"
            if ev.failure_category == primary_cat and (idx == 0 or ev.is_smoking_gun):
                phase = "Root Cause Trigger"
            elif ev.failure_category in (FailureCategory.PROBE_FAILURE, FailureCategory.CRASH_LOOP_BACKOFF):
                phase = "Cascading Impact"
            elif ev.failure_category == FailureCategory.OOM_KILLED:
                phase = "Process Termination"
            else:
                phase = "Symptom Manifestation"

            timeline.append(
                TimelineEvent(
                    timestamp=ev.timestamp,
                    phase=phase,
                    description=ev.explanation,
                    severity=ev.severity,
                    evidence_lines=[ev.line_number],
                    source_component=ev.failure_category.value,
                )
            )

        return timeline

    def _build_remediations(
        self,
        primary_cat: FailureCategory,
        secondary_causes: List[RootCause],
        grouped_evidence: Dict[FailureCategory, List[EvidenceItem]],
    ) -> List[RemediationAction]:
        """Collects and deduplicates remediation actions prioritizing primary cause."""
        actions: List[RemediationAction] = []
        seen_titles = set()

        # Primary rule remediations first
        primary_rule = self.rules_by_category.get(primary_cat)
        if primary_rule:
            for act in primary_rule.generate_remediations(grouped_evidence[primary_cat]):
                if act.title not in seen_titles:
                    actions.append(act)
                    seen_titles.add(act.title)

        # Secondary causes remediations
        for sc in secondary_causes:
            rule = self.rules_by_category.get(sc.category)
            if rule:
                for act in rule.generate_remediations(grouped_evidence[sc.category]):
                    if act.title not in seen_titles:
                        actions.append(act)
                        seen_titles.add(act.title)

        return actions
