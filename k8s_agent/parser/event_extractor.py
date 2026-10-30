"""Extractor for Kubernetes describe/event streams."""

import re
from typing import List, Optional
from pydantic import BaseModel
from k8s_agent.models.failure_modes import Severity


class K8sEvent(BaseModel):
    event_type: str  # "Normal" or "Warning"
    reason: str      # e.g., "Unhealthy", "FailedMount", "BackOff", "OOMKilling"
    from_component: str
    message: str
    count: int = 1
    line_number: int

    @property
    def severity(self) -> Severity:
        if self.event_type.lower() == "warning":
            if self.reason in ("OOMKilling", "CrashLoopBackOff", "FailedMount", "FailedCreate"):
                return Severity.CRITICAL
            return Severity.HIGH
        return Severity.INFO


# Regex matching `kubectl describe` Event table format:
# Warning  Unhealthy  4m2s (x3 over 4m32s)  kubelet  Liveness probe failed...
# Normal   Created    5m                    kubelet  Created container web
K8S_EVENT_REGEX = re.compile(
    r"^\s*(?P<type>Normal|Warning)\s+"
    r"(?P<reason>[A-Za-z0-9_]+)\s+"
    r"(?P<age>[0-9a-z\s\(\)]+?)\s+"
    r"(?P<component>[a-zA-Z0-9_\-\.]+)\s+"
    r"(?P<msg>.+)$"
)


class EventExtractor:
    """Detects and extracts Kubernetes events from logs or describe outputs."""

    def extract_events(self, raw_lines: List[str]) -> List[K8sEvent]:
        events = []
        for idx, line in enumerate(raw_lines, start=1):
            m = K8S_EVENT_REGEX.match(line)
            if m:
                ev = K8sEvent(
                    event_type=m.group("type"),
                    reason=m.group("reason"),
                    from_component=m.group("component"),
                    message=m.group("msg").strip(),
                    line_number=idx,
                )
                events.append(ev)
        return events
