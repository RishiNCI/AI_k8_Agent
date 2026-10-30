"""Evidence item structures for Kubernetes investigations."""

from datetime import datetime
from typing import Optional
from pydantic import BaseModel, Field
from k8s_agent.models.failure_modes import FailureCategory, Severity


class EvidenceItem(BaseModel):
    """Represents a specific log line or block identified as evidence of a failure."""
    id: str = Field(default_factory=lambda: "")
    line_number: int
    timestamp: Optional[datetime] = None
    raw_excerpt: str
    failure_category: FailureCategory
    matched_pattern: str
    explanation: str
    severity: Severity = Severity.HIGH
    weight: float = Field(default=0.8, ge=0.0, le=1.0)
    is_smoking_gun: bool = False
    context_before: str = ""
    context_after: str = ""

    def formatted_timestamp(self) -> str:
        if self.timestamp:
            return self.timestamp.isoformat()
        return "N/A"
