"""Prepares structured diagnostic context for LLM agent synthesis."""

from k8s_agent.models.report import InvestigationReport


class ContextBuilder:
    """Builds prompt contexts from deterministic diagnostic findings."""

    @staticmethod
    def build_sre_prompt(report: InvestigationReport) -> str:
        prompt_lines = [
            "You are a Principal Kubernetes Site Reliability Engineer (SRE).",
            "Review the following deterministic investigation findings extracted from a Kubernetes log stream.",
            "Synthesize a concise, expert post-mortem narrative explaining:",
            "1. The physical sequence of events that unfolded",
            "2. Why the failure occurred at a systems/architectural level",
            "3. Any non-obvious risks or latent defects in the workload configuration",
            "4. Permanent architectural hardening advice",
            "",
            f"Incident ID: {report.incident_id}",
            f"Log Volume Analyzed: {report.total_lines_analyzed} lines",
            f"Error Count: {report.error_count} | Warning Count: {report.warning_count}",
            "",
        ]

        if report.primary_root_cause:
            rc = report.primary_root_cause
            prompt_lines.append(f"Primary Root Cause: {rc.title} ({rc.confidence_percent}% confidence)")
            prompt_lines.append(f"Category: {rc.category.value}")
            prompt_lines.append(f"Summary: {rc.summary}")
            if rc.contributing_factors:
                prompt_lines.append(f"Contributing Factors: {'; '.join(rc.contributing_factors)}")
            prompt_lines.append("")

        if report.secondary_root_causes:
            prompt_lines.append("Cascading Secondary Failures Detected:")
            for sc in report.secondary_root_causes:
                prompt_lines.append(f"- {sc.title} ({sc.category.value}): {sc.summary}")
            prompt_lines.append("")

        if report.evidence:
            prompt_lines.append("Extracted Evidence Excerpts:")
            for ev in report.evidence[:8]:  # Limit to top 8 items
                prompt_lines.append(
                    f"- [Line {ev.line_number}] [{ev.failure_category.value}] {ev.raw_excerpt[:150]}"
                )
            prompt_lines.append("")

        prompt_lines.append(
            "Please provide a clear, concise expert analysis (2-3 paragraphs) followed by bulleted hardening advice."
        )

        return "\n".join(prompt_lines)
