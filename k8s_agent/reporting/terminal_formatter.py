"""Rich terminal visualization formatter for Kubernetes investigation reports."""

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.syntax import Syntax

from k8s_agent.models.failure_modes import Severity
from k8s_agent.models.report import InvestigationReport


class TerminalFormatter:
    """Renders formatted reports directly to the terminal using rich widgets."""

    def __init__(self, console: Console = None):
        self.console = console or Console()

    def render(self, report: InvestigationReport) -> None:
        """Print full interactive report to console."""
        # 1. Header
        header_text = Text()
        header_text.append("🛡️  KUBERNETES INVESTIGATION REPORT\n", style="bold cyan")
        header_text.append(f"Incident ID: {report.incident_id}  |  Target: {report.source_name}\n", style="dim")
        header_text.append(
            f"Analyzed: {report.total_lines_analyzed} lines  •  Errors: {report.error_count}  •  Warnings: {report.warning_count}",
            style="bold white",
        )
        self.console.print(Panel(header_text, border_style="cyan", expand=False))

        # 2. Executive Summary
        summary_panel = Panel(
            Text(report.executive_summary, style="white"),
            title="[bold blue]📌 Executive Summary[/bold blue]",
            border_style="blue",
        )
        self.console.print(summary_panel)

        # 3. Root Cause Analysis
        if report.primary_root_cause:
            rc = report.primary_root_cause
            rc_color = rc.severity.badge_color

            rc_text = Text()
            rc_text.append(f"[{rc.severity.value}] ", style=f"bold {rc_color}")
            rc_text.append(f"{rc.title}\n", style=f"bold white")
            rc_text.append(f"Confidence Score: {rc.confidence_percent}%\n", style="bold green")
            rc_text.append(f"Category: {rc.category.value}\n\n", style="italic cyan")
            rc_text.append(f"{rc.summary}\n\n", style="white")

            if rc.contributing_factors:
                rc_text.append("Contributing Factors:\n", style="bold yellow")
                for factor in rc.contributing_factors:
                    rc_text.append(f"  • {factor}\n", style="yellow")

            self.console.print(
                Panel(
                    rc_text,
                    title="[bold red]🎯 Primary Root Cause[/bold red]",
                    border_style="red",
                )
            )

        # 4. Secondary / Cascading Failures
        if report.secondary_root_causes:
            sec_table = Table(title="🔗 Cascading / Secondary Failures", border_style="yellow")
            sec_table.add_column("Category", style="cyan", no_wrap=True)
            sec_table.add_column("Title", style="bold white")
            sec_table.add_column("Summary", style="dim white")

            for sc in report.secondary_root_causes:
                sec_table.add_row(sc.category.value, sc.title, sc.summary)

            self.console.print(sec_table)

        # 5. Incident Timeline
        if report.timeline:
            tl_table = Table(title="⏱️ Chronological Incident Timeline", border_style="magenta")
            tl_table.add_column("Timestamp", style="cyan", no_wrap=True)
            tl_table.add_column("Phase", style="bold yellow")
            tl_table.add_column("Description", style="white")
            tl_table.add_column("Lines", style="green", no_wrap=True)

            for item in report.timeline:
                ts_str = item.formatted_timestamp
                lines_str = ", ".join(f"L{l}" for l in item.evidence_lines) if item.evidence_lines else "—"
                tl_table.add_row(ts_str, item.phase, item.description, lines_str)

            self.console.print(tl_table)

        # 6. Supporting Evidence
        if report.evidence:
            self.console.print("\n[bold cyan]🔍 Supporting Evidence Cited:[/bold cyan]")
            for idx, ev in enumerate(report.evidence, start=1):
                ts = ev.formatted_timestamp()
                smoking = " 💥 [bold red]SMOKING GUN[/bold red]" if ev.is_smoking_gun else ""
                title = f"Evidence #{idx} — Line {ev.line_number} [{ev.failure_category.value}]{smoking}"

                ev_text = Text()
                ev_text.append(f"Timestamp: {ts}  |  Trigger: {ev.matched_pattern}\n", style="dim cyan")
                ev_text.append(f"Analysis: {ev.explanation}\n\n", style="bold white")

                # Log snippet
                snippet = ""
                if ev.context_before:
                    snippet += f"# Context before:\n{ev.context_before}\n"
                snippet += f">>> {ev.raw_excerpt}\n"
                if ev.context_after:
                    snippet += f"# Context after:\n{ev.context_after}\n"

                panel = Panel(
                    ev_text + Text(snippet, style="dim white"),
                    title=f"[bold green]{title}[/bold green]",
                    border_style="green",
                )
                self.console.print(panel)

        # 7. Actionable Remediation Plan
        if report.remediations:
            self.console.print("\n[bold yellow]🛠️ Actionable Remediation Plan:[/bold yellow]")
            for rem in report.remediations:
                rem_text = Text()
                rem_text.append(f"Phase: {rem.phase}\n", style="bold magenta")
                rem_text.append(f"{rem.description}\n", style="white")

                if rem.kubectl_command:
                    rem_text.append("\nKubectl Diagnostic Command:\n", style="bold cyan")
                    rem_text.append(f"  $ {rem.kubectl_command}", style="bold green")

                self.console.print(
                    Panel(
                        rem_text,
                        title=f"[bold cyan]Action: {rem.title}[/bold cyan]",
                        border_style="cyan",
                    )
                )

        # 8. Optional LLM insights
        if report.llm_insights:
            self.console.print(
                Panel(
                    report.llm_insights,
                    title="[bold purple]🤖 Agentic AI Synthesis[/bold purple]",
                    border_style="purple",
                )
            )
