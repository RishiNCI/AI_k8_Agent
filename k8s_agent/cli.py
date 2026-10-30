"""Command Line Interface for Kubernetes Investigation Agent."""

import argparse
import sys
from pathlib import Path

from rich.console import Console

from k8s_agent import __version__
from k8s_agent.agent.investigator import KubernetesInvestigator
from k8s_agent.reporting.terminal_formatter import TerminalFormatter
from k8s_agent.tools.get_pod_logs import KubernetesToolError


def create_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="k8s-investigate",
        description="🛡️ Autonomous Kubernetes Log Investigation Agent with Root Cause Analysis & Evidence Citation.",
    )
    parser.add_argument(
        "target",
        nargs="?",
        default=None,
        help="Kubernetes Pod name (logs fetched via get_pod_logs tool), log file path, or '-' for stdin.",
    )
    parser.add_argument(
        "-p",
        "--pod",
        type=str,
        default=None,
        help="Explicitly specify target Kubernetes pod name to fetch logs from.",
    )
    parser.add_argument(
        "-n",
        "--namespace",
        type=str,
        default="default",
        help="Kubernetes namespace of the pod (default: 'default').",
    )
    parser.add_argument(
        "-c",
        "--container",
        type=str,
        default=None,
        help="Container name inside a multi-container pod.",
    )
    parser.add_argument(
        "--tail",
        type=int,
        default=500,
        help="Number of most recent log lines to fetch (default: 500).",
    )
    parser.add_argument(
        "--previous",
        action="store_true",
        help="Fetch logs for previous terminated container instance.",
    )
    parser.add_argument(
        "-f",
        "--format",
        choices=["terminal", "markdown", "json"],
        default="terminal",
        help="Output format: 'terminal' (rich interactive UI), 'markdown', or 'json' (default: terminal).",
    )
    parser.add_argument(
        "-o",
        "--output",
        type=str,
        default=None,
        help="Optional destination file path to write the generated report.",
    )
    parser.add_argument(
        "--source-name",
        type=str,
        default=None,
        help="Override the displayed source name in the report header.",
    )
    parser.add_argument(
        "--use-llm",
        action="store_true",
        help="Enhance the investigation report with AI SRE synthesis using Gemini API.",
    )
    parser.add_argument(
        "--api-key",
        type=str,
        default=None,
        help="Gemini API Key (can also be set via GEMINI_API_KEY environment variable).",
    )
    parser.add_argument(
        "--model",
        type=str,
        default="gemini-2.5-flash",
        help="LLM model to use when --use-llm is active (default: gemini-2.5-flash).",
    )
    parser.add_argument(
        "-v",
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
    )

    return parser


def main() -> int:
    parser = create_parser()
    args = parser.parse_args()

    console = Console()

    # Determine investigation mode: Pod target vs file vs stdin
    target_pod = args.pod
    target_arg = args.target

    investigator = KubernetesInvestigator(
        use_llm=args.use_llm,
        gemini_api_key=args.api_key,
        llm_model=args.model,
    )

    try:
        # Case 1: Explicit --pod flag
        if target_pod:
            if args.format == "terminal":
                console.print(f"[bold cyan]🔍 Fetching logs for pod [green]{target_pod}[/green] in namespace [yellow]{args.namespace}[/yellow] using [magenta]get_pod_logs[/magenta] tool...[/bold cyan]")
            report = investigator.investigate_pod(
                pod_name=target_pod,
                namespace=args.namespace,
                container=args.container,
                tail_lines=args.tail,
                previous=args.previous,
            )

        # Case 2: Positional argument provided
        elif target_arg:
            # Check if stdin
            if target_arg == "-":
                if sys.stdin.isatty():
                    console.print("[yellow]Reading from stdin... (Paste logs and press Ctrl+D, or pipe logs via 'kubectl logs ... | k8s-investigate -')[/yellow]")
                raw_input = sys.stdin.read()
                report = investigator.investigate(raw_input, source_name=args.source_name or "stdin")

            # Check if existing file on disk
            elif Path(target_arg).is_file():
                report = investigator.investigate(
                    Path(target_arg),
                    source_name=args.source_name or Path(target_arg).name,
                )

            # Otherwise, treat positional arg as Pod Name and fetch via get_pod_logs
            else:
                if args.format == "terminal":
                    console.print(f"[bold cyan]🔍 Fetching logs for pod [green]{target_arg}[/green] in namespace [yellow]{args.namespace}[/yellow] using [magenta]get_pod_logs[/magenta] tool...[/bold cyan]")
                report = investigator.investigate_pod(
                    pod_name=target_arg,
                    namespace=args.namespace,
                    container=args.container,
                    tail_lines=args.tail,
                    previous=args.previous,
                )

        # Case 3: No argument provided
        else:
            if not sys.stdin.isatty():
                raw_input = sys.stdin.read()
                report = investigator.investigate(raw_input, source_name=args.source_name or "stdin")
            else:
                parser.print_help()
                return 1

    except KubernetesToolError as kte:
        err_console = Console(stderr=True)
        err_console.print(f"[bold red]❌ Kubernetes Tool Error (get_pod_logs):[/bold red] {kte}")
        return 1
    except Exception as e:
        err_console = Console(stderr=True)
        err_console.print(f"[bold red]❌ Investigation Error:[/bold red] {e}")
        return 1

    # Format and Output
    if args.format == "json":
        rendered = report.to_json()
        if args.output:
            Path(args.output).write_text(rendered, encoding="utf-8")
            console.print(f"[green]JSON report saved to {args.output}[/green]")
        else:
            print(rendered)

    elif args.format == "markdown":
        rendered = report.to_markdown()
        if args.output:
            Path(args.output).write_text(rendered, encoding="utf-8")
            console.print(f"[green]Markdown report saved to {args.output}[/green]")
        else:
            print(rendered)

    else:  # terminal
        formatter = TerminalFormatter(console=console)
        formatter.render(report)
        if args.output:
            Path(args.output).write_text(report.to_markdown(), encoding="utf-8")
            console.print(f"\n[green]Report also saved as Markdown to {args.output}[/green]")

    return 0


if __name__ == "__main__":
    sys.exit(main())
