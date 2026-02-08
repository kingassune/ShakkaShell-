"""Rich console display helpers for ShakkaShell.

Provides formatted output using Rich library for command results, errors,
and status messages.
"""

from typing import Optional

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.markdown import Markdown

from shakka.providers.base import CommandResult


# Global console instance
console = Console()


def print_banner() -> None:
    """Print ShakkaShell banner."""
    banner = """
╭─────────────────────────────────────────────────╮
│         [bold cyan]ShakkaShell v2.0[/bold cyan]              │
│  Natural Language to Security Commands          │
╰─────────────────────────────────────────────────╯
    """
    console.print(banner)


def print_command_result(result: CommandResult) -> None:
    """Display command generation result in a formatted panel.
    
    Args:
        result: CommandResult to display
    """
    # Determine risk color
    risk_colors = {
        "Low": "green",
        "Medium": "yellow",
        "High": "orange1",
        "Critical": "red"
    }
    risk_color = risk_colors.get(result.risk_level, "white")
    
    # Build content
    content_parts = []
    
    # Command
    content_parts.append(f"[bold]Command:[/bold]")
    content_parts.append(f"[cyan]{result.command}[/cyan]\n")
    
    # Risk level
    content_parts.append(
        f"[bold]Risk:[/bold] [{risk_color}]{result.risk_level}[/{risk_color}]"
    )
    
    # Prerequisites
    if result.prerequisites:
        prereqs = ", ".join(result.prerequisites)
        content_parts.append(f"[bold]Requires:[/bold] {prereqs}")
    
    # Explanation
    content_parts.append(f"\n{result.explanation}")
    
    # Warnings
    if result.warnings:
        content_parts.append("")
        content_parts.append("[bold yellow]⚠ Warnings:[/bold yellow]")
        for warning in result.warnings:
            content_parts.append(f"  • {warning}")
    
    # Alternatives
    if result.alternatives:
        content_parts.append("")
        content_parts.append("[bold]Alternatives:[/bold]")
        for alt in result.alternatives:
            content_parts.append(f"  • [dim]{alt}[/dim]")
    
    content = "\n".join(content_parts)
    
    panel = Panel(
        content,
        title="[bold]ShakkaShell[/bold]",
        border_style="blue",
        padding=(1, 2)
    )
    
    console.print(panel)


def print_error(message: str, title: str = "Error") -> None:
    """Display error message.
    
    Args:
        message: Error message to display
        title: Panel title
    """
    console.print(
        Panel(
            f"[red]{message}[/red]",
            title=f"[bold red]{title}[/bold red]",
            border_style="red"
        )
    )


def print_success(message: str) -> None:
    """Display success message.
    
    Args:
        message: Success message to display
    """
    console.print(f"[green]✓[/green] {message}")


def print_warning(message: str) -> None:
    """Display warning message.
    
    Args:
        message: Warning message to display
    """
    console.print(f"[yellow]⚠[/yellow] {message}")


def print_info(message: str) -> None:
    """Display info message.
    
    Args:
        message: Info message to display
    """
    console.print(f"[blue]ℹ[/blue] {message}")


def print_history_table(history: list[dict]) -> None:
    """Display command history in a table.
    
    Args:
        history: List of history entries (dicts with keys: id, command, risk_level, created_at)
    """
    if not history:
        print_info("No history entries found.")
        return
    
    table = Table(title="Command History", show_header=True, header_style="bold cyan")
    table.add_column("ID", style="dim", width=6)
    table.add_column("Command", style="cyan", width=50)
    table.add_column("Risk", width=10)
    table.add_column("Date", style="dim", width=20)
    
    risk_colors = {
        "Low": "green",
        "Medium": "yellow",
        "High": "orange1",
        "Critical": "red"
    }
    
    for entry in history:
        risk_color = risk_colors.get(entry.get("risk_level", "Medium"), "white")
        table.add_row(
            str(entry.get("id", "")),
            entry.get("command", "")[:47] + "..." if len(entry.get("command", "")) > 50 else entry.get("command", ""),
            f"[{risk_color}]{entry.get('risk_level', 'Unknown')}[/{risk_color}]",
            entry.get("created_at", "")
        )
    
    console.print(table)


def print_provider_status(status: dict[str, bool]) -> None:
    """Display provider configuration status.
    
    Args:
        status: Dictionary mapping provider names to configuration status
    """
    table = Table(title="Provider Status", show_header=True, header_style="bold cyan")
    table.add_column("Provider", style="bold")
    table.add_column("Status", width=20)
    
    for provider, is_configured in status.items():
        status_text = "[green]✓ Configured[/green]" if is_configured else "[red]✗ Not configured[/red]"
        table.add_row(provider.capitalize(), status_text)
    
    console.print(table)


def confirm(message: str, default: bool = True) -> bool:
    """Prompt user for confirmation.
    
    Args:
        message: Confirmation message
        default: Default response
        
    Returns:
        True if user confirms, False otherwise
    """
    from rich.prompt import Confirm
    return Confirm.ask(message, default=default)


def prompt(message: str, default: Optional[str] = None) -> str:
    """Prompt user for input.
    
    Args:
        message: Prompt message
        default: Default value
        
    Returns:
        User input string
    """
    from rich.prompt import Prompt
    return Prompt.ask(message, default=default)


def print_spinner_context(message: str):
    """Create a spinner context for long-running operations.
    
    Args:
        message: Message to display with spinner
        
    Returns:
        Rich spinner context manager
    """
    from rich.spinner import Spinner
    from rich.live import Live
    
    spinner = Spinner("dots", text=message)
    return console.status(message, spinner="dots")


def print_agent_step_progress(step_num: int, total_steps: int, agent: str, description: str, status: str = "running") -> None:
    """Display progress for a single agent step.
    
    Args:
        step_num: Current step number
        total_steps: Total number of steps
        agent: Agent name performing the step
        description: Step description
        status: Current status (running, completed, failed)
    """
    status_icons = {
        "running": "[cyan]⟳[/cyan]",
        "completed": "[green]✓[/green]",
        "failed": "[red]✗[/red]",
        "skipped": "[dim]⏭[/dim]",
    }
    icon = status_icons.get(status, "[blue]●[/blue]")
    
    agent_colors = {
        "recon": "cyan",
        "exploit": "red",
        "persistence": "yellow",
        "reporter": "green",
    }
    color = agent_colors.get(agent.lower(), "white")
    
    console.print(f"  {icon} [{step_num}/{total_steps}] [[{color}]{agent.upper()}[/{color}]] {description}")


def print_step_result(step_num: int, agent: str, output: str, success: bool, show_full: bool = False) -> None:
    """Display the result of a completed step.
    
    Args:
        step_num: Step number
        agent: Agent that executed the step
        output: Step output
        success: Whether step succeeded
        show_full: Show full output instead of truncated
    """
    status = "[green]SUCCESS[/green]" if success else "[red]FAILED[/red]"
    
    if show_full:
        console.print(Panel(
            output,
            title=f"[bold]Step {step_num} - {agent.title()}[/bold] {status}",
            border_style="green" if success else "red",
            padding=(0, 1),
        ))
    else:
        # Truncated preview
        preview = output[:200] + "..." if len(output) > 200 else output
        console.print(f"    [dim]└─ {preview}[/dim]")


def print_agent_report(report_data: dict, objective: str = "") -> None:
    """Display a full agent execution report with all findings.
    
    Args:
        report_data: The report data from agent execution
        objective: The original objective
    """
    console.print()
    console.print(Panel(
        f"[bold cyan]{objective or 'Security Assessment Report'}[/bold cyan]",
        title="[bold green]📋 FINAL REPORT[/bold green]",
        border_style="green",
        padding=(0, 2),
    ))
    
    # Show executive summary if present
    if isinstance(report_data, dict):
        exec_summary = report_data.get("executive_summary") or report_data.get("summary")
        if exec_summary:
            console.print()
            console.print(Panel(
                exec_summary,
                title="[bold]Executive Summary[/bold]",
                border_style="blue",
                padding=(0, 1),
            ))
        
        # Show findings
        findings = report_data.get("findings", [])
        if findings:
            console.print()
            console.print("[bold]Findings:[/bold]")
            
            severity_colors = {
                "critical": "red",
                "high": "orange1",
                "medium": "yellow",
                "low": "green",
                "informational": "dim",
            }
            
            for i, finding in enumerate(findings, 1):
                if isinstance(finding, dict):
                    severity = finding.get("severity", "medium").lower()
                    color = severity_colors.get(severity, "white")
                    title = finding.get("title", f"Finding {i}")
                    desc = finding.get("description", "")
                    
                    console.print(f"  [{color}]●[/{color}] [bold]{title}[/bold] [{color}][{severity.upper()}][/{color}]")
                    if desc:
                        console.print(f"    [dim]{desc[:300]}{'...' if len(desc) > 300 else ''}[/dim]")
                    
                    recommendation = finding.get("recommendation")
                    if recommendation:
                        console.print(f"    [green]→ {recommendation[:200]}{'...' if len(recommendation) > 200 else ''}[/green]")
                    console.print()
        
        # Show risk summary
        risk = report_data.get("risk_summary")
        if risk and isinstance(risk, dict):
            console.print()
            table = Table(title="Risk Summary", show_header=True, header_style="bold")
            table.add_column("Severity", style="bold")
            table.add_column("Count", justify="center")
            
            for level in ["critical", "high", "medium", "low"]:
                count = risk.get(level, 0)
                color = severity_colors.get(level, "white")
                if count > 0:
                    table.add_row(f"[{color}]{level.title()}[/{color}]", str(count))
            
            console.print(table)
        
        # Show recommendations
        recommendations = report_data.get("recommendations", [])
        if recommendations:
            console.print()
            console.print("[bold]Recommended Actions:[/bold]")
            for i, rec in enumerate(recommendations, 1):
                if isinstance(rec, dict):
                    action = rec.get("action", str(rec))
                    priority = rec.get("priority", i)
                    console.print(f"  [cyan]{priority}.[/cyan] {action}")
                else:
                    console.print(f"  [cyan]{i}.[/cyan] {rec}")
        
        # Show conclusion
        conclusion = report_data.get("conclusion")
        if conclusion:
            console.print()
            console.print(Panel(
                conclusion,
                title="[bold]Conclusion[/bold]",
                border_style="dim",
                padding=(0, 1),
            ))
    else:
        # Raw output
        console.print(str(report_data))


def create_live_progress_table(objective: str, steps: list, current_step_id: str = None):
    """Create a live progress table for agent execution.
    
    Args:
        objective: The task objective
        steps: List of step dicts with step_id, description, status, assigned_agent
        current_step_id: Currently executing step ID
        
    Returns:
        Rich Table object
    """
    table = Table(
        title=f"[bold]🔄 Executing: {objective[:60]}{'...' if len(objective) > 60 else ''}[/bold]",
        show_header=True,
        header_style="bold cyan",
        border_style="dim",
    )
    table.add_column("#", width=3, justify="center")
    table.add_column("Agent", width=12)
    table.add_column("Task", width=50)
    table.add_column("Status", width=12)
    
    status_display = {
        "pending": ("⏳", "dim"),
        "in_progress": ("🔄", "cyan"),
        "completed": ("✅", "green"),
        "failed": ("❌", "red"),
        "skipped": ("⏭️", "dim"),
    }
    
    agent_colors = {
        "recon": "cyan",
        "exploit": "red", 
        "persistence": "yellow",
        "reporter": "green",
        "orchestrator": "magenta",
    }
    
    for i, step in enumerate(steps, 1):
        status = step.get("status", "pending")
        icon, style = status_display.get(status, ("●", "white"))
        
        agent = step.get("assigned_agent", "unknown")
        agent_color = agent_colors.get(agent.lower(), "white")
        
        desc = step.get("description", "")
        if len(desc) > 48:
            desc = desc[:45] + "..."
        
        # Highlight current step
        if step.get("step_id") == current_step_id:
            table.add_row(
                f"[bold]{i}[/bold]",
                f"[bold {agent_color}]{agent.upper()}[/bold {agent_color}]",
                f"[bold]{desc}[/bold]",
                f"[{style}]{icon} Running...[/{style}]"
            )
        else:
            table.add_row(
                str(i),
                f"[{agent_color}]{agent.title()}[/{agent_color}]",
                desc,
                f"[{style}]{icon} {status.title()}[/{style}]"
            )
    
    return table
