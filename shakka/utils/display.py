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
