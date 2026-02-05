"""Command-line interface for ShakkaShell using Typer."""

import asyncio
from typing import Optional

import typer
from rich.console import Console
from rich.panel import Panel

from shakka import __version__
from shakka.config import ShakkaConfig
from shakka.core.generator import CommandGenerator
from shakka.agents import (
    Orchestrator,
    AgentConfig,
    AgentRole,
    ReconAgent,
    ExploitAgent,
    PersistenceAgent,
    ReporterAgent,
)
from shakka.utils import display

app = typer.Typer(
    name="shakka",
    help="Natural language to security commands",
    add_completion=False,
)

PROVIDER_COMMAND_ALIASES = (":provider", "/provider")


def version_callback(value: bool):
    """Print version and exit."""
    if value:
        display.console.print(f"ShakkaShell version {__version__}")
        raise typer.Exit()


@app.callback()
def main_callback(
    version: bool = typer.Option(
        False,
        "--version",
        "-v",
        help="Show version and exit",
        callback=version_callback,
        is_eager=True
    )
):
    """ShakkaShell - Natural language to security commands."""
    pass


@app.command(name="generate")
def generate_command(
    query: Optional[str] = typer.Argument(
        None,
        help="Your request in plain language"
    ),
    provider: Optional[str] = typer.Option(
        None,
        "--provider",
        "-p",
        help="LLM provider to use (openai, anthropic, ollama)"
    ),
    interactive: bool = typer.Option(
        False,
        "--interactive",
        "-i",
        help="Enter interactive mode"
    ),
    agent: bool = typer.Option(
        False,
        "--agent",
        "-a",
        help="Use multi-agent orchestration for complex tasks"
    ),
):
    """Generate security commands from natural language.
    
    Examples:
        shakka generate "scan ports on 10.0.0.1"
        shakka generate "find subdomains for example.com" --provider openai
        shakka generate --interactive
        shakka generate --agent "Full recon and initial access assessment on target.com"
    """
    config = ShakkaConfig()
    
    # Agent mode
    if agent:
        if not query:
            display.print_error("Please provide a task for agent mode")
            raise typer.Exit(code=1)
        
        _run_agent_mode(query, config)
        return
    
    generator = CommandGenerator(config=config)
    
    if interactive:
        # Interactive mode
        display.print_banner()
        display.print_info("Interactive mode. Type 'exit' or 'quit' to exit.\n")
        provider_usage_message = (
            f"Usage: :provider <{'|'.join(generator.list_providers())}>"
        )
        
        while True:
            try:
                user_query = display.prompt("[bold cyan]ShakkaShell>[/bold cyan]")
                user_input = user_query.strip()
                
                if user_input.lower() in ["exit", "quit", "q"]:
                    display.print_info("Goodbye!")
                    break
                if not user_input:
                    continue

                input_parts = user_input.split(maxsplit=1)
                if not input_parts:
                    continue
                command_prefix = input_parts[0].lower()

                if command_prefix in PROVIDER_COMMAND_ALIASES:
                    if len(input_parts) < 2:
                        display.print_error(provider_usage_message)
                        continue

                    new_provider = input_parts[1].strip()
                    if not new_provider:
                        display.print_error(provider_usage_message)
                        continue
                    try:
                        generator.set_provider(new_provider)
                        display.print_success(f"Switched provider to: {new_provider}")
                    except ValueError as e:
                        display.print_error(str(e))
                    continue

                # Generate command
                with display.print_spinner_context("Generating command..."):
                    result = asyncio.run(
                        generator.generate(user_query, provider=provider)
                    )
                
                display.print_command_result(result)
                display.console.print()
                
            except KeyboardInterrupt:
                display.print_info("\nGoodbye!")
                break
            except Exception as e:
                display.print_error(str(e))
    
    else:
        # Single command mode
        if not query:
            display.print_error("Please provide a query or use --interactive mode")
            raise typer.Exit(code=1)
        
        try:
            with display.print_spinner_context("Generating command..."):
                result = asyncio.run(
                    generator.generate(query, provider=provider)
                )
            
            display.print_command_result(result)
            
        except Exception as e:
            display.print_error(str(e))
            raise typer.Exit(code=1)


@app.command(name="history")
def history(
    limit: int = typer.Option(
        10,
        "--limit",
        "-n",
        help="Number of history entries to show"
    ),
    clear: bool = typer.Option(
        False,
        "--clear",
        help="Clear command history"
    )
):
    """View or manage command history.
    
    Examples:
        shakka history
        shakka history --limit 20
        shakka history --clear
    """
    if clear:
        if display.confirm("Are you sure you want to clear all history?", default=False):
            # TODO: Implement history clearing
            display.print_success("History cleared")
        else:
            display.print_info("Cancelled")
        return
    
    # TODO: Implement history retrieval
    display.print_info("History feature coming soon...")


@app.command(name="config")
def config_command(
    show: bool = typer.Option(
        False,
        "--show",
        help="Show current configuration"
    ),
    provider: Optional[str] = typer.Option(
        None,
        "--set-provider",
        help="Set default provider"
    )
):
    """Manage ShakkaShell configuration.
    
    Examples:
        shakka config --show
        shakka config --set-provider openai
    """
    config = ShakkaConfig()
    
    if show:
        display.print_info("Current Configuration:")
        display.console.print(f"  Default Provider: [cyan]{config.default_provider}[/cyan]")
        display.console.print(f"  Debug Mode: [cyan]{config.debug}[/cyan]")
        display.console.print(f"  Max History: [cyan]{config.max_history}[/cyan]")
        display.console.print()
        
        # Show provider status
        generator = CommandGenerator(config=config)
        status = generator.get_provider_status()
        display.print_provider_status(status)
        return
    
    if provider:
        if provider not in ["openai", "anthropic", "ollama"]:
            display.print_error(f"Invalid provider: {provider}")
            raise typer.Exit(code=1)
        
        config.default_provider = provider
        config.save_to_file()
        display.print_success(f"Default provider set to: {provider}")
        return
    
    # No options specified, show help
    display.print_info("Use --show to view configuration or --set-provider to change provider")


def _run_agent_mode(objective: str, config: ShakkaConfig) -> None:
    """Run multi-agent orchestration for complex tasks.
    
    Args:
        objective: The high-level task to accomplish.
        config: ShakkaConfig instance.
    """
    display.print_info("Initializing multi-agent orchestration...")
    display.console.print()
    
    # Create orchestrator with agent config
    orchestrator = Orchestrator(
        config=AgentConfig(
            role=AgentRole.ORCHESTRATOR,
            use_shared_memory=True,
        )
    )
    
    # Create and register specialized agents
    agents = {
        AgentRole.RECON: ReconAgent(),
        AgentRole.EXPLOIT: ExploitAgent(),
        AgentRole.PERSISTENCE: PersistenceAgent(),
        AgentRole.REPORTER: ReporterAgent(),
    }
    
    for role, agent in agents.items():
        orchestrator.register_agent(agent)
    
    # Show registered agents
    display.console.print(Panel(
        f"[bold cyan]Objective:[/bold cyan] {objective}\n\n"
        f"[bold]Registered Agents:[/bold]\n"
        + "\n".join(f"  • {role.value.title()}" for role in agents.keys()),
        title="[bold green]Agent Mode[/bold green]",
        border_style="green",
    ))
    display.console.print()
    
    # Create and display the execution plan
    with display.print_spinner_context("Creating execution plan..."):
        plan = orchestrator.create_plan(objective)
    
    display.console.print(plan.format_plan())
    display.console.print()
    
    # Execute the plan
    display.print_info("Executing plan...")
    display.console.print()
    
    try:
        result = asyncio.run(orchestrator.execute(objective))
        
        # Display results
        if result.success:
            display.print_success("Task completed successfully!")
        else:
            display.print_warning("Task completed with some issues.")
        
        display.console.print()
        
        # Show step results
        if result.data and "step_results" in result.data:
            display.console.print("[bold]Step Results:[/bold]")
            for i, step_result in enumerate(result.data["step_results"], 1):
                status = "✅" if step_result.get("success") else "❌"
                output = step_result.get("output", "No output")[:100]
                display.console.print(f"  {status} Step {i}: {output}")
        
        display.console.print()
        
        # Show final output
        if result.output:
            display.console.print(Panel(
                result.output,
                title="[bold]Agent Output[/bold]",
                border_style="blue",
            ))
        
        # Show plan status
        final_plan = result.data.get("plan", {}) if result.data else {}
        if final_plan:
            progress = final_plan.get("progress", 0)
            status = final_plan.get("status", "unknown")
            display.console.print(
                f"\n[dim]Plan Status: {status} ({progress:.0f}% complete)[/dim]"
            )
        
    except KeyboardInterrupt:
        display.print_warning("\nAgent execution interrupted by user.")
        raise typer.Exit(code=130)
    except Exception as e:
        display.print_error(f"Agent execution failed: {e}")
        raise typer.Exit(code=1)


@app.command(name="validate")
def validate(
    provider: Optional[str] = typer.Option(
        None,
        "--provider",
        "-p",
        help="Provider to validate (default: all configured)"
    )
):
    """Validate LLM provider connections.
    
    Examples:
        shakka validate
        shakka validate --provider openai
    """
    config = ShakkaConfig()
    generator = CommandGenerator(config=config)
    
    if provider:
        providers_to_check = [provider]
    else:
        # Check all configured providers
        status = generator.get_provider_status()
        providers_to_check = [p for p, configured in status.items() if configured]
    
    display.print_info("Validating provider connections...\n")
    
    for prov in providers_to_check:
        with display.print_spinner_context(f"Checking {prov}..."):
            try:
                is_valid = asyncio.run(generator.validate_provider(prov))
                if is_valid:
                    display.print_success(f"{prov}: Connected")
                else:
                    display.print_error(f"{prov}: Failed to connect")
            except Exception as e:
                display.print_error(f"{prov}: {str(e)}")


@app.command(name="agent")
def agent(
    objective: str = typer.Argument(
        ...,
        help="The complex task to accomplish using multi-agent orchestration"
    ),
):
    """Run multi-agent orchestration for complex security tasks.
    
    This command uses multiple specialized agents (Recon, Exploit, 
    Persistence, Reporter) coordinated by an orchestrator to complete
    complex, multi-step security assessments.
    
    Examples:
        shakka agent "Full recon and initial access assessment on target.com"
        shakka agent "Scan network 192.168.1.0/24 and identify vulnerabilities"
        shakka agent "Perform comprehensive security audit and generate report"
    """
    config = ShakkaConfig()
    _run_agent_mode(objective, config)


if __name__ == "__main__":
    app()
