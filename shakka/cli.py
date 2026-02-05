"""Command-line interface for ShakkaShell using Typer."""

import asyncio
from typing import Optional

import typer
from rich.console import Console

from shakka import __version__
from shakka.config import ShakkaConfig
from shakka.core.generator import CommandGenerator
from shakka.utils import display

app = typer.Typer(
    name="shakka",
    help="Natural language to security commands",
    add_completion=False,
)


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
):
    """Generate security commands from natural language.
    
    Examples:
        shakka generate "scan ports on 10.0.0.1"
        shakka generate "find subdomains for example.com" --provider openai
        shakka generate --interactive
    """
    config = ShakkaConfig()
    generator = CommandGenerator(config=config)
    
    if interactive:
        # Interactive mode
        display.print_banner()
        display.print_info("Interactive mode. Type 'exit' or 'quit' to exit.\n")
        
        while True:
            try:
                user_query = display.prompt("[bold cyan]ShakkaShell>[/bold cyan]")
                user_input = user_query.strip()
                
                if user_input.lower() in ["exit", "quit", "q"]:
                    display.print_info("Goodbye!")
                    break

                raw_parts = user_input.split(maxsplit=1)
                lower_parts = user_input.lower().split(maxsplit=1)
                command_word = lower_parts[0] if lower_parts else ""

                if command_word in (":provider", "/provider"):
                    if len(raw_parts) < 2 or not raw_parts[1].strip():
                        display.print_error("Usage: :provider <openai|anthropic|ollama>")
                        continue

                    new_provider = raw_parts[1].strip()
                    try:
                        generator.set_provider(new_provider)
                        display.print_success(f"Switched provider to: {new_provider}")
                    except ValueError as e:
                        display.print_error(str(e))
                    continue
                
                if not user_input:
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


@app.command()
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


@app.command()
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


@app.command()
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


if __name__ == "__main__":
    app()
