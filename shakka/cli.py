"""Command-line interface for ShakkaShell using Typer."""

import asyncio
from typing import Optional

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.syntax import Syntax

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
from shakka.exploit import (
    ExploitPipeline,
    ExploitResult,
    ExploitSource,
)
from shakka.mcp import (
    MCPServer,
    MCPHTTPTransport,
    HTTPTransportConfig,
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


@app.command(name="exploit")
def exploit_command(
    cve_id: str = typer.Argument(
        ...,
        help="CVE identifier to search for exploits (e.g., CVE-2024-1234)"
    ),
    source: Optional[str] = typer.Option(
        None,
        "--source",
        "-s",
        help="Specific source to search (nvd, exploit_db, github, llm)"
    ),
    show_code: bool = typer.Option(
        False,
        "--code",
        "-c",
        help="Show exploit code if available"
    ),
    limit: int = typer.Option(
        5,
        "--limit",
        "-n",
        help="Maximum number of results to display"
    ),
    no_llm: bool = typer.Option(
        False,
        "--no-llm",
        help="Disable LLM-based exploit synthesis"
    ),
):
    """Search for exploits by CVE identifier.
    
    Searches NVD, Exploit-DB, GitHub, and optionally synthesizes
    exploits using LLM based on vulnerability details.
    
    Examples:
        shakka exploit CVE-2024-1234
        shakka exploit CVE-2023-44487 --source exploit_db
        shakka exploit CVE-2021-44228 --code --limit 3
        shakka exploit CVE-2020-1472 --no-llm
    """
    # Validate CVE format
    import re
    cve_pattern = r"^CVE-\d{4}-\d{4,}$"
    cve_id = cve_id.upper().strip()
    
    if not re.match(cve_pattern, cve_id):
        display.print_error(f"Invalid CVE format: {cve_id}")
        display.print_info("Expected format: CVE-YYYY-NNNN (e.g., CVE-2024-1234)")
        raise typer.Exit(code=1)
    
    # Parse source filter
    sources = None
    if source:
        try:
            sources = [ExploitSource(source.lower())]
        except ValueError:
            valid_sources = ", ".join(s.value for s in ExploitSource)
            display.print_error(f"Invalid source: {source}")
            display.print_info(f"Valid sources: {valid_sources}")
            raise typer.Exit(code=1)
    
    # Create pipeline
    config = ShakkaConfig()
    pipeline = ExploitPipeline(
        nvd_api_key=getattr(config, 'nvd_api_key', None),
        github_token=getattr(config, 'github_token', None),
        enable_llm_synthesis=not no_llm,
        safety_check=True,
    )
    
    display.console.print(Panel(
        f"[bold cyan]Searching for exploits:[/bold cyan] {cve_id}",
        title="[bold green]CVE Exploit Search[/bold green]",
        border_style="green",
    ))
    display.console.print()
    
    # Search for exploits
    try:
        with display.print_spinner_context(f"Searching for {cve_id}..."):
            results = asyncio.run(pipeline.search(cve_id, sources=sources))
    except Exception as e:
        display.print_error(f"Search failed: {e}")
        raise typer.Exit(code=1)
    
    if not results:
        display.print_warning(f"No exploits found for {cve_id}")
        display.print_info("Try searching with different sources or check if the CVE exists")
        raise typer.Exit(code=0)
    
    # Display results
    display.print_success(f"Found {len(results)} result(s) for {cve_id}")
    display.console.print()
    
    # Create results table
    table = Table(title=f"Exploits for {cve_id}", show_header=True, header_style="bold cyan")
    table.add_column("#", style="dim", width=3)
    table.add_column("Source", width=12)
    table.add_column("Title", min_width=30)
    table.add_column("Confidence", justify="center", width=12)
    table.add_column("Status", width=15)
    
    for i, result in enumerate(results[:limit], 1):
        # Format confidence as percentage
        confidence = f"{result.confidence:.0%}"
        
        # Format status
        verified = "✅ Verified" if result.verified else "⚠️ Unverified"
        safe = " 🔒" if result.safe_for_testing else ""
        status = f"{verified}{safe}"
        
        # Source badge
        source_badge = result.source.value.upper()
        
        table.add_row(
            str(i),
            source_badge,
            result.title[:40] + "..." if len(result.title) > 40 else result.title,
            confidence,
            status,
        )
    
    display.console.print(table)
    display.console.print()
    
    # Display detailed results
    for i, result in enumerate(results[:limit], 1):
        display.console.print(f"[bold]#{i} - {result.title}[/bold]")
        display.console.print(f"  [dim]Source:[/dim] {result.source.value}")
        display.console.print(f"  [dim]CVE:[/dim] {result.cve_id}")
        
        if result.url:
            display.console.print(f"  [dim]URL:[/dim] [link={result.url}]{result.url}[/link]")
        
        if result.description:
            desc = result.description[:150] + "..." if len(result.description) > 150 else result.description
            display.console.print(f"  [dim]Description:[/dim] {desc}")
        
        # Show code if requested and available
        if show_code and result.code:
            display.console.print()
            display.console.print(f"  [bold]Exploit Code:[/bold]")
            
            # Determine language for syntax highlighting
            lang = "python"
            if result.code.startswith("#!/bin/bash") or result.code.startswith("#!/usr/bin/env bash"):
                lang = "bash"
            elif "<script" in result.code.lower() or "<!doctype" in result.code.lower():
                lang = "html"
            elif "import java" in result.code or "public class" in result.code:
                lang = "java"
            elif "#include" in result.code:
                lang = "c"
            
            syntax = Syntax(
                result.code[:2000] + "\n..." if len(result.code) > 2000 else result.code,
                lang,
                theme="monokai",
                line_numbers=True,
            )
            display.console.print(Panel(syntax, title="Code", border_style="blue"))
        
        # Show metadata
        if result.metadata:
            meta_items = []
            if "cvss" in result.metadata and result.metadata["cvss"]:
                cvss = result.metadata["cvss"]
                meta_items.append(f"CVSS: {cvss.get('score', 'N/A')} ({cvss.get('severity', 'N/A')})")
            if "stars" in result.metadata:
                meta_items.append(f"⭐ {result.metadata['stars']}")
            if "edb_id" in result.metadata:
                meta_items.append(f"EDB-{result.metadata['edb_id']}")
            if meta_items:
                display.console.print(f"  [dim]Info:[/dim] {' | '.join(meta_items)}")
        
        display.console.print()
    
    # Summary
    if len(results) > limit:
        display.print_info(f"Showing {limit} of {len(results)} results. Use --limit to see more.")


@app.command(name="mcp")
def mcp_command(
    port: Optional[int] = typer.Option(
        None,
        "--port",
        "-p",
        help="Port for HTTP transport (if not specified, uses stdio)"
    ),
    transport: str = typer.Option(
        "stdio",
        "--transport",
        "-t",
        help="Transport type: stdio, http, or sse"
    ),
    host: str = typer.Option(
        "127.0.0.1",
        "--host",
        "-H",
        help="Host to bind to (for HTTP/SSE transport)"
    ),
    auth_token: Optional[str] = typer.Option(
        None,
        "--auth-token",
        help="Bearer token for HTTP authentication"
    ),
):
    """Start MCP (Model Context Protocol) server.
    
    Exposes ShakkaShell as an MCP server for integration with AI clients
    like Claude Desktop, VS Code with Continue/Copilot, and Cursor IDE.
    
    Transport modes:
      - stdio: JSON-RPC over standard input/output (default)
      - http: JSON-RPC over HTTP POST
      - sse: HTTP with Server-Sent Events for notifications
    
    Examples:
        shakka mcp                          # Start stdio server
        shakka mcp --port 3000              # Start HTTP server on port 3000
        shakka mcp --transport sse -p 3000  # HTTP with SSE support
        shakka mcp -p 3000 --auth-token secret  # HTTP with authentication
    """
    # Validate transport option
    valid_transports = ["stdio", "http", "sse"]
    transport = transport.lower()
    if transport not in valid_transports:
        display.print_error(f"Invalid transport: {transport}")
        display.print_info(f"Valid transports: {', '.join(valid_transports)}")
        raise typer.Exit(code=1)
    
    # If port is specified, default to HTTP transport
    if port is not None and transport == "stdio":
        transport = "http"
    
    # Create MCP server
    server = MCPServer()
    
    if transport == "stdio":
        # Stdio transport
        display.print_info("Starting MCP server with stdio transport...")
        display.print_info("Waiting for JSON-RPC messages on stdin...")
        display.console.print()
        display.console.print("[dim]Press Ctrl+C to stop[/dim]")
        
        try:
            asyncio.run(server.run_stdio())
        except KeyboardInterrupt:
            display.print_info("\nMCP server stopped.")
    
    else:
        # HTTP or SSE transport
        if port is None:
            port = 3000
        
        # Configure HTTP transport
        http_config = HTTPTransportConfig(
            host=host,
            port=port,
            cors_enabled=True,
            auth_enabled=auth_token is not None,
            auth_token=auth_token,
            enable_sse=(transport == "sse"),
        )
        
        # Create and start HTTP transport
        http_transport = MCPHTTPTransport(server, config=http_config)
        
        display.console.print(Panel(
            f"[bold cyan]MCP Server[/bold cyan]\n\n"
            f"[bold]Transport:[/bold] {transport.upper()}\n"
            f"[bold]Address:[/bold] {http_transport.address}\n"
            f"[bold]SSE Enabled:[/bold] {'Yes' if transport == 'sse' else 'No'}\n"
            f"[bold]Auth:[/bold] {'Enabled' if auth_token else 'Disabled'}",
            title="[bold green]MCP Server Started[/bold green]",
            border_style="green",
        ))
        display.console.print()
        display.console.print("[dim]Endpoints:[/dim]")
        display.console.print(f"  [dim]Health:[/dim] {http_transport.address}/health")
        display.console.print(f"  [dim]Info:[/dim] {http_transport.address}/info")
        display.console.print(f"  [dim]JSON-RPC:[/dim] POST {http_transport.address}/")
        if transport == "sse":
            display.console.print(f"  [dim]SSE Stream:[/dim] {http_transport.address}/sse")
        display.console.print()
        display.console.print("[dim]Press Ctrl+C to stop[/dim]")
        
        try:
            http_transport.start(blocking=True)
        except KeyboardInterrupt:
            display.print_info("\nMCP server stopped.")
        finally:
            http_transport.stop()


if __name__ == "__main__":
    app()
