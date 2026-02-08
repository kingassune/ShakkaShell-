"""Specialized security agents for different tasks.

Provides concrete agent implementations for:
- Reconnaissance
- Exploitation
- Persistence
- Reporting
"""

import json
from typing import Optional, TYPE_CHECKING

from .base import Agent, AgentConfig, AgentResult, AgentRole, AgentState

if TYPE_CHECKING:
    from shakka.config import ShakkaConfig


def create_agent_from_config(
    role: AgentRole,
    shakka_config: "ShakkaConfig",
    shared_memory=None,
) -> Agent:
    """Create an agent with model/provider settings from ShakkaConfig.
    
    This factory function reads the per-role model and provider configuration
    and creates the appropriate agent with those settings.
    
    Args:
        role: The agent role to create.
        shakka_config: ShakkaConfig instance with agent model settings.
        shared_memory: Optional shared memory store.
        
    Returns:
        Configured agent instance.
        
    Example:
        from shakka.config import ShakkaConfig
        from shakka.agents.roles import create_agent_from_config
        from shakka.agents.base import AgentRole
        
        config = ShakkaConfig()
        recon_agent = create_agent_from_config(AgentRole.RECON, config)
    """
    role_name = role.value
    model = shakka_config.get_agent_model(role_name)
    provider = shakka_config.get_agent_provider(role_name)
    
    agent_config = AgentConfig(
        role=role,
        provider=provider,
        model=model,
        max_retries=shakka_config.agent_max_retries,
        timeout_seconds=shakka_config.agent_timeout,
        verbose=shakka_config.agent_verbose,
        use_shared_memory=shared_memory is not None,
    )
    
    agent_classes = {
        AgentRole.RECON: ReconAgent,
        AgentRole.EXPLOIT: ExploitAgent,
        AgentRole.PERSISTENCE: PersistenceAgent,
        AgentRole.REPORTER: ReporterAgent,
    }
    
    agent_class = agent_classes.get(role)
    if agent_class is None:
        raise ValueError(f"Unsupported agent role: {role}")
    
    return agent_class(config=agent_config, shared_memory=shared_memory, shakka_config=shakka_config)


class ReconAgent(Agent):
    """Agent specialized in reconnaissance and enumeration.
    
    Executes real security tools (nmap, etc.) and analyzes actual output.
    
    Handles tasks like:
    - Network scanning with nmap
    - Service detection
    - Version enumeration
    - Attack surface mapping
    """
    
    def __init__(
        self,
        config: Optional[AgentConfig] = None,
        shared_memory=None,
        shakka_config: Optional["ShakkaConfig"] = None,
    ):
        """Initialize the recon agent.
        
        Args:
            config: Agent configuration.
            shared_memory: Optional shared memory store.
            shakka_config: Optional ShakkaConfig for provider settings.
        """
        if config is None:
            config = AgentConfig(role=AgentRole.RECON, model="gpt-4o")
        else:
            config.role = AgentRole.RECON
        
        super().__init__(config, shared_memory, shakka_config)
        
        # Import executor for running real commands
        from shakka.core.executor import CommandExecutor
        self._executor = CommandExecutor(default_timeout=300)
    
    def _extract_target(self, task: str) -> Optional[str]:
        """Extract target IP or hostname from task description.
        
        Args:
            task: Task description containing target.
            
        Returns:
            Extracted target or None.
        """
        import re
        
        # Match IP addresses (with optional port)
        ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?(?:/\d{1,2})?\b'
        ip_match = re.search(ip_pattern, task)
        if ip_match:
            return ip_match.group()
        
        # Match localhost (with optional port)
        localhost_pattern = r'\blocalhost(?::\d+)?\b'
        localhost_match = re.search(localhost_pattern, task, re.IGNORECASE)
        if localhost_match:
            return localhost_match.group()
        
        # Match hostnames/domains (with optional port)
        domain_pattern = r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}(?::\d+)?\b'
        domain_match = re.search(domain_pattern, task)
        if domain_match:
            return domain_match.group()
        
        return None
    
    async def _run_nmap(self, target: str, scan_type: str = "default") -> dict:
        """Run nmap scan and parse results.
        
        Args:
            target: Target IP or hostname.
            scan_type: Type of scan (default, aggressive, stealth, quick).
            
        Returns:
            Dict with scan results.
        """
        # Build nmap command based on scan type
        nmap_flags = {
            "default": "-sV -sC",
            "aggressive": "-A -T4",
            "stealth": "-sS -T2",
            "quick": "-F -T4",
            "full": "-p- -sV",
        }
        
        flags = nmap_flags.get(scan_type, nmap_flags["default"])
        command = f"nmap {flags} {target}"
        
        self._log_event("nmap_started", {"target": target, "command": command})
        
        # Execute nmap
        result = await self._executor.execute(command, timeout=300)
        
        return {
            "command": command,
            "success": result.success,
            "output": result.stdout,
            "stderr": result.stderr,
            "execution_time": result.execution_time,
        }
    
    def _parse_nmap_output(self, output: str) -> dict:
        """Parse nmap output into structured data.
        
        Args:
            output: Raw nmap output.
            
        Returns:
            Structured scan results.
        """
        import re
        
        results = {
            "host": None,
            "state": None,
            "ports": [],
            "os_detection": None,
            "raw_output": output,
        }
        
        # Parse host status
        host_match = re.search(r'Nmap scan report for ([^\s]+)', output)
        if host_match:
            results["host"] = host_match.group(1)
        
        state_match = re.search(r'Host is (up|down)', output)
        if state_match:
            results["state"] = state_match.group(1)
        
        # Parse open ports
        port_pattern = r'(\d+)/(\w+)\s+(open|closed|filtered)\s+(\S+)(?:\s+(.*))?'
        for match in re.finditer(port_pattern, output):
            port_info = {
                "port": int(match.group(1)),
                "protocol": match.group(2),
                "state": match.group(3),
                "service": match.group(4),
                "version": match.group(5).strip() if match.group(5) else None,
            }
            if port_info["state"] == "open":
                results["ports"].append(port_info)
        
        # Parse OS detection
        os_match = re.search(r'OS details?: ([^\n]+)', output)
        if os_match:
            results["os_detection"] = os_match.group(1)
        
        # Parse service info
        service_match = re.search(r'Service Info: ([^\n]+)', output)
        if service_match:
            results["service_info"] = service_match.group(1)
        
        return results
    
    async def execute(self, task: str, context: Optional[dict] = None) -> AgentResult:
        """Execute a reconnaissance task with real tool execution.
        
        Args:
            task: Recon task description (should contain target IP/hostname).
            context: Optional context.
            
        Returns:
            Recon results from actual scans.
        """
        self._log_event("recon_started", {"task": task[:100]})
        
        # Extract target from task first
        target = self._extract_target(task)
        
        # If no target in task, check context for objective or plan
        if not target and context:
            # Check plan objective
            plan = context.get("plan", {})
            if plan.get("objective"):
                target = self._extract_target(plan["objective"])
            
            # Check if target was passed directly in context
            if not target and context.get("target"):
                target = context["target"]
        
        if not target:
            return AgentResult(
                success=False,
                output=f"Could not extract target from task: {task}",
                error="No valid IP address or hostname found in task description",
            )
        
        # Store in memory if available
        if self._shared_memory:
            from shakka.storage.memory import MemoryType
            self._shared_memory.remember(
                f"Recon task: {task} - Target: {target}",
                memory_type=MemoryType.SESSION,
                metadata={"agent": self.name, "target": target},
            )
        
        # Determine scan type from task description
        task_lower = task.lower()
        if "aggressive" in task_lower or "full" in task_lower:
            scan_type = "aggressive"
        elif "stealth" in task_lower or "quiet" in task_lower:
            scan_type = "stealth"
        elif "quick" in task_lower or "fast" in task_lower:
            scan_type = "quick"
        else:
            scan_type = "default"
        
        # Run actual nmap scan
        try:
            nmap_result = await self._run_nmap(target, scan_type)
            
            if not nmap_result["success"]:
                return AgentResult(
                    success=False,
                    output=f"Nmap scan failed: {nmap_result['stderr']}",
                    error=nmap_result["stderr"],
                    data={"command": nmap_result["command"]},
                )
            
            # Parse the real nmap output
            parsed = self._parse_nmap_output(nmap_result["output"])
            
            # Now use LLM to analyze the REAL results
            analysis_prompt = f"""Analyze the following REAL nmap scan results and provide security insights:

TARGET: {target}
COMMAND: {nmap_result['command']}

SCAN RESULTS:
{nmap_result['output']}

PARSED DATA:
- Host: {parsed.get('host')}
- State: {parsed.get('state')}
- Open Ports: {json.dumps(parsed['ports'], indent=2)}
- OS Detection: {parsed.get('os_detection', 'Not detected')}

Provide your analysis as JSON:
{{
  "target": "{target}",
  "summary": "Brief summary of what was found",
  "open_ports_analysis": [
    {{"port": N, "service": "name", "version": "ver", "risk_notes": "any security concerns"}}
  ],
  "potential_vulnerabilities": [
    {{"service": "name", "concern": "what to investigate", "severity": "high/medium/low"}}
  ],
  "recommended_next_steps": ["next step 1", "next step 2"],
  "overall_risk": "low/medium/high/critical"
}}

Base your analysis ONLY on the actual scan data above. Do NOT make up information."""

            llm_response = await self._call_llm(analysis_prompt, context)
            
            # Parse LLM analysis
            try:
                if "```json" in llm_response:
                    import re
                    json_match = re.search(r"```json\s*(.*?)\s*```", llm_response, re.DOTALL)
                    if json_match:
                        llm_response = json_match.group(1)
                elif "```" in llm_response:
                    import re
                    json_match = re.search(r"```\s*(.*?)\s*```", llm_response, re.DOTALL)
                    if json_match:
                        llm_response = json_match.group(1)
                
                analysis = json.loads(llm_response)
            except json.JSONDecodeError:
                analysis = {"raw_analysis": llm_response}
            
            # Combine real data with LLM analysis
            findings = {
                "target": target,
                "scan_command": nmap_result["command"],
                "execution_time": nmap_result["execution_time"],
                "raw_output": nmap_result["output"],
                "parsed_ports": parsed["ports"],
                "os_detection": parsed.get("os_detection"),
                "analysis": analysis,
            }
            
            # Build human-readable output
            port_summary = ", ".join([f"{p['port']}/{p['service']}" for p in parsed['ports'][:10]])
            output = f"""Reconnaissance completed for target: {target}

Command: {nmap_result['command']}
Execution Time: {nmap_result['execution_time']:.1f}s
Host State: {parsed.get('state', 'unknown')}

Open Ports: {port_summary or 'None found'}

{analysis.get('summary', 'See data for full analysis.')}"""

            return AgentResult(
                success=True,
                output=output,
                data=findings,
                execution_time=nmap_result["execution_time"],
            )
            
        except Exception as e:
            return AgentResult(
                success=False,
                output=f"Recon failed: {str(e)}",
                error=str(e),
            )


class ExploitAgent(Agent):
    """Agent specialized in exploitation and vulnerability analysis.
    
    Analyzes real recon data to identify vulnerabilities and suggest exploits.
    When auto_exploit is enabled in context, will attempt actual exploitation.
    
    Handles tasks like:
    - Vulnerability identification from real scan data
    - Exploit selection based on actual services
    - CVE lookup for detected versions
    - Attack vector analysis
    - Actual exploitation attempts (when enabled)
    """
    
    def __init__(
        self,
        config: Optional[AgentConfig] = None,
        shared_memory=None,
        shakka_config: Optional["ShakkaConfig"] = None,
    ):
        """Initialize the exploit agent.
        
        Args:
            config: Agent configuration.
            shared_memory: Optional shared memory store.
            shakka_config: Optional ShakkaConfig for provider settings.
        """
        if config is None:
            config = AgentConfig(role=AgentRole.EXPLOIT, model="gpt-4o")
        else:
            config.role = AgentRole.EXPLOIT
        
        super().__init__(config, shared_memory, shakka_config)
        
        # Import executor for running exploit commands
        from shakka.core.executor import CommandExecutor
        self._executor = CommandExecutor(default_timeout=120)
    
    async def _generate_exploit_commands(
        self,
        target: str,
        vulnerabilities: list,
        recommended_exploits: list,
        ports: list,
        raw_output: str,
    ) -> list:
        """Use LLM to generate specific exploit commands for the target.
        
        Args:
            target: Target IP/hostname.
            vulnerabilities: Identified vulnerabilities.
            recommended_exploits: Suggested exploits.
            ports: Open ports with service info.
            raw_output: Raw nmap output for context.
            
        Returns:
            List of exploit commands to try.
        """
        # Build services info
        services_info = ""
        for port in ports:
            version = port.get('version', 'unknown version')
            services_info += f"  - {port.get('port')}/{port.get('protocol')}: {port.get('service')} ({version})\n"
        
        vulns_info = json.dumps(vulnerabilities, indent=2) if vulnerabilities else "None identified"
        exploits_info = json.dumps(recommended_exploits, indent=2) if recommended_exploits else "None suggested"
        
        prompt = f"""You are a penetration testing expert. Based on the following scan results, generate SPECIFIC exploitation commands that can be run on a Linux system.

TARGET: {target}

OPEN PORTS AND SERVICES:
{services_info}

IDENTIFIED VULNERABILITIES:
{vulns_info}

SUGGESTED EXPLOITS:
{exploits_info}

RAW NMAP OUTPUT (partial):
{raw_output[:2000]}

Generate a list of practical exploitation commands. For each command:
1. Use tools commonly available on Kali/Parrot (curl, nikto, sqlmap, hydra, nmap scripts, searchsploit, nuclei, etc.)
2. Include the actual target IP/hostname and port in the command
3. Focus on exploits likely to give shell access or sensitive data
4. Order by likelihood of success (most likely first)

IMPORTANT RULES:
- Generate REAL, EXECUTABLE commands - not pseudocode
- Use the exact target: {target}
- Include proper timeouts to avoid hanging
- Maximum 10 commands
- Focus on the specific services and versions found

Respond as JSON array:
[
  {{
    "command": "the actual command to run",
    "description": "what this tests/exploits",
    "service": "which service this targets",
    "port": port_number,
    "success_indicators": ["strings that indicate success", "like 'uid=' or 'root:'"],
    "timeout": seconds_to_wait
  }}
]

Only output the JSON array, no other text."""

        try:
            response = await self._call_llm(prompt, None)
            
            # Parse response
            import re
            if "```json" in response:
                json_match = re.search(r"```json\s*(.*?)\s*```", response, re.DOTALL)
                if json_match:
                    response = json_match.group(1)
            elif "```" in response:
                json_match = re.search(r"```\s*(.*?)\s*```", response, re.DOTALL)
                if json_match:
                    response = json_match.group(1)
            
            commands = json.loads(response)
            return commands if isinstance(commands, list) else []
            
        except Exception as e:
            self._log_event("exploit_generation_failed", {"error": str(e)})
            return []
    
    async def _attempt_exploitation(
        self, 
        target: str, 
        vulnerabilities: list, 
        recommended_exploits: list,
        ports: list,
        raw_output: str = "",
    ) -> dict:
        """Attempt actual exploitation using LLM-generated commands.
        
        Args:
            target: Target IP/hostname.
            vulnerabilities: List of identified vulnerabilities.
            recommended_exploits: List of recommended exploits.
            ports: List of open ports with service info.
            raw_output: Raw nmap output for context.
            
        Returns:
            Dict with exploitation results.
        """
        from rich.console import Console
        from rich.panel import Panel
        from rich.syntax import Syntax
        
        console = Console()
        verbose = self.config.verbose
        
        results = {
            "attempted": [],
            "successful": [],
            "failed": [],
            "shells_obtained": [],
            "data_obtained": [],
        }
        
        if verbose:
            console.print()
            console.print(Panel(
                f"[bold cyan]Target:[/bold cyan] {target}\n"
                f"[bold cyan]Vulnerabilities:[/bold cyan] {len(vulnerabilities)}\n"
                f"[bold cyan]Generating exploit commands...[/bold cyan]",
                title="[bold red]🔥 EXPLOITATION PHASE[/bold red]",
                border_style="red",
            ))
        
        # Generate dynamic exploit commands using LLM
        exploit_commands = await self._generate_exploit_commands(
            target=target,
            vulnerabilities=vulnerabilities,
            recommended_exploits=recommended_exploits,
            ports=ports,
            raw_output=raw_output,
        )
        
        if not exploit_commands:
            # Fallback to basic enumeration if LLM fails
            if verbose:
                console.print("[yellow]LLM generation failed, using fallback commands...[/yellow]")
            exploit_commands = self._get_fallback_commands(target, ports)
        
        if verbose:
            console.print(f"\n[bold]📋 {len(exploit_commands)} exploit commands to execute:[/bold]\n")
        
        self._log_event("exploitation_started", {
            "target": target,
            "commands_to_try": len(exploit_commands),
        })
        
        for idx, cmd_info in enumerate(exploit_commands, 1):
            command = cmd_info.get("command", "")
            description = cmd_info.get("description", "Unknown exploit")
            service = cmd_info.get("service", "unknown")
            port = cmd_info.get("port", 0)
            success_indicators = cmd_info.get("success_indicators", [])
            timeout = min(cmd_info.get("timeout", 30), 120)  # Cap at 2 minutes
            
            if not command:
                continue
            
            # Safety check - skip obviously dangerous commands
            if self._is_dangerous_command(command):
                self._log_event("dangerous_command_skipped", {"command": command})
                if verbose:
                    console.print(f"  [dim]⏭️  Skipping dangerous command[/dim]")
                continue
            
            if verbose:
                console.print(f"[bold cyan]━━━ Exploit {idx}/{len(exploit_commands)} ━━━[/bold cyan]")
                console.print(f"  [bold]Description:[/bold] {description}")
                console.print(f"  [bold]Service:[/bold] {service}:{port}")
                console.print(f"  [bold]Command:[/bold]")
                console.print(Syntax(command, "bash", theme="monokai", line_numbers=False, word_wrap=True))
                console.print(f"  [dim]Executing (timeout: {timeout}s)...[/dim]")
            
            exploit_attempt = {
                "command": command,
                "description": description,
                "service": service,
                "port": port,
                "output": "",
                "success": False,
            }
            
            try:
                self._log_event("running_exploit", {"command": command[:100]})
                
                result = await self._executor.execute(command, timeout=timeout)
                
                exploit_attempt["output"] = result.stdout[:2000] if result.stdout else ""
                if result.stderr:
                    exploit_attempt["output"] += f"\nSTDERR: {result.stderr[:500]}"
                
                # Check for success indicators
                output_lower = (result.stdout or "").lower()
                for indicator in success_indicators:
                    if indicator.lower() in output_lower:
                        exploit_attempt["success"] = True
                        break
                
                # Also check common success patterns
                common_success = [
                    "uid=", "root:", "password", "credentials", 
                    "access granted", "logged in", "welcome",
                    "shell", "flag{", "ctf{", "admin",
                ]
                for pattern in common_success:
                    if pattern in output_lower:
                        exploit_attempt["success"] = True
                        break
                
                # Display result in verbose mode
                if verbose:
                    if exploit_attempt["success"]:
                        console.print(f"  [bold green]✅ SUCCESS![/bold green]")
                        if result.stdout:
                            output_preview = result.stdout[:500].strip()
                            console.print(Panel(
                                output_preview,
                                title="[green]Output[/green]",
                                border_style="green",
                            ))
                    else:
                        console.print(f"  [dim]❌ No success indicators found[/dim]")
                        if result.stdout and len(result.stdout.strip()) > 0:
                            output_preview = result.stdout[:200].strip()
                            console.print(f"  [dim]Output: {output_preview}...[/dim]" if len(result.stdout) > 200 else f"  [dim]Output: {output_preview}[/dim]")
                    console.print()
                
                if exploit_attempt["success"]:
                    results["successful"].append(exploit_attempt)
                    
                    # Categorize the success
                    if "uid=" in output_lower or "shell" in description.lower():
                        results["shells_obtained"].append({
                            "type": service,
                            "command": command,
                            "target": target,
                            "port": port,
                            "output": result.stdout[:500],
                        })
                    else:
                        results["data_obtained"].append({
                            "type": service,
                            "description": description,
                            "data": result.stdout[:1000],
                        })
                else:
                    results["failed"].append(exploit_attempt)
                
            except Exception as e:
                exploit_attempt["output"] = f"Error: {str(e)}"
                results["failed"].append(exploit_attempt)
                if verbose:
                    console.print(f"  [red]⚠️  Error: {str(e)}[/red]")
                    console.print()
            
            results["attempted"].append(exploit_attempt)
        
        # Summary in verbose mode
        if verbose:
            console.print(Panel(
                f"[bold]Attempted:[/bold] {len(results['attempted'])}\n"
                f"[bold green]Successful:[/bold green] {len(results['successful'])}\n"
                f"[bold red]Failed:[/bold red] {len(results['failed'])}\n"
                f"[bold yellow]Shells:[/bold yellow] {len(results['shells_obtained'])}\n"
                f"[bold cyan]Data Leaks:[/bold cyan] {len(results['data_obtained'])}",
                title="[bold]📊 Exploitation Summary[/bold]",
                border_style="blue",
            ))
        
        return results
    
    def _get_fallback_commands(self, target: str, ports: list) -> list:
        """Generate fallback exploitation commands when LLM fails.
        
        Args:
            target: Target IP/hostname.
            ports: List of open ports.
            
        Returns:
            List of basic exploitation commands.
        """
        commands = []
        
        for port_info in ports:
            port = port_info.get("port")
            service = port_info.get("service", "").lower()
            
            # Web services
            if service in ["http", "https"] or port in [80, 443, 8080, 8443, 3000, 3001]:
                protocol = "https" if port == 443 else "http"
                commands.extend([
                    {
                        "command": f"curl -s -I {protocol}://{target}:{port}/ | head -20",
                        "description": "HTTP header reconnaissance",
                        "service": service,
                        "port": port,
                        "success_indicators": ["200 OK", "Server:"],
                        "timeout": 10,
                    },
                    {
                        "command": f"curl -s '{protocol}://{target}:{port}/robots.txt' 2>/dev/null",
                        "description": "Check robots.txt for hidden paths",
                        "service": service,
                        "port": port,
                        "success_indicators": ["Disallow:", "User-agent:"],
                        "timeout": 10,
                    },
                    {
                        "command": f"curl -s '{protocol}://{target}:{port}/?id=1%27%20OR%20%271%27=%271' 2>/dev/null | head -30",
                        "description": "Basic SQL injection test",
                        "service": service,
                        "port": port,
                        "success_indicators": ["error", "sql", "mysql", "syntax"],
                        "timeout": 15,
                    },
                ])
            
            # SSH
            elif service == "ssh" or port == 22:
                commands.append({
                    "command": f"ssh-audit {target} 2>/dev/null | head -30 || nmap -p {port} --script ssh-auth-methods {target}",
                    "description": "SSH security audit",
                    "service": "ssh",
                    "port": port,
                    "success_indicators": ["weak", "vulnerable", "password"],
                    "timeout": 30,
                })
            
            # FTP
            elif service == "ftp" or port == 21:
                commands.append({
                    "command": f"curl -s 'ftp://anonymous:anonymous@{target}/' 2>/dev/null | head -20",
                    "description": "FTP anonymous access test",
                    "service": "ftp",
                    "port": port,
                    "success_indicators": ["drwx", "-rw", "total"],
                    "timeout": 15,
                })
            
            # SMB
            elif service in ["smb", "microsoft-ds", "netbios-ssn"] or port in [445, 139]:
                commands.append({
                    "command": f"smbclient -N -L //{target}/ 2>/dev/null | head -30",
                    "description": "SMB null session enumeration",
                    "service": "smb",
                    "port": port,
                    "success_indicators": ["Sharename", "IPC$", "ADMIN$"],
                    "timeout": 20,
                })
            
            # MySQL
            elif service == "mysql" or port == 3306:
                commands.append({
                    "command": f"mysql -h {target} -u root --connect-timeout=5 -e 'SELECT version();' 2>/dev/null",
                    "description": "MySQL root no-password test",
                    "service": "mysql",
                    "port": port,
                    "success_indicators": ["version", "MariaDB", "MySQL"],
                    "timeout": 10,
                })
            
            # Redis
            elif service == "redis" or port == 6379:
                commands.append({
                    "command": f"redis-cli -h {target} -p {port} INFO 2>/dev/null | head -20",
                    "description": "Redis unauthenticated access",
                    "service": "redis",
                    "port": port,
                    "success_indicators": ["redis_version", "connected_clients"],
                    "timeout": 10,
                })
            
            # MongoDB
            elif service == "mongodb" or port == 27017:
                commands.append({
                    "command": f"mongosh --host {target} --eval 'db.adminCommand({{listDatabases:1}})' 2>/dev/null | head -20",
                    "description": "MongoDB unauthenticated access",
                    "service": "mongodb",
                    "port": port,
                    "success_indicators": ["databases", "name", "sizeOnDisk"],
                    "timeout": 15,
                })
        
        return commands
    
    def _is_dangerous_command(self, command: str) -> bool:
        """Check if a command is too dangerous to execute.
        
        Args:
            command: Command string to check.
            
        Returns:
            True if command should be skipped.
        """
        dangerous_patterns = [
            "rm -rf",
            "mkfs",
            "> /dev/",
            "dd if=",
            ":(){:|:&};:",  # Fork bomb
            "chmod -R 777 /",
            "wget.*|.*bash",
            "curl.*|.*sh",
            "nc.*-e",
            "/dev/tcp",
        ]
        
        command_lower = command.lower()
        for pattern in dangerous_patterns:
            if pattern.lower() in command_lower:
                return True
        
        return False
    
    def _extract_real_recon_data(self, context: Optional[dict]) -> dict:
        """Extract real recon data from previous results.
        
        Args:
            context: Context with previous_results.
            
        Returns:
            Extracted recon data or empty dict.
        """
        if not context or "previous_results" not in context:
            return {}
        
        for result in context.get("previous_results", []):
            data = result.get("data", {})
            # Look for real nmap data
            if "parsed_ports" in data or "raw_output" in data:
                return data
        
        return {}
    
    async def execute(self, task: str, context: Optional[dict] = None) -> AgentResult:
        """Execute vulnerability analysis based on real recon data.
        
        Args:
            task: Exploit task description.
            context: Context with recon data from previous step.
            
        Returns:
            Exploitation analysis based on real findings.
        """
        self._log_event("exploit_started", {"task": task[:100]})
        
        # Extract real recon data from previous steps
        recon_data = self._extract_real_recon_data(context)
        
        if not recon_data:
            return AgentResult(
                success=False,
                output="No recon data available. Run reconnaissance first.",
                error="Missing recon data from previous step",
            )
        
        # Get the real findings
        target = recon_data.get("target", "unknown")
        ports = recon_data.get("parsed_ports", [])
        raw_output = recon_data.get("raw_output", "")
        analysis = recon_data.get("analysis", {})
        
        # Build services summary from real data
        services_str = ""
        for port in ports:
            version_str = f" ({port['version']})" if port.get('version') else ""
            services_str += f"  - Port {port['port']}/{port['protocol']}: {port['service']}{version_str}\n"
        
        if not services_str:
            services_str = "  No open ports detected\n"
        
        # Build exploitation prompt with REAL data
        prompt = f"""Analyze the following REAL scan results for vulnerabilities and potential exploits:

TARGET: {target}

ACTUAL OPEN PORTS AND SERVICES:
{services_str}

RAW NMAP OUTPUT:
{raw_output[:3000]}

INITIAL ANALYSIS:
{json.dumps(analysis, indent=2)[:2000] if analysis else 'None'}

Based on the ACTUAL services and versions detected above, provide:

1. Identify known vulnerabilities for the EXACT versions found
2. Suggest realistic exploits that would work against these specific services
3. Prioritize based on likelihood of success

Respond as JSON:
{{
  "target": "{target}",
  "services_analyzed": [
    {{"port": N, "service": "name", "version": "actual version from scan"}}
  ],
  "vulnerabilities": [
    {{
      "service": "service name",
      "port": N,
      "cve": "CVE-XXXX-XXXXX or N/A",
      "severity": "critical|high|medium|low",
      "description": "what the vulnerability is",
      "exploitable": true/false,
      "exploit_difficulty": "easy|medium|hard"
    }}
  ],
  "recommended_exploits": [
    {{
      "name": "exploit name",
      "target_service": "which service",
      "source": "metasploit|exploitdb|manual",
      "command_hint": "how to use it",
      "success_probability": "high|medium|low"
    }}
  ],
  "attack_vectors": ["vector 1", "vector 2"],
  "next_steps": ["what to do next"],
  "summary": "overall vulnerability assessment"
}}

IMPORTANT: Only report vulnerabilities that apply to the ACTUAL versions detected. Do not make up findings."""

        try:
            response = await self._call_llm(prompt, context)
            
            # Parse response
            try:
                import re
                if "```json" in response:
                    json_match = re.search(r"```json\s*(.*?)\s*```", response, re.DOTALL)
                    if json_match:
                        response = json_match.group(1)
                elif "```" in response:
                    json_match = re.search(r"```\s*(.*?)\s*```", response, re.DOTALL)
                    if json_match:
                        response = json_match.group(1)
                
                data = json.loads(response)
            except json.JSONDecodeError:
                data = {"raw_response": response}
            
            # Count findings
            vuln_count = len(data.get("vulnerabilities", []))
            exploit_count = len(data.get("recommended_exploits", []))
            
            output = f"""Vulnerability analysis for: {target}

Services Analyzed: {len(ports)} open ports
Vulnerabilities Found: {vuln_count}
Potential Exploits: {exploit_count}

{data.get('summary', 'See data field for details.')}"""

            # Check if auto-exploitation is enabled
            auto_exploit = context.get("auto_exploit", False) if context else False
            exploitation_results = None
            
            if auto_exploit and vuln_count > 0:
                self._log_event("auto_exploit_started", {"target": target, "vulns": vuln_count})
                
                exploitation_results = await self._attempt_exploitation(
                    target=target,
                    vulnerabilities=data.get("vulnerabilities", []),
                    recommended_exploits=data.get("recommended_exploits", []),
                    ports=ports,
                    raw_output=raw_output,
                )
                
                # Update output with exploitation results
                successful_count = len(exploitation_results.get("successful", []))
                shells_count = len(exploitation_results.get("shells_obtained", []))
                data_count = len(exploitation_results.get("data_obtained", []))
                
                output += f"""

--- EXPLOITATION RESULTS ---
Exploits Attempted: {len(exploitation_results.get('attempted', []))}
Successful Exploits: {successful_count}
Shells Obtained: {shells_count}
Data Leaks Found: {data_count}"""

                if shells_count > 0:
                    output += "\n\n🎯 ACCESS OBTAINED:"
                    for shell in exploitation_results.get("shells_obtained", []):
                        output += f"\n  • {shell.get('type')}: {shell.get('target')}:{shell.get('port')}"
                        if shell.get('credentials'):
                            output += f" ({shell.get('credentials')})"
                        if shell.get('command'):
                            output += f"\n    Command: {shell.get('command')[:80]}"
                
                if data_count > 0:
                    output += "\n\n📄 DATA OBTAINED:"
                    for data_item in exploitation_results.get("data_obtained", [])[:5]:
                        output += f"\n  • {data_item.get('description', 'Unknown')}"

            return AgentResult(
                success=True,
                output=output,
                data={
                    "target": target,
                    "services_scanned": ports,
                    "analysis": data,
                    "exploitation_results": exploitation_results,
                },
            )
        except Exception as e:
            return AgentResult(
                success=False,
                output=f"Exploitation analysis failed: {str(e)}",
                error=str(e),
            )


class PersistenceAgent(Agent):
    """Agent specialized in post-exploitation and persistence.
    
    Handles tasks like:
    - Maintaining access
    - Lateral movement
    - Privilege escalation
    - Avoiding detection
    """
    
    def __init__(
        self,
        config: Optional[AgentConfig] = None,
        shared_memory=None,
        shakka_config: Optional["ShakkaConfig"] = None,
    ):
        """Initialize the persistence agent.
        
        Args:
            config: Agent configuration.
            shared_memory: Optional shared memory store.
            shakka_config: Optional ShakkaConfig for provider settings.
        """
        if config is None:
            config = AgentConfig(role=AgentRole.PERSISTENCE, model="gpt-4o-mini")
        else:
            config.role = AgentRole.PERSISTENCE
        
        super().__init__(config, shared_memory, shakka_config)
    
    async def execute(self, task: str, context: Optional[dict] = None) -> AgentResult:
        """Execute a persistence task using LLM.
        
        Args:
            task: Persistence task description.
            context: Optional context with exploit data.
            
        Returns:
            Persistence results.
        """
        self._log_event("persistence_started", {"task": task[:100]})
        
        # Build persistence prompt
        prompt = f"""Plan persistence mechanisms for the following task:

TASK: {task}

Provide your analysis as JSON with this structure:
{{
  "techniques": [
    {{
      "name": "technique name",
      "mitre_id": "TXXXX.XXX",
      "stealth_level": "high|medium|low",
      "persistence_type": "user|system|boot",
      "command": "implementation command",
      "cleanup": "how to remove later",
      "detection_risk": "what might detect this"
    }}
  ],
  "lateral_movement": [
    {{
      "method": "movement method",
      "prerequisites": ["what's needed"],
      "command": "command to execute"
    }}
  ],
  "privilege_escalation": [
    {{
      "technique": "privesc technique",
      "from": "current privilege",
      "to": "target privilege",
      "command": "command"
    }}
  ],
  "cleanup_plan": ["step 1", "step 2"],
  "summary": "brief summary"
}}

Focus on stealth and avoiding detection."""
        
        try:
            response = await self._call_llm(prompt, context)
            
            # Parse response
            try:
                import re
                if "```json" in response:
                    json_match = re.search(r"```json\s*(.*?)\s*```", response, re.DOTALL)
                    if json_match:
                        response = json_match.group(1)
                elif "```" in response:
                    json_match = re.search(r"```\s*(.*?)\s*```", response, re.DOTALL)
                    if json_match:
                        response = json_match.group(1)
                
                data = json.loads(response)
            except json.JSONDecodeError:
                data = {"raw_response": response}
            
            output = f"""Persistence analysis for: {task}

{data.get('summary', 'See data field for details.')}"""
            
            return AgentResult(
                success=True,
                output=output,
                data=data,
                tokens_used=len(response.split()) * 2,
            )
        except Exception as e:
            return AgentResult(
                success=False,
                output=f"Persistence analysis failed: {str(e)}",
                error=str(e),
            )


class ReporterAgent(Agent):
    """Agent specialized in documentation and reporting.
    
    Generates professional pentest reports from real scan data.
    
    Handles tasks like:
    - Professional report generation
    - Executive summaries
    - Remediation recommendations
    - Risk prioritization
    """
    
    def __init__(
        self,
        config: Optional[AgentConfig] = None,
        shared_memory=None,
        shakka_config: Optional["ShakkaConfig"] = None,
    ):
        """Initialize the reporter agent.
        
        Args:
            config: Agent configuration.
            shared_memory: Optional shared memory store.
            shakka_config: Optional ShakkaConfig for provider settings.
        """
        if config is None:
            config = AgentConfig(role=AgentRole.REPORTER, model="gpt-4o")
        else:
            config.role = AgentRole.REPORTER
        
        super().__init__(config, shared_memory, shakka_config)
    
    def _extract_all_findings(self, context: Optional[dict]) -> dict:
        """Extract all real findings from previous steps.
        
        Args:
            context: Context with previous_results.
            
        Returns:
            Consolidated findings dict.
        """
        findings = {
            "target": None,
            "scan_command": None,
            "ports": [],
            "vulnerabilities": [],
            "exploits": [],
            "raw_output": None,
        }
        
        if not context or "previous_results" not in context:
            return findings
        
        for result in context.get("previous_results", []):
            data = result.get("data", {})
            
            # Extract from recon step
            if "parsed_ports" in data:
                findings["target"] = data.get("target")
                findings["scan_command"] = data.get("scan_command")
                findings["ports"] = data.get("parsed_ports", [])
                findings["raw_output"] = data.get("raw_output")
                if data.get("analysis"):
                    findings["recon_analysis"] = data["analysis"]
            
            # Extract from exploit step  
            if "analysis" in data and "vulnerabilities" in data.get("analysis", {}):
                findings["vulnerabilities"] = data["analysis"].get("vulnerabilities", [])
                findings["exploits"] = data["analysis"].get("recommended_exploits", [])
                findings["exploit_summary"] = data["analysis"].get("summary")
        
        return findings
    
    async def execute(self, task: str, context: Optional[dict] = None) -> AgentResult:
        """Generate a professional report from real scan data.
        
        Args:
            task: Reporting task description.
            context: Context with all previous findings.
            
        Returns:
            Professional pentest report.
        """
        self._log_event("report_started", {"task": task[:100]})
        
        # Extract real findings
        findings = self._extract_all_findings(context)
        target = findings.get("target", "Unknown target")
        
        # Build summary of real findings
        ports_str = ""
        for port in findings.get("ports", []):
            version = f" ({port.get('version')})" if port.get('version') else ""
            ports_str += f"  - {port.get('port')}/{port.get('protocol')}: {port.get('service')}{version}\n"
        
        vulns_str = ""
        for vuln in findings.get("vulnerabilities", []):
            vulns_str += f"  - [{vuln.get('severity', 'unknown').upper()}] {vuln.get('service')}: {vuln.get('description', 'N/A')[:100]}\n"
            if vuln.get('cve'):
                vulns_str += f"    CVE: {vuln.get('cve')}\n"
        
        # Build reporting prompt with REAL data
        prompt = f"""Generate a professional penetration testing report based on the following REAL findings:

TARGET: {target}
SCAN COMMAND: {findings.get('scan_command', 'N/A')}

DISCOVERED SERVICES:
{ports_str if ports_str else 'No services detected'}

IDENTIFIED VULNERABILITIES:
{vulns_str if vulns_str else 'No vulnerabilities identified'}

RAW SCAN OUTPUT (excerpt):
{findings.get('raw_output', 'N/A')[:2000]}

RECON ANALYSIS:
{json.dumps(findings.get('recon_analysis', {}), indent=2)[:1500]}

EXPLOIT SUMMARY:
{findings.get('exploit_summary', 'N/A')}

Generate a professional report as JSON. Base ALL findings on the ACTUAL data above:
{{
  "title": "Penetration Test Report - {target}",
  "date": "Report date",
  "target": "{target}",
  "scope": "What was tested",
  "executive_summary": "High-level summary based on actual findings",
  "methodology": "Describe actual scans performed",
  "findings": [
    {{
      "id": "FIND-001",
      "title": "Finding title based on actual vulnerability",
      "severity": "critical|high|medium|low|informational",
      "affected_service": "port/service from scan",
      "description": "Actual vulnerability details",
      "evidence": "What scan data shows this",
      "impact": "Potential business impact",
      "recommendation": "Specific remediation steps",
      "cve": "CVE if applicable"
    }}
  ],
  "risk_summary": {{
    "critical": count,
    "high": count,
    "medium": count,
    "low": count
  }},
  "recommendations": [
    {{
      "priority": 1,
      "action": "Specific action",
      "rationale": "Based on actual finding"
    }}
  ],
  "conclusion": "Overall security posture based on real findings"
}}

IMPORTANT: Only report what was ACTUALLY found. Do not make up vulnerabilities."""

        try:
            response = await self._call_llm(prompt, context)
            
            # Parse response
            try:
                import re
                if "```json" in response:
                    json_match = re.search(r"```json\s*(.*?)\s*```", response, re.DOTALL)
                    if json_match:
                        response = json_match.group(1)
                elif "```" in response:
                    json_match = re.search(r"```\s*(.*?)\s*```", response, re.DOTALL)
                    if json_match:
                        response = json_match.group(1)
                
                report = json.loads(response)
            except json.JSONDecodeError:
                report = {"raw_response": response}
            
            # Add metadata
            report["scan_data"] = {
                "target": target,
                "command": findings.get("scan_command"),
                "ports_scanned": len(findings.get("ports", [])),
                "vulnerabilities_found": len(findings.get("vulnerabilities", [])),
            }
            
            output = f"""Report generated for: {target}

{report.get('executive_summary', 'See data field for full report.')}"""
            
            return AgentResult(
                success=True,
                output=output,
                data={"report": report},
            )
        except Exception as e:
            return AgentResult(
                success=False,
                output=f"Report generation failed: {str(e)}",
                error=str(e),
            )
