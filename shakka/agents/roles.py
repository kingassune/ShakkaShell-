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
        
        # Match IP addresses
        ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?\b'
        ip_match = re.search(ip_pattern, task)
        if ip_match:
            return ip_match.group()
        
        # Match hostnames/domains
        domain_pattern = r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b'
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
    
    Handles tasks like:
    - Vulnerability identification from real scan data
    - Exploit selection based on actual services
    - CVE lookup for detected versions
    - Attack vector analysis
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

            return AgentResult(
                success=True,
                output=output,
                data={
                    "target": target,
                    "services_scanned": ports,
                    "analysis": data,
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
