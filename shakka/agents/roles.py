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
    
    Handles tasks like:
    - Network scanning
    - Service detection
    - OSINT gathering
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
    
    async def execute(self, task: str, context: Optional[dict] = None) -> AgentResult:
        """Execute a reconnaissance task using LLM.
        
        Args:
            task: Recon task description.
            context: Optional context.
            
        Returns:
            Recon results.
        """
        self._log_event("recon_started", {"task": task[:100]})
        
        # Store in memory if available
        if self._shared_memory:
            from shakka.storage.memory import MemoryType
            self._shared_memory.remember(
                f"Recon task: {task}",
                memory_type=MemoryType.SESSION,
                metadata={"agent": self.name},
            )
        
        # Build recon prompt
        prompt = f"""Execute the following reconnaissance task:

TASK: {task}

Provide your analysis as JSON with this structure:
{{
  "target": "target identifier",
  "methodology": "approach taken",
  "findings": {{
    "open_ports": [list of ports],
    "services": [{{"port": N, "service": "name", "version": "ver"}}],
    "hostnames": ["hostname1"],
    "vulnerabilities": ["potential vuln1"],
    "notes": "additional findings"
  }},
  "commands_to_run": ["nmap command", "other commands"],
  "summary": "brief summary of findings"
}}

Be specific with service versions and potential vulnerabilities."""
        
        try:
            response = await self._call_llm(prompt, context)
            
            # Parse response
            try:
                # Handle markdown code blocks
                if "```json" in response:
                    import re
                    json_match = re.search(r"```json\s*(.*?)\s*```", response, re.DOTALL)
                    if json_match:
                        response = json_match.group(1)
                elif "```" in response:
                    import re
                    json_match = re.search(r"```\s*(.*?)\s*```", response, re.DOTALL)
                    if json_match:
                        response = json_match.group(1)
                
                findings = json.loads(response)
            except json.JSONDecodeError:
                findings = {"raw_response": response}
            
            output = f"""Reconnaissance completed for task: {task}

{findings.get('summary', 'See data field for details.')}"""
            
            return AgentResult(
                success=True,
                output=output,
                data=findings,
                tokens_used=len(response.split()) * 2,  # Rough estimate
            )
        except Exception as e:
            return AgentResult(
                success=False,
                output=f"Recon failed: {str(e)}",
                error=str(e),
            )


class ExploitAgent(Agent):
    """Agent specialized in exploitation and vulnerability analysis.
    
    Handles tasks like:
    - Vulnerability identification
    - Exploit selection
    - Payload generation
    - Initial access
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
    
    async def execute(self, task: str, context: Optional[dict] = None) -> AgentResult:
        """Execute an exploitation task using LLM.
        
        Args:
            task: Exploit task description.
            context: Optional context with recon data.
            
        Returns:
            Exploitation results.
        """
        self._log_event("exploit_started", {"task": task[:100]})
        
        # Build exploitation prompt
        prompt = f"""Analyze and plan exploitation for the following task:

TASK: {task}

Provide your analysis as JSON with this structure:
{{
  "vulnerability_assessment": [
    {{
      "type": "vuln type (e.g., RCE, SQLi, XSS)",
      "cve": "CVE-XXXX-XXXXX if known",
      "severity": "critical|high|medium|low",
      "service": "affected service",
      "port": port_number,
      "description": "vulnerability description"
    }}
  ],
  "recommended_exploits": [
    {{
      "name": "exploit name",
      "source": "metasploit|exploitdb|custom",
      "command": "command to run",
      "success_probability": "high|medium|low"
    }}
  ],
  "attack_chain": ["step 1", "step 2"],
  "payloads": ["suggested payload 1"],
  "prerequisites": ["what's needed first"],
  "evasion_tips": ["how to avoid detection"],
  "summary": "brief summary"
}}

Be specific with exploit details and MITRE ATT&CK technique IDs."""
        
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
            
            output = f"""Exploitation analysis for: {task}

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
    
    Handles tasks like:
    - Finding documentation
    - Report generation
    - Executive summaries
    - Remediation recommendations
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
    
    async def execute(self, task: str, context: Optional[dict] = None) -> AgentResult:
        """Execute a reporting task using LLM.
        
        Args:
            task: Reporting task description.
            context: Optional context with all previous findings.
            
        Returns:
            Report results.
        """
        self._log_event("report_started", {"task": task[:100]})
        
        # Aggregate previous results for context
        all_findings = []
        if context and "previous_results" in context:
            for result in context.get("previous_results", []):
                if result.get("data"):
                    all_findings.append(result["data"])
        
        # Build reporting prompt
        findings_str = json.dumps(all_findings, indent=2) if all_findings else "No previous findings"
        
        prompt = f"""Generate a professional penetration testing report for:

TASK: {task}

FINDINGS DATA:
{findings_str[:3000]}  

Provide your report as JSON with this structure:
{{
  "title": "Report title",
  "executive_summary": "High-level summary for executives",
  "methodology": "Approach taken during assessment",
  "findings": [
    {{
      "id": "FIND-001",
      "title": "Finding title",
      "severity": "critical|high|medium|low|informational",
      "description": "Detailed description",
      "impact": "Business impact",
      "recommendation": "How to fix",
      "references": ["CVE or reference links"]
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
      "action": "What to do",
      "rationale": "Why"
    }}
  ],
  "conclusion": "Overall assessment conclusion"
}}

Be professional and provide actionable recommendations."""
        
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
            
            output = f"""Report generated for: {task}

{report.get('executive_summary', 'See data field for full report.')}"""
            
            return AgentResult(
                success=True,
                output=output,
                data={"report": report},
                tokens_used=len(response.split()) * 2,
            )
        except Exception as e:
            return AgentResult(
                success=False,
                output=f"Report generation failed: {str(e)}",
                error=str(e),
            )
