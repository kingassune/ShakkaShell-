"""Chain-of-Thought Attack Planner.

Generates attack plans with visible AI reasoning using reasoning models.
"""

from dataclasses import dataclass, field
from typing import Optional

from .models import (
    AttackPlan,
    AttackStep,
    PlanPhase,
    RiskLevel,
    StepAction,
    AlternativePath,
)


@dataclass
class PlannerConfig:
    """Configuration for the attack planner.
    
    Attributes:
        model: LLM model to use (prefer reasoning models).
        max_steps: Maximum steps in a plan.
        include_alternatives: Whether to generate alternative paths.
        include_risk_assessment: Whether to assess risk per step.
        include_detection_notes: Whether to add detection information.
        verbose_thinking: Whether to show detailed reasoning.
    """
    
    model: str = "claude-3-5-sonnet-20241022"
    max_steps: int = 10
    include_alternatives: bool = True
    include_risk_assessment: bool = True
    include_detection_notes: bool = True
    verbose_thinking: bool = True
    
    def to_dict(self) -> dict:
        """Convert to dictionary."""
        return {
            "model": self.model,
            "max_steps": self.max_steps,
            "include_alternatives": self.include_alternatives,
            "include_risk_assessment": self.include_risk_assessment,
            "include_detection_notes": self.include_detection_notes,
            "verbose_thinking": self.verbose_thinking,
        }


class AttackPlanner:
    """Chain-of-Thought Attack Planner.
    
    Generates comprehensive attack plans with visible reasoning.
    Supports reasoning models like o1, DeepSeek-R1, and Claude with thinking.
    
    Example:
        planner = AttackPlanner()
        plan = await planner.plan("Get domain admin from external foothold")
        print(plan.format())
    """
    
    # System prompt for attack planning
    PLANNING_PROMPT = """You are an expert penetration tester creating an attack plan.

For the given objective, create a detailed plan with:
1. Your step-by-step thinking process
2. Concrete attack phases following MITRE ATT&CK
3. Specific techniques and commands for each step
4. Risk assessment for each action
5. Alternative approaches if primary fails
6. Detection indicators for each step

Be thorough but realistic. Consider:
- Current position and available access
- Required tools and techniques
- Stealth vs speed tradeoffs
- Potential obstacles and mitigations
"""
    
    def __init__(self, config: Optional[PlannerConfig] = None):
        """Initialize the planner.
        
        Args:
            config: Optional planner configuration.
        """
        self.config = config or PlannerConfig()
        self._cache: dict[str, AttackPlan] = {}
    
    async def plan(
        self,
        objective: str,
        context: Optional[dict] = None,
    ) -> AttackPlan:
        """Generate an attack plan for the given objective.
        
        Args:
            objective: The attack goal (e.g., "Get domain admin").
            context: Optional context (current position, known info).
            
        Returns:
            Complete attack plan with reasoning.
        """
        objective = objective.strip()
        if not objective:
            return AttackPlan(objective="", thinking="No objective provided")
        
        # Check cache
        cache_key = f"{objective}:{context}"
        if cache_key in self._cache:
            return self._cache[cache_key]
        
        # Extract context
        current_position = ""
        if context:
            current_position = context.get("position", "")
        
        # Generate plan using reasoning
        plan = await self._generate_plan(objective, current_position, context)
        
        self._cache[cache_key] = plan
        return plan
    
    async def _generate_plan(
        self,
        objective: str,
        current_position: str,
        context: Optional[dict],
    ) -> AttackPlan:
        """Generate the attack plan.
        
        In production, this calls an LLM with reasoning capabilities.
        For testing, returns a simulated plan.
        
        Args:
            objective: Attack objective.
            current_position: Current position description.
            context: Additional context.
            
        Returns:
            Generated attack plan.
        """
        # Analyze the objective to determine attack type
        plan_type = self._categorize_objective(objective)
        
        # Generate appropriate plan based on type
        if plan_type == "domain_admin":
            return self._generate_domain_admin_plan(objective, current_position)
        elif plan_type == "web_app":
            return self._generate_web_app_plan(objective, current_position)
        elif plan_type == "network":
            return self._generate_network_plan(objective, current_position)
        else:
            return self._generate_generic_plan(objective, current_position)
    
    def _categorize_objective(self, objective: str) -> str:
        """Categorize the attack objective.
        
        Args:
            objective: Attack objective text.
            
        Returns:
            Category string.
        """
        objective_lower = objective.lower()
        
        if any(term in objective_lower for term in ["domain admin", "active directory", "ad", "kerberos", "dc"]):
            return "domain_admin"
        elif any(term in objective_lower for term in ["web", "sql", "xss", "injection", "api"]):
            return "web_app"
        elif any(term in objective_lower for term in ["network", "pivot", "lateral", "scan"]):
            return "network"
        else:
            return "generic"
    
    def _generate_domain_admin_plan(
        self,
        objective: str,
        current_position: str,
    ) -> AttackPlan:
        """Generate a domain admin attack plan.
        
        Args:
            objective: Attack objective.
            current_position: Starting position.
            
        Returns:
            Attack plan for domain compromise.
        """
        thinking = """Starting from external foothold, I need to:

1. First, establish internal network access from the external position
2. Then identify Active Directory infrastructure 
3. Harvest credentials using low-noise techniques
4. Escalate privileges to domain admin level

Let me break this down into specific phases with techniques..."""
        
        steps = [
            AttackStep(
                phase=PlanPhase.INITIAL_ACCESS,
                title="Establish Internal Access",
                goal="Gain access to internal network from external foothold",
                reasoning="Need to pivot from external position to internal network",
                actions=[
                    StepAction(
                        description="Check for SSRF vulnerabilities",
                        command="ffuf -u http://target/fetch?url=FUZZ -w internal_ips.txt",
                        tool="ffuf",
                        technique_id="T1090",
                    ),
                    StepAction(
                        description="Test for command injection",
                        command="nuclei -t command-injection.yaml -u http://target",
                        tool="nuclei",
                        technique_id="T1059",
                    ),
                    StepAction(
                        description="Check for file upload vulnerabilities",
                        tool="manual",
                        technique_id="T1105",
                    ),
                ],
                alternatives=[
                    AlternativePath(
                        condition="If web vulnerabilities not found",
                        description="Try VPN or exposed services",
                        actions=[
                            StepAction(description="Scan for VPN endpoints"),
                            StepAction(description="Check for RDP or SSH access"),
                        ],
                    ),
                ],
                risk_level=RiskLevel.MEDIUM,
                risk_factors=["May trigger WAF", "Commands logged"],
                detection_notes="Web application firewall may block payloads",
            ),
            AttackStep(
                phase=PlanPhase.DISCOVERY,
                title="Internal Reconnaissance",
                goal="Identify Active Directory infrastructure",
                reasoning="Need to find domain controllers and understand AD structure",
                actions=[
                    StepAction(
                        description="Scan for Kerberos (88/tcp)",
                        command="nmap -p 88,389,445 -sV 10.0.0.0/24",
                        tool="nmap",
                        technique_id="T1046",
                    ),
                    StepAction(
                        description="Identify domain controllers",
                        command="nslookup -type=srv _ldap._tcp.dc._msdcs.domain.local",
                        technique_id="T1018",
                    ),
                    StepAction(
                        description="Enumerate users via LDAP",
                        command="ldapsearch -x -H ldap://dc -b 'DC=domain,DC=local' '(objectClass=user)'",
                        tool="ldapsearch",
                        technique_id="T1087.002",
                    ),
                ],
                risk_level=RiskLevel.LOW,
                risk_factors=["LDAP queries logged", "Network scanning may alert"],
                detection_notes="SIEM may alert on LDAP enumeration patterns",
            ),
            AttackStep(
                phase=PlanPhase.CREDENTIAL_ACCESS,
                title="Credential Harvesting",
                goal="Obtain valid domain credentials",
                reasoning="Kerberoasting is low-noise and requires no admin access",
                actions=[
                    StepAction(
                        description="Kerberoasting attack",
                        command="GetUserSPNs.py domain.local/user:pass -dc-ip 10.0.0.1 -request",
                        tool="impacket",
                        technique_id="T1558.003",
                    ),
                    StepAction(
                        description="AS-REP roasting for accounts without preauth",
                        command="GetNPUsers.py domain.local/ -usersfile users.txt -no-pass -dc-ip 10.0.0.1",
                        tool="impacket",
                        technique_id="T1558.004",
                    ),
                    StepAction(
                        description="Crack service account hashes",
                        command="hashcat -m 13100 hashes.txt wordlist.txt",
                        tool="hashcat",
                    ),
                ],
                alternatives=[
                    AlternativePath(
                        condition="If no SPNs found",
                        description="Try NTLM relay attacks",
                        actions=[
                            StepAction(
                                description="Set up NTLM relay",
                                command="ntlmrelayx.py -t ldap://dc -smb2support",
                            ),
                        ],
                        risk_level=RiskLevel.MEDIUM,
                    ),
                ],
                risk_level=RiskLevel.MEDIUM,
                risk_factors=["TGS requests logged", "Hash cracking takes time"],
                detection_notes="Many TGS requests may trigger alerts",
            ),
            AttackStep(
                phase=PlanPhase.PRIVILEGE_ESCALATION,
                title="Privilege Escalation to Domain Admin",
                goal="Escalate to domain administrator privileges",
                reasoning="With service account creds, check for delegation and ACL issues",
                actions=[
                    StepAction(
                        description="Check for unconstrained delegation",
                        command="Get-ADComputer -Filter {TrustedForDelegation -eq $true}",
                        tool="powershell",
                        technique_id="T1558.001",
                    ),
                    StepAction(
                        description="Look for GPP passwords",
                        command="Get-GPPPassword.py domain.local/user:pass@dc",
                        tool="impacket",
                        technique_id="T1552.006",
                    ),
                    StepAction(
                        description="Attempt DCSync if replication rights found",
                        command="secretsdump.py domain.local/admin:pass@dc -just-dc-ntlm",
                        tool="impacket",
                        technique_id="T1003.006",
                    ),
                ],
                alternatives=[
                    AlternativePath(
                        condition="If no direct path to DA",
                        description="Look for path through ACL abuse",
                        actions=[
                            StepAction(description="Run BloodHound for path analysis"),
                        ],
                        risk_level=RiskLevel.HIGH,
                    ),
                ],
                risk_level=RiskLevel.HIGH,
                risk_factors=["DCSync highly monitored", "May trigger alerts"],
                detection_notes="DCSync attempts should trigger security alerts",
            ),
        ]
        
        return AttackPlan(
            objective=objective,
            thinking=thinking,
            current_position=current_position or "External web server",
            steps=steps,
            recommended_first_step='shakka "SSRF scan on web application"',
            overall_risk=RiskLevel.HIGH,
            estimated_time="4-8 hours",
            success_probability=0.65,
            metadata={"plan_type": "domain_admin"},
        )
    
    def _generate_web_app_plan(
        self,
        objective: str,
        current_position: str,
    ) -> AttackPlan:
        """Generate a web application attack plan.
        
        Args:
            objective: Attack objective.
            current_position: Starting position.
            
        Returns:
            Attack plan for web app testing.
        """
        thinking = """For web application testing, my approach is:

1. Start with reconnaissance to understand the application
2. Map all endpoints and parameters
3. Test for common vulnerabilities systematically
4. Chain vulnerabilities for maximum impact

Prioritizing high-impact vulns like SQLi and RCE..."""
        
        steps = [
            AttackStep(
                phase=PlanPhase.RECONNAISSANCE,
                title="Application Mapping",
                goal="Understand the web application structure",
                reasoning="Need to identify all entry points before testing",
                actions=[
                    StepAction(
                        description="Directory enumeration",
                        command="gobuster dir -u http://target -w /usr/share/wordlists/dirb/common.txt",
                        tool="gobuster",
                        technique_id="T1595.003",
                    ),
                    StepAction(
                        description="Identify technologies",
                        command="whatweb http://target",
                        tool="whatweb",
                    ),
                    StepAction(
                        description="Spider the application",
                        command="gospider -s http://target -d 3",
                        tool="gospider",
                    ),
                ],
                risk_level=RiskLevel.LOW,
                detection_notes="Directory brute forcing may be logged",
            ),
            AttackStep(
                phase=PlanPhase.INITIAL_ACCESS,
                title="Vulnerability Testing",
                goal="Identify exploitable vulnerabilities",
                reasoning="Testing for high-impact vulnerabilities first",
                actions=[
                    StepAction(
                        description="SQL injection testing",
                        command="sqlmap -u 'http://target/page?id=1' --batch --dbs",
                        tool="sqlmap",
                        technique_id="T1190",
                    ),
                    StepAction(
                        description="XSS testing",
                        command="dalfox url http://target/search?q=test",
                        tool="dalfox",
                        technique_id="T1059.007",
                    ),
                    StepAction(
                        description="Template injection testing",
                        command="tplmap -u 'http://target/page?name=test'",
                        tool="tplmap",
                        technique_id="T1059",
                    ),
                ],
                risk_level=RiskLevel.MEDIUM,
                risk_factors=["Automated scanners detectable", "Payloads logged"],
            ),
        ]
        
        return AttackPlan(
            objective=objective,
            thinking=thinking,
            current_position=current_position or "External",
            steps=steps,
            recommended_first_step='shakka "enumerate directories on target"',
            overall_risk=RiskLevel.MEDIUM,
            estimated_time="2-4 hours",
            success_probability=0.75,
            metadata={"plan_type": "web_app"},
        )
    
    def _generate_network_plan(
        self,
        objective: str,
        current_position: str,
    ) -> AttackPlan:
        """Generate a network attack plan.
        
        Args:
            objective: Attack objective.
            current_position: Starting position.
            
        Returns:
            Attack plan for network testing.
        """
        thinking = """For network penetration, I need to:

1. Perform comprehensive host discovery
2. Identify services and versions
3. Look for known vulnerabilities
4. Attempt exploitation of weak services"""
        
        steps = [
            AttackStep(
                phase=PlanPhase.RECONNAISSANCE,
                title="Host Discovery",
                goal="Identify live hosts on the network",
                reasoning="Need to know what targets exist before deeper scanning",
                actions=[
                    StepAction(
                        description="Ping sweep",
                        command="nmap -sn 10.0.0.0/24",
                        tool="nmap",
                        technique_id="T1046",
                    ),
                    StepAction(
                        description="ARP scan for local network",
                        command="arp-scan -l",
                        tool="arp-scan",
                    ),
                ],
                risk_level=RiskLevel.LOW,
            ),
            AttackStep(
                phase=PlanPhase.DISCOVERY,
                title="Service Enumeration",
                goal="Identify running services and versions",
                reasoning="Version info needed to find applicable exploits",
                actions=[
                    StepAction(
                        description="Full port scan with version detection",
                        command="nmap -sV -sC -p- -T4 target",
                        tool="nmap",
                        technique_id="T1046",
                    ),
                ],
                risk_level=RiskLevel.MEDIUM,
                detection_notes="Full port scans are very noisy",
            ),
        ]
        
        return AttackPlan(
            objective=objective,
            thinking=thinking,
            current_position=current_position or "Network segment",
            steps=steps,
            recommended_first_step='shakka "scan network for live hosts"',
            overall_risk=RiskLevel.MEDIUM,
            estimated_time="1-2 hours",
            success_probability=0.8,
            metadata={"plan_type": "network"},
        )
    
    def _generate_generic_plan(
        self,
        objective: str,
        current_position: str,
    ) -> AttackPlan:
        """Generate a generic attack plan.
        
        Args:
            objective: Attack objective.
            current_position: Starting position.
            
        Returns:
            Generic attack plan.
        """
        thinking = f"""Analyzing the objective: {objective}

I'll create a general penetration testing plan:
1. Reconnaissance phase
2. Initial access attempts
3. Exploitation and escalation
4. Goal achievement"""
        
        steps = [
            AttackStep(
                phase=PlanPhase.RECONNAISSANCE,
                title="Information Gathering",
                goal="Collect information about the target",
                reasoning="Understanding the target is crucial for success",
                actions=[
                    StepAction(
                        description="Initial reconnaissance",
                        command="nmap -sV -sC target",
                        tool="nmap",
                    ),
                ],
                risk_level=RiskLevel.LOW,
            ),
            AttackStep(
                phase=PlanPhase.INITIAL_ACCESS,
                title="Gain Initial Access",
                goal="Establish foothold on target",
                reasoning="Need to find and exploit an entry point",
                actions=[
                    StepAction(
                        description="Vulnerability scanning",
                        command="nuclei -u http://target",
                        tool="nuclei",
                    ),
                ],
                risk_level=RiskLevel.MEDIUM,
            ),
        ]
        
        return AttackPlan(
            objective=objective,
            thinking=thinking,
            current_position=current_position or "Unknown",
            steps=steps,
            recommended_first_step=f'shakka "scan {objective.split()[0] if objective else "target"}"',
            overall_risk=RiskLevel.MEDIUM,
            estimated_time="Variable",
            success_probability=0.5,
            metadata={"plan_type": "generic"},
        )
    
    async def refine_step(
        self,
        plan: AttackPlan,
        step_index: int,
        feedback: str,
    ) -> AttackStep:
        """Refine a specific step based on feedback.
        
        Args:
            plan: The current plan.
            step_index: Index of the step to refine.
            feedback: User feedback for refinement.
            
        Returns:
            Refined attack step.
        """
        if step_index < 0 or step_index >= len(plan.steps):
            raise IndexError(f"Invalid step index: {step_index}")
        
        step = plan.steps[step_index]
        
        # In production, this would call LLM for refinement
        # For now, add the feedback to reasoning
        step.reasoning = f"{step.reasoning}\n\nRefinement: {feedback}"
        
        return step
    
    async def suggest_next_step(
        self,
        plan: AttackPlan,
        completed_steps: list[int],
    ) -> Optional[AttackStep]:
        """Suggest the next step to execute.
        
        Args:
            plan: The attack plan.
            completed_steps: Indices of completed steps.
            
        Returns:
            Next step to execute, or None if plan complete.
        """
        for i, step in enumerate(plan.steps):
            if i not in completed_steps:
                return step
        return None
    
    def clear_cache(self) -> None:
        """Clear the plan cache."""
        self._cache.clear()
