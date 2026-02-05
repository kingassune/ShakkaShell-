"""Orchestrator agent for coordinating multi-agent workflows.

The Orchestrator is responsible for:
- Breaking down complex tasks into steps
- Assigning work to specialized agents
- Handling failures and retries
- Managing the overall workflow state
"""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Optional

from .base import Agent, AgentConfig, AgentResult, AgentRole, AgentState
from .message import AgentMessage, MessageQueue, MessageType


class StepStatus(str, Enum):
    """Status of a task step."""
    
    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    FAILED = "failed"
    SKIPPED = "skipped"


@dataclass
class TaskStep:
    """A single step in a task plan."""
    
    step_id: str
    description: str
    assigned_agent: AgentRole
    status: StepStatus = StepStatus.PENDING
    dependencies: list[str] = field(default_factory=list)
    result: Optional[AgentResult] = None
    retry_count: int = 0
    max_retries: int = 3
    
    @property
    def is_ready(self) -> bool:
        """Check if step is ready to execute (dependencies met)."""
        return self.status == StepStatus.PENDING and not self.dependencies
    
    @property
    def is_complete(self) -> bool:
        """Check if step is finished (success or failure)."""
        return self.status in (StepStatus.COMPLETED, StepStatus.FAILED, StepStatus.SKIPPED)
    
    @property
    def can_retry(self) -> bool:
        """Check if step can be retried."""
        return self.retry_count < self.max_retries
    
    def to_dict(self) -> dict:
        """Convert to dictionary."""
        return {
            "step_id": self.step_id,
            "description": self.description,
            "assigned_agent": self.assigned_agent.value,
            "status": self.status.value,
            "dependencies": self.dependencies,
            "result": self.result.to_dict() if self.result else None,
            "retry_count": self.retry_count,
        }


@dataclass
class TaskPlan:
    """A plan for executing a complex task.
    
    Contains ordered steps that may have dependencies on each other.
    """
    
    plan_id: str
    objective: str
    steps: list[TaskStep] = field(default_factory=list)
    created_at: str = field(default_factory=lambda: datetime.now().isoformat())
    status: str = "pending"
    
    def add_step(
        self,
        description: str,
        agent: AgentRole,
        dependencies: Optional[list[str]] = None,
    ) -> TaskStep:
        """Add a step to the plan.
        
        Args:
            description: Step description.
            agent: Agent role to execute step.
            dependencies: IDs of steps that must complete first.
            
        Returns:
            The created step.
        """
        step = TaskStep(
            step_id=f"step_{len(self.steps) + 1}",
            description=description,
            assigned_agent=agent,
            dependencies=dependencies or [],
        )
        self.steps.append(step)
        return step
    
    def get_step(self, step_id: str) -> Optional[TaskStep]:
        """Get a step by ID.
        
        Args:
            step_id: Step ID to find.
            
        Returns:
            Step or None.
        """
        for step in self.steps:
            if step.step_id == step_id:
                return step
        return None
    
    def get_ready_steps(self) -> list[TaskStep]:
        """Get steps ready to execute.
        
        Returns:
            List of steps with met dependencies.
        """
        completed_ids = {s.step_id for s in self.steps if s.status == StepStatus.COMPLETED}
        
        ready = []
        for step in self.steps:
            if step.status == StepStatus.PENDING:
                deps_met = all(dep in completed_ids for dep in step.dependencies)
                if deps_met:
                    ready.append(step)
        
        return ready
    
    def mark_step_complete(self, step_id: str, result: AgentResult) -> None:
        """Mark a step as complete.
        
        Args:
            step_id: Step to mark.
            result: Execution result.
        """
        step = self.get_step(step_id)
        if step:
            step.status = StepStatus.COMPLETED if result.success else StepStatus.FAILED
            step.result = result
            
            # Update plan status
            if all(s.is_complete for s in self.steps):
                if all(s.status == StepStatus.COMPLETED for s in self.steps):
                    self.status = "completed"
                else:
                    self.status = "partial"
    
    def mark_step_failed(self, step_id: str, error: str) -> None:
        """Mark a step as failed.
        
        Args:
            step_id: Step to mark.
            error: Error message.
        """
        step = self.get_step(step_id)
        if step:
            step.status = StepStatus.FAILED
            step.result = AgentResult(success=False, output="", error=error)
    
    @property
    def is_complete(self) -> bool:
        """Check if plan is fully executed."""
        return all(step.is_complete for step in self.steps)
    
    @property
    def progress(self) -> float:
        """Get plan progress as percentage."""
        if not self.steps:
            return 100.0
        completed = sum(1 for s in self.steps if s.is_complete)
        return (completed / len(self.steps)) * 100
    
    def to_dict(self) -> dict:
        """Convert to dictionary."""
        return {
            "plan_id": self.plan_id,
            "objective": self.objective,
            "steps": [s.to_dict() for s in self.steps],
            "created_at": self.created_at,
            "status": self.status,
            "progress": self.progress,
        }
    
    def format_plan(self) -> str:
        """Format plan for display.
        
        Returns:
            Formatted plan string.
        """
        lines = [
            f"╔══ Task Plan: {self.objective[:50]} ══╗",
            f"║ Status: {self.status} ({self.progress:.0f}% complete)",
            "╟─────────────────────────────────────────────────╢",
        ]
        
        status_icons = {
            StepStatus.PENDING: "⚪",
            StepStatus.IN_PROGRESS: "🔵",
            StepStatus.COMPLETED: "✅",
            StepStatus.FAILED: "❌",
            StepStatus.SKIPPED: "⏭️",
        }
        
        for step in self.steps:
            icon = status_icons.get(step.status, "❓")
            agent_short = step.assigned_agent.value[:6].upper()
            desc = step.description[:35]
            lines.append(f"║ {icon} [{agent_short}] {desc}")
        
        lines.append("╚═════════════════════════════════════════════════╝")
        return "\n".join(lines)


class Orchestrator(Agent):
    """Orchestrator agent that coordinates multi-agent workflows.
    
    The Orchestrator breaks down complex tasks, creates execution plans,
    and coordinates specialized agents to complete the work.
    
    Example:
        orchestrator = Orchestrator()
        agents = {"recon": ReconAgent(), "exploit": ExploitAgent()}
        result = await orchestrator.orchestrate(
            "Full assessment of target.com",
            agents,
        )
    """
    
    def __init__(
        self,
        config: Optional[AgentConfig] = None,
        shared_memory=None,
    ):
        """Initialize the orchestrator.
        
        Args:
            config: Agent configuration.
            shared_memory: Optional shared memory store.
        """
        # Force orchestrator role
        if config is None:
            config = AgentConfig(role=AgentRole.ORCHESTRATOR)
        else:
            config.role = AgentRole.ORCHESTRATOR
        
        super().__init__(config, shared_memory)
        
        self._agents: dict[AgentRole, Agent] = {}
        self._message_queue = MessageQueue()
        self._current_plan: Optional[TaskPlan] = None
        self._plan_history: list[TaskPlan] = []
    
    def register_agent(self, agent: Agent) -> None:
        """Register an agent for orchestration.
        
        Args:
            agent: Agent to register.
        """
        self._agents[agent.role] = agent
        
        # Share memory if configured
        if self.config.use_shared_memory and self._shared_memory:
            agent.set_shared_memory(self._shared_memory)
    
    def unregister_agent(self, role: AgentRole) -> None:
        """Unregister an agent.
        
        Args:
            role: Role of agent to remove.
        """
        if role in self._agents:
            del self._agents[role]
    
    def get_agent(self, role: AgentRole) -> Optional[Agent]:
        """Get a registered agent by role.
        
        Args:
            role: Agent role.
            
        Returns:
            Agent or None.
        """
        return self._agents.get(role)
    
    @property
    def current_plan(self) -> Optional[TaskPlan]:
        """Get the current execution plan."""
        return self._current_plan
    
    @property
    def registered_agents(self) -> list[AgentRole]:
        """Get list of registered agent roles."""
        return list(self._agents.keys())
    
    def create_plan(self, objective: str) -> TaskPlan:
        """Create a new task plan.
        
        This creates a basic plan structure. In a full implementation,
        this would use an LLM to break down the objective.
        
        Args:
            objective: High-level objective.
            
        Returns:
            New task plan.
        """
        plan = TaskPlan(
            plan_id=f"plan_{datetime.now().timestamp()}",
            objective=objective,
        )
        
        # Default plan structure for security assessments
        # In production, this would be generated by the LLM
        if "scan" in objective.lower() or "recon" in objective.lower():
            plan.add_step(
                "Perform initial reconnaissance",
                AgentRole.RECON,
            )
            plan.add_step(
                "Analyze findings and identify vulnerabilities",
                AgentRole.EXPLOIT,
                dependencies=["step_1"],
            )
            plan.add_step(
                "Document findings in report",
                AgentRole.REPORTER,
                dependencies=["step_2"],
            )
        elif "exploit" in objective.lower() or "attack" in objective.lower():
            plan.add_step(
                "Enumerate target",
                AgentRole.RECON,
            )
            plan.add_step(
                "Identify and exploit vulnerabilities",
                AgentRole.EXPLOIT,
                dependencies=["step_1"],
            )
            plan.add_step(
                "Establish persistence",
                AgentRole.PERSISTENCE,
                dependencies=["step_2"],
            )
            plan.add_step(
                "Generate report",
                AgentRole.REPORTER,
                dependencies=["step_3"],
            )
        else:
            # Generic single-step plan
            plan.add_step(
                f"Execute: {objective}",
                AgentRole.RECON,
            )
        
        self._current_plan = plan
        return plan
    
    async def execute(self, task: str, context: Optional[dict] = None) -> AgentResult:
        """Execute orchestration for a task.
        
        Creates a plan and coordinates agents to complete it.
        
        Args:
            task: Task description.
            context: Optional context.
            
        Returns:
            Aggregated result from all agents.
        """
        # Create execution plan
        self._set_state(AgentState.PLANNING)
        plan = self.create_plan(task)
        
        self._log_event("plan_created", {
            "plan_id": plan.plan_id,
            "steps": len(plan.steps),
        })
        
        # Execute plan
        self._set_state(AgentState.EXECUTING)
        results: list[AgentResult] = []
        
        while not plan.is_complete and not self._interrupted:
            ready_steps = plan.get_ready_steps()
            
            if not ready_steps:
                # Check for stuck state
                if any(s.status == StepStatus.PENDING for s in plan.steps):
                    # Some steps pending but none ready - likely failed dependencies
                    break
                break
            
            for step in ready_steps:
                if self._interrupted:
                    break
                
                step.status = StepStatus.IN_PROGRESS
                
                agent = self._agents.get(step.assigned_agent)
                if agent is None:
                    # No agent for this role, skip or fail
                    step.status = StepStatus.SKIPPED
                    self._log_event("step_skipped", {
                        "step_id": step.step_id,
                        "reason": f"No agent for role {step.assigned_agent.value}",
                    })
                    continue
                
                # Build context from previous results
                step_context = context.copy() if context else {}
                step_context["previous_results"] = [r.to_dict() for r in results]
                step_context["plan"] = plan.to_dict()
                
                # Execute step
                result = await agent.run(step.description, step_context)
                results.append(result)
                
                plan.mark_step_complete(step.step_id, result)
                
                self._log_event("step_completed", {
                    "step_id": step.step_id,
                    "success": result.success,
                })
                
                # Handle failure with retry
                if not result.success and step.can_retry:
                    step.retry_count += 1
                    step.status = StepStatus.PENDING
                    self._log_event("step_retry", {
                        "step_id": step.step_id,
                        "attempt": step.retry_count,
                    })
        
        # Store plan in history
        self._plan_history.append(plan)
        
        # Aggregate results
        all_success = all(r.success for r in results)
        all_output = "\n\n".join(f"[{i+1}] {r.output}" for i, r in enumerate(results) if r.output)
        total_tokens = sum(r.tokens_used for r in results)
        
        return AgentResult(
            success=all_success,
            output=all_output or "Task completed",
            data={
                "plan": plan.to_dict(),
                "step_results": [r.to_dict() for r in results],
            },
            tokens_used=total_tokens,
        )
    
    async def orchestrate(
        self,
        objective: str,
        agents: Optional[dict[AgentRole, Agent]] = None,
        context: Optional[dict] = None,
    ) -> AgentResult:
        """High-level orchestration entry point.
        
        Args:
            objective: What to accomplish.
            agents: Dictionary of agents to use.
            context: Optional context.
            
        Returns:
            Orchestrated result.
        """
        # Register provided agents
        if agents:
            for role, agent in agents.items():
                self.register_agent(agent)
        
        return await self.run(objective, context)
    
    def get_plan_history(self) -> list[TaskPlan]:
        """Get history of executed plans.
        
        Returns:
            List of past plans.
        """
        return list(self._plan_history)
    
    def format_status(self) -> str:
        """Format orchestrator status including registered agents.
        
        Returns:
            Formatted status string.
        """
        lines = [super().format_status()]
        
        if self._agents:
            lines.append("  Registered agents:")
            for role, agent in self._agents.items():
                lines.append(f"    • {agent.format_status()}")
        
        if self._current_plan:
            lines.append(f"  Current plan: {self._current_plan.progress:.0f}% complete")
        
        return "\n".join(lines)
