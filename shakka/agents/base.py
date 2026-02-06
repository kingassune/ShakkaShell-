"""Base classes for the multi-agent system.

Provides the foundational Agent class and related types for building
specialized security agents.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Optional, TYPE_CHECKING

from shakka.config import ShakkaConfig
from shakka.providers.base import LLMProvider

if TYPE_CHECKING:
    from shakka.storage.memory import MemoryStore


class AgentRole(str, Enum):
    """Roles that agents can take in the system."""
    
    ORCHESTRATOR = "orchestrator"
    RECON = "recon"
    EXPLOIT = "exploit"
    PERSISTENCE = "persistence"
    REPORTER = "reporter"


class AgentState(str, Enum):
    """Possible states for an agent."""
    
    IDLE = "idle"
    PLANNING = "planning"
    EXECUTING = "executing"
    WAITING = "waiting"
    COMPLETED = "completed"
    FAILED = "failed"
    INTERRUPTED = "interrupted"


@dataclass
class AgentConfig:
    """Configuration for an agent instance."""
    
    # Identity
    role: AgentRole = AgentRole.RECON
    name: Optional[str] = None
    
    # Model configuration
    provider: str = "openai"
    model: str = "gpt-4o"
    
    # Behavior
    max_retries: int = 3
    timeout_seconds: int = 300
    verbose: bool = False
    
    # Memory
    use_shared_memory: bool = True
    
    def __post_init__(self):
        """Set default name based on role if not provided."""
        if self.name is None:
            self.name = f"{self.role.value}_agent"


@dataclass
class AgentResult:
    """Result from an agent execution."""
    
    success: bool
    output: str
    data: dict = field(default_factory=dict)
    error: Optional[str] = None
    execution_time: float = 0.0
    tokens_used: int = 0
    
    @property
    def has_data(self) -> bool:
        """Check if result contains structured data."""
        return bool(self.data)
    
    def to_dict(self) -> dict:
        """Convert to dictionary."""
        return {
            "success": self.success,
            "output": self.output,
            "data": self.data,
            "error": self.error,
            "execution_time": self.execution_time,
            "tokens_used": self.tokens_used,
        }
    
    @classmethod
    def from_dict(cls, data: dict) -> "AgentResult":
        """Create from dictionary."""
        return cls(
            success=data.get("success", False),
            output=data.get("output", ""),
            data=data.get("data", {}),
            error=data.get("error"),
            execution_time=data.get("execution_time", 0.0),
            tokens_used=data.get("tokens_used", 0),
        )


class Agent(ABC):
    """Base class for all agents in the system.
    
    Agents are specialized workers that can execute tasks independently
    or as part of a coordinated workflow. Each agent has a specific role
    and can communicate with other agents through messages.
    
    Example:
        class MyAgent(Agent):
            async def execute(self, task):
                # Do work
                return AgentResult(success=True, output="Done")
    """
    
    def __init__(
        self,
        config: Optional[AgentConfig] = None,
        shared_memory: Optional["MemoryStore"] = None,
        shakka_config: Optional[ShakkaConfig] = None,
    ):
        """Initialize the agent.
        
        Args:
            config: Agent configuration. Uses defaults if not provided.
            shared_memory: Optional shared memory store for agent coordination.
            shakka_config: Optional ShakkaConfig for provider settings.
        """
        self.config = config or AgentConfig()
        self._shared_memory = shared_memory
        self._shakka_config = shakka_config or ShakkaConfig()
        self._state = AgentState.IDLE
        self._history: list[dict] = []
        self._start_time: Optional[datetime] = None
        self._interrupted = False
        self._provider: Optional[LLMProvider] = None
    
    def _get_provider(self) -> LLMProvider:
        """Get or create the LLM provider for this agent.
        
        Returns:
            Configured LLMProvider instance.
        """
        if self._provider:
            return self._provider
        
        provider_name = self.config.provider or self._shakka_config.default_provider
        
        if provider_name == "openai":
            from shakka.providers.openai import OpenAIProvider
            api_key = self._shakka_config.openai_api_key
            if not api_key:
                raise ValueError("OpenAI API key not found.")
            self._provider = OpenAIProvider(api_key=api_key)
        elif provider_name == "anthropic":
            from shakka.providers.anthropic import AnthropicProvider
            api_key = self._shakka_config.anthropic_api_key
            if not api_key:
                raise ValueError("Anthropic API key not found.")
            self._provider = AnthropicProvider(api_key=api_key)
        elif provider_name == "ollama":
            from shakka.providers.ollama import OllamaProvider
            self._provider = OllamaProvider(
                base_url=self._shakka_config.ollama_base_url,
                model=self._shakka_config.ollama_model
            )
        elif provider_name == "openrouter":
            from shakka.providers.openrouter import OpenRouterProvider
            api_key = self._shakka_config.openrouter_api_key
            if not api_key:
                raise ValueError("OpenRouter API key not found.")
            self._provider = OpenRouterProvider(
                api_key=api_key,
                model=self._shakka_config.openrouter_model,
                site_url=self._shakka_config.openrouter_site_url
            )
        else:
            raise ValueError(f"Unknown provider: {provider_name}")
        
        return self._provider
    
    async def _call_llm(self, prompt: str, context: Optional[dict] = None) -> str:
        """Call the LLM directly for agent reasoning tasks.
        
        Uses LiteLLM directly for flexibility in response format,
        unlike provider.generate() which returns CommandResult.
        
        Args:
            prompt: User prompt.
            context: Optional context to include.
            
        Returns:
            LLM response text.
            
        Raises:
            ValueError: If LLM call fails.
        """
        from litellm import acompletion
        
        # Build messages with system and user prompts
        messages = [
            {"role": "system", "content": self.get_system_prompt()},
            {"role": "user", "content": prompt}
        ]
        
        if context:
            import json
            messages[-1]["content"] += f"\n\nContext: {json.dumps(context)}"
        
        # Determine model and API key based on provider
        provider_name = self.config.provider or self._shakka_config.default_provider
        
        if provider_name == "openrouter":
            model = f"openrouter/{self._shakka_config.openrouter_model}"
            api_key = self._shakka_config.openrouter_api_key
            extra_headers = {
                "HTTP-Referer": self._shakka_config.openrouter_site_url or "https://github.com/ShakkaShell",
                "X-Title": "ShakkaShell",
            }
        elif provider_name == "openai":
            model = self.config.model or self._shakka_config.agent_default_model or "gpt-4o"
            api_key = self._shakka_config.openai_api_key
            extra_headers = None
        elif provider_name == "anthropic":
            model = self.config.model or self._shakka_config.agent_default_model or "claude-3-5-sonnet-20241022"
            api_key = self._shakka_config.anthropic_api_key
            extra_headers = None
        elif provider_name == "ollama":
            model = f"ollama/{self._shakka_config.ollama_model}"
            api_key = None
            extra_headers = None
        else:
            raise ValueError(f"Provider {provider_name} not supported for agent LLM calls")
        
        try:
            response = await acompletion(
                model=model,
                messages=messages,
                api_key=api_key,
                temperature=0.1,
                extra_headers=extra_headers,
            )
            
            content = response.choices[0].message.content
            return content
            
        except Exception as e:
            raise ValueError(f"{provider_name.title()} API error: {str(e)}")
    
    @property
    def role(self) -> AgentRole:
        """Get the agent's role."""
        return self.config.role
    
    @property
    def name(self) -> str:
        """Get the agent's name."""
        return self.config.name or f"{self.role.value}_agent"
    
    @property
    def state(self) -> AgentState:
        """Get the agent's current state."""
        return self._state
    
    @property
    def is_busy(self) -> bool:
        """Check if agent is currently executing."""
        return self._state in (AgentState.PLANNING, AgentState.EXECUTING, AgentState.WAITING)
    
    @property
    def shared_memory(self) -> Optional["MemoryStore"]:
        """Access shared memory store."""
        return self._shared_memory
    
    def set_shared_memory(self, memory: "MemoryStore") -> None:
        """Set the shared memory store.
        
        Args:
            memory: Memory store to use for sharing.
        """
        self._shared_memory = memory
    
    def _set_state(self, state: AgentState) -> None:
        """Update agent state and log transition.
        
        Args:
            state: New state.
        """
        old_state = self._state
        self._state = state
        self._history.append({
            "timestamp": datetime.now().isoformat(),
            "event": "state_change",
            "from": old_state.value,
            "to": state.value,
        })
    
    def _log_event(self, event_type: str, data: dict) -> None:
        """Log an event to history.
        
        Args:
            event_type: Type of event.
            data: Event data.
        """
        self._history.append({
            "timestamp": datetime.now().isoformat(),
            "event": event_type,
            **data,
        })
    
    def get_history(self) -> list[dict]:
        """Get execution history.
        
        Returns:
            List of history entries.
        """
        return list(self._history)
    
    def clear_history(self) -> None:
        """Clear execution history."""
        self._history.clear()
    
    def interrupt(self) -> None:
        """Request agent to interrupt current execution."""
        self._interrupted = True
        if self.is_busy:
            self._set_state(AgentState.INTERRUPTED)
    
    def reset(self) -> None:
        """Reset agent to idle state."""
        self._state = AgentState.IDLE
        self._interrupted = False
        self._start_time = None
    
    @abstractmethod
    async def execute(self, task: str, context: Optional[dict] = None) -> AgentResult:
        """Execute a task.
        
        Args:
            task: Task description or instruction.
            context: Optional context from previous operations or other agents.
            
        Returns:
            AgentResult with execution outcome.
        """
        pass
    
    async def run(self, task: str, context: Optional[dict] = None) -> AgentResult:
        """Run the agent on a task with state management.
        
        This is the main entry point for executing tasks. It handles
        state transitions and error handling.
        
        Args:
            task: Task to execute.
            context: Optional context.
            
        Returns:
            AgentResult with outcome.
        """
        self._interrupted = False
        self._start_time = datetime.now()
        self._set_state(AgentState.EXECUTING)
        
        self._log_event("task_started", {"task": task[:100]})
        
        try:
            result = await self.execute(task, context)
            
            if self._interrupted:
                self._set_state(AgentState.INTERRUPTED)
                result = AgentResult(
                    success=False,
                    output="Agent interrupted",
                    error="Execution was interrupted",
                )
            else:
                self._set_state(AgentState.COMPLETED if result.success else AgentState.FAILED)
            
            self._log_event("task_completed", {
                "success": result.success,
                "tokens_used": result.tokens_used,
            })
            
            return result
            
        except Exception as e:
            self._set_state(AgentState.FAILED)
            self._log_event("task_failed", {"error": str(e)})
            return AgentResult(
                success=False,
                output="",
                error=str(e),
            )
    
    def get_system_prompt(self) -> str:
        """Get the system prompt for this agent role.
        
        Returns:
            System prompt string.
        """
        prompts = {
            AgentRole.ORCHESTRATOR: """You are the Orchestrator Agent, responsible for:
- Breaking down complex security tasks into manageable steps
- Coordinating other specialized agents
- Planning attack chains and methodologies
- Making strategic decisions about approach

Always think step-by-step and explain your reasoning.""",

            AgentRole.RECON: """You are the Recon Agent, specialized in:
- Network and host enumeration
- Service detection and fingerprinting
- OSINT and information gathering
- Attack surface mapping

Focus on thorough, stealthy reconnaissance.""",

            AgentRole.EXPLOIT: """You are the Exploit Agent, specialized in:
- Vulnerability analysis and identification
- Exploit selection and customization
- Payload generation and delivery
- Initial access techniques

Always verify exploits are safe and targeted.""",

            AgentRole.PERSISTENCE: """You are the Persistence Agent, specialized in:
- Post-exploitation activities
- Maintaining access to compromised systems
- Lateral movement techniques
- Privilege escalation

Focus on stealth and avoiding detection.""",

            AgentRole.REPORTER: """You are the Reporter Agent, specialized in:
- Documenting findings clearly and professionally
- Generating penetration testing reports
- Summarizing attack chains
- Providing remediation recommendations

Focus on clarity and actionable insights.""",
        }
        
        return prompts.get(self.role, "You are a security agent.")
    
    def format_status(self) -> str:
        """Format current agent status for display.
        
        Returns:
            Formatted status string.
        """
        status_icons = {
            AgentState.IDLE: "⚪",
            AgentState.PLANNING: "🔵",
            AgentState.EXECUTING: "🟢",
            AgentState.WAITING: "🟡",
            AgentState.COMPLETED: "✅",
            AgentState.FAILED: "❌",
            AgentState.INTERRUPTED: "⚠️",
        }
        
        icon = status_icons.get(self._state, "❓")
        return f"[{icon} {self.name}] {self._state.value}"
