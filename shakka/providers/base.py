"""Abstract base class for LLM providers.

All LLM providers (OpenAI, Anthropic, Ollama) must implement the LLMProvider interface.
"""

from abc import ABC, abstractmethod
from typing import Optional

from pydantic import BaseModel, Field


class CommandResult(BaseModel):
    """Result from LLM command generation.
    
    Attributes:
        command: The executable security command
        explanation: 1-2 sentence explanation of what the command does
        risk_level: Safety level (Low, Medium, High, Critical)
        prerequisites: List of required tools/packages
        alternatives: List of alternative commands
        warnings: List of safety warnings
    """
    
    command: str = Field(
        ...,
        description="The full executable command",
        min_length=1
    )
    
    explanation: str = Field(
        ...,
        description="1-2 sentence explanation of the command",
        min_length=1
    )
    
    risk_level: str = Field(
        ...,
        description="Risk level: Low, Medium, High, or Critical",
        pattern="^(Low|Medium|High|Critical)$"
    )
    
    prerequisites: list[str] = Field(
        default_factory=list,
        description="Required tools or packages"
    )
    
    alternatives: list[str] = Field(
        default_factory=list,
        description="Alternative command options"
    )
    
    warnings: list[str] = Field(
        default_factory=list,
        description="Safety warnings for the command"
    )
    
    def __str__(self) -> str:
        """String representation of the command result."""
        return f"CommandResult(command='{self.command}', risk_level='{self.risk_level}')"
    
    def __repr__(self) -> str:
        """Detailed string representation."""
        return (
            f"CommandResult(command='{self.command}', "
            f"risk_level='{self.risk_level}', "
            f"prerequisites={self.prerequisites})"
        )


class LLMProvider(ABC):
    """Abstract base class for LLM providers.
    
    All provider implementations must inherit from this class and implement
    the generate() method.
    """
    
    def __init__(self, api_key: Optional[str] = None, **kwargs):
        """Initialize the LLM provider.
        
        Args:
            api_key: API key for the provider (if required)
            **kwargs: Additional provider-specific configuration
        """
        self.api_key = api_key
        self.config = kwargs
    
    @abstractmethod
    async def generate(
        self,
        prompt: str,
        context: Optional[dict] = None
    ) -> CommandResult:
        """Generate a security command from natural language.
        
        Args:
            prompt: User's natural language request
            context: Optional context information (history, preferences, etc.)
            
        Returns:
            CommandResult with generated command and metadata
            
        Raises:
            ValueError: If prompt is empty or invalid
            RuntimeError: If LLM API call fails
        """
        pass
    
    @abstractmethod
    async def validate_connection(self) -> bool:
        """Validate that the provider can connect to the LLM service.
        
        Returns:
            True if connection is successful, False otherwise
        """
        pass
    
    def get_system_prompt(self) -> str:
        """Get the system prompt for command generation.
        
        Returns:
            System prompt string
        """
        return """You are ShakkaShell, an expert offensive security command generator.

TASK: Convert the user's natural language request into an executable security command.

RULES:
1. Output valid JSON only, no markdown
2. Use common tools: nmap, gobuster, ffuf, sqlmap, hydra, nikto, crackmapexec
3. Prefer safe defaults, add aggressive flags only when requested
4. Risk levels: Low (passive/safe), Medium (active scanning), High (exploitation), Critical (destructive)

OUTPUT FORMAT:
{
  "command": "the full executable command",
  "explanation": "1-2 sentence explanation",
  "risk_level": "Low|Medium|High|Critical",
  "prerequisites": ["tool1", "tool2"],
  "alternatives": ["alt command 1"],
  "warnings": ["any safety warnings"]
}"""
