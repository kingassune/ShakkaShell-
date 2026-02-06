"""Anthropic (Claude) LLM provider implementation using LiteLLM.

Supports Claude models including extended thinking for reasoning models like
claude-3-5-sonnet-20241022 and newer.
"""

import json
from typing import Optional

from litellm import acompletion

from shakka.providers.base import CommandResult, LLMProvider


# Models that support extended thinking
EXTENDED_THINKING_MODELS = [
    "claude-3-5-sonnet-20241022",
    "claude-3-5-sonnet",
    "claude-3-7-sonnet",
    "claude-sonnet-4",
    "claude-4",
]


def model_supports_extended_thinking(model: str) -> bool:
    """Check if a model supports extended thinking.
    
    Extended thinking is supported by newer Claude models:
    - claude-3-5-sonnet-20241022 and later
    - claude-3-7-sonnet
    - claude-sonnet-4 and later
    - claude-4
    
    Args:
        model: Model name to check.
        
    Returns:
        True if model supports extended thinking.
    """
    model_lower = model.lower()
    
    # Check for exact matches or prefixes
    for supported in EXTENDED_THINKING_MODELS:
        if supported in model_lower:
            return True
    
    return False


class AnthropicProvider(LLMProvider):
    """Anthropic (Claude) LLM provider using LiteLLM.
    
    Supports Claude 3 models (Opus, Sonnet, Haiku) through LiteLLM's
    unified interface. Also supports extended thinking for reasoning models.
    """
    
    def __init__(
        self,
        api_key: Optional[str] = None,
        model: str = "claude-3-sonnet-20240229",
        temperature: float = 0.1,
        enable_extended_thinking: bool = False,
        thinking_budget: int = 10000,
        **kwargs
    ):
        """Initialize Anthropic provider.
        
        Args:
            api_key: Anthropic API key (can also be set via ANTHROPIC_API_KEY env var)
            model: Model name (e.g., claude-3-opus, claude-3-sonnet, claude-3-haiku)
            temperature: Sampling temperature (0.0 to 1.0)
            enable_extended_thinking: Enable extended thinking mode for supported models
            thinking_budget: Maximum tokens for thinking (default 10000)
            **kwargs: Additional LiteLLM parameters
        """
        super().__init__(api_key=api_key, **kwargs)
        self.model = model
        self.temperature = temperature
        self.enable_extended_thinking = enable_extended_thinking
        self.thinking_budget = thinking_budget
        self._last_thinking_content: Optional[str] = None
    
    @property
    def last_thinking_content(self) -> Optional[str]:
        """Get the thinking content from the last generation.
        
        Returns:
            The thinking content if extended thinking was used, else None.
        """
        return self._last_thinking_content
    
    async def generate(
        self,
        prompt: str,
        context: Optional[dict] = None
    ) -> CommandResult:
        """Generate security command using Anthropic Claude.
        
        Args:
            prompt: User's natural language request
            context: Optional context information
            
        Returns:
            CommandResult with generated command
            
        Raises:
            ValueError: If prompt is empty
            RuntimeError: If API call fails
        """
        if not prompt or not prompt.strip():
            raise ValueError("Prompt cannot be empty")
        
        # Reset thinking content
        self._last_thinking_content = None
        
        try:
            # Prepare messages
            messages = [
                {"role": "user", "content": f"{self.get_system_prompt()}\n\n{prompt}"}
            ]
            
            # Add context if provided
            if context:
                context_str = f"\nContext: {json.dumps(context)}"
                messages[-1]["content"] += context_str
            
            # Build request parameters
            request_params = {
                "model": self.model,
                "messages": messages,
                "api_key": self.api_key,
            }
            
            # Check if extended thinking should be used
            use_extended_thinking = (
                self.enable_extended_thinking 
                and model_supports_extended_thinking(self.model)
            )
            
            if use_extended_thinking:
                # Extended thinking requires temperature=1 and specific parameters
                request_params["temperature"] = 1.0
                request_params["thinking"] = {
                    "type": "enabled",
                    "budget_tokens": self.thinking_budget,
                }
            else:
                request_params["temperature"] = self.temperature
            
            # Call Anthropic via LiteLLM
            response = await acompletion(**request_params)
            
            # Extract response content
            message = response.choices[0].message
            content = message.content
            
            # Handle extended thinking response format
            # LiteLLM may return thinking content in different ways
            if hasattr(message, "thinking") and message.thinking:
                self._last_thinking_content = message.thinking
            elif hasattr(message, "reasoning_content") and message.reasoning_content:
                self._last_thinking_content = message.reasoning_content
            
            # Try to extract JSON from the response
            # Claude sometimes wraps JSON in markdown code blocks
            if "```json" in content:
                json_start = content.find("```json") + 7
                json_end = content.find("```", json_start)
                if json_end != -1:
                    content = content[json_start:json_end].strip()
            elif "```" in content:
                json_start = content.find("```") + 3
                json_end = content.find("```", json_start)
                if json_end != -1:
                    content = content[json_start:json_end].strip()
            
            # Parse JSON response
            result_data = json.loads(content)
            
            # Include thinking in the result data if available
            thinking = self._last_thinking_content
            
            # Create CommandResult from response
            result = CommandResult(
                command=result_data.get("command", ""),
                explanation=result_data.get("explanation", ""),
                risk_level=result_data.get("risk_level", "Medium"),
                prerequisites=result_data.get("prerequisites", []),
                alternatives=result_data.get("alternatives", []),
                warnings=result_data.get("warnings", [])
            )
            
            # Add thinking to result if available
            if thinking:
                result.thinking = thinking
            
            return result
            
        except json.JSONDecodeError as e:
            raise RuntimeError(f"Failed to parse LLM response as JSON: {e}")
        except Exception as e:
            raise RuntimeError(f"Anthropic API call failed: {e}")
    
    async def validate_connection(self) -> bool:
        """Validate Anthropic API connection.
        
        Returns:
            True if connection is successful, False otherwise
        """
        try:
            # Try a simple completion with minimal tokens
            response = await acompletion(
                model=self.model,
                messages=[{"role": "user", "content": "test"}],
                max_tokens=5,
                api_key=self.api_key
            )
            return response is not None
        except Exception:
            return False
