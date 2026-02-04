"""Anthropic (Claude) LLM provider implementation using LiteLLM."""

import json
from typing import Optional

from litellm import acompletion

from shakka.providers.base import CommandResult, LLMProvider


class AnthropicProvider(LLMProvider):
    """Anthropic (Claude) LLM provider using LiteLLM.
    
    Supports Claude 3 models (Opus, Sonnet, Haiku) through LiteLLM's
    unified interface.
    """
    
    def __init__(
        self,
        api_key: Optional[str] = None,
        model: str = "claude-3-sonnet-20240229",
        temperature: float = 0.1,
        **kwargs
    ):
        """Initialize Anthropic provider.
        
        Args:
            api_key: Anthropic API key (can also be set via ANTHROPIC_API_KEY env var)
            model: Model name (e.g., claude-3-opus, claude-3-sonnet, claude-3-haiku)
            temperature: Sampling temperature (0.0 to 1.0)
            **kwargs: Additional LiteLLM parameters
        """
        super().__init__(api_key=api_key, **kwargs)
        self.model = model
        self.temperature = temperature
    
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
        
        try:
            # Prepare messages
            messages = [
                {"role": "user", "content": f"{self.get_system_prompt()}\n\n{prompt}"}
            ]
            
            # Add context if provided
            if context:
                context_str = f"\nContext: {json.dumps(context)}"
                messages[-1]["content"] += context_str
            
            # Call Anthropic via LiteLLM
            response = await acompletion(
                model=self.model,
                messages=messages,
                temperature=self.temperature,
                api_key=self.api_key,
            )
            
            # Extract response content
            content = response.choices[0].message.content
            
            # Try to extract JSON from the response
            # Claude sometimes wraps JSON in markdown code blocks
            if "```json" in content:
                json_start = content.find("```json") + 7
                json_end = content.find("```", json_start)
                content = content[json_start:json_end].strip()
            elif "```" in content:
                json_start = content.find("```") + 3
                json_end = content.find("```", json_start)
                content = content[json_start:json_end].strip()
            
            # Parse JSON response
            result_data = json.loads(content)
            
            # Create CommandResult from response
            return CommandResult(
                command=result_data.get("command", ""),
                explanation=result_data.get("explanation", ""),
                risk_level=result_data.get("risk_level", "Medium"),
                prerequisites=result_data.get("prerequisites", []),
                alternatives=result_data.get("alternatives", []),
                warnings=result_data.get("warnings", [])
            )
            
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
