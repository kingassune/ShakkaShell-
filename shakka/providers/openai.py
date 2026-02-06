"""OpenAI LLM provider implementation using LiteLLM.

Supports GPT-4, GPT-3.5-turbo, o1, o1-mini, and other OpenAI models through
LiteLLM's unified interface. Includes special handling for o1 reasoning models.
"""

import json
from typing import Literal, Optional

from litellm import acompletion

from shakka.providers.base import CommandResult, LLMProvider


# O1 reasoning models need special handling
O1_MODELS = ["o1", "o1-mini", "o1-preview", "o1-2024-12-17"]


def is_o1_model(model: str) -> bool:
    """Check if a model is an o1 reasoning model.
    
    Args:
        model: Model name to check.
        
    Returns:
        True if model is an o1 reasoning model.
    """
    model_lower = model.lower()
    return any(o1 in model_lower for o1 in O1_MODELS)


class OpenAIProvider(LLMProvider):
    """OpenAI LLM provider using LiteLLM.
    
    Supports GPT-4, GPT-3.5-turbo, o1, o1-mini, and other OpenAI models through
    LiteLLM's unified interface. Special handling for o1 reasoning models.
    """
    
    def __init__(
        self,
        api_key: Optional[str] = None,
        model: str = "gpt-3.5-turbo",
        temperature: float = 0.1,
        reasoning_effort: Literal["low", "medium", "high"] = "medium",
        **kwargs
    ):
        """Initialize OpenAI provider.
        
        Args:
            api_key: OpenAI API key (can also be set via OPENAI_API_KEY env var)
            model: Model name (e.g., gpt-3.5-turbo, gpt-4, o1, o1-mini)
            temperature: Sampling temperature (0.0 to 1.0)
            reasoning_effort: Effort level for o1 models (low, medium, high)
            **kwargs: Additional LiteLLM parameters
        """
        super().__init__(api_key=api_key, **kwargs)
        self.model = model
        self.temperature = temperature
        self.reasoning_effort = reasoning_effort
        self._last_reasoning_content: Optional[str] = None
    
    @property
    def last_reasoning_content(self) -> Optional[str]:
        """Get the reasoning content from the last generation.
        
        Returns:
            The reasoning content if an o1 model was used, else None.
        """
        return self._last_reasoning_content
    
    @property
    def is_reasoning_model(self) -> bool:
        """Check if current model is an o1 reasoning model."""
        return is_o1_model(self.model)
    
    async def generate(
        self,
        prompt: str,
        context: Optional[dict] = None
    ) -> CommandResult:
        """Generate security command using OpenAI.
        
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
        
        # Reset reasoning content
        self._last_reasoning_content = None
        
        try:
            # O1 models don't support system messages in the same way
            if self.is_reasoning_model:
                # Combine system prompt into user message for o1
                messages = [
                    {"role": "user", "content": f"{self.get_system_prompt()}\n\n{prompt}"}
                ]
            else:
                messages = [
                    {"role": "system", "content": self.get_system_prompt()},
                    {"role": "user", "content": prompt}
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
            
            # O1 models have special requirements
            if self.is_reasoning_model:
                # O1 requires temperature=1 (or not specified)
                # Add reasoning effort parameter
                request_params["reasoning_effort"] = self.reasoning_effort
                # O1 doesn't support response_format in the same way
            else:
                request_params["temperature"] = self.temperature
                request_params["response_format"] = {"type": "json_object"}
            
            # Call OpenAI via LiteLLM
            response = await acompletion(**request_params)
            
            # Extract response content
            message = response.choices[0].message
            content = message.content
            
            # Track reasoning tokens if available
            reasoning_tokens = 0
            if hasattr(response, "usage") and response.usage:
                if hasattr(response.usage, "completion_tokens_details"):
                    details = response.usage.completion_tokens_details
                    if hasattr(details, "reasoning_tokens"):
                        reasoning_tokens = details.reasoning_tokens or 0
            
            # Handle o1 response format - may include reasoning
            if hasattr(message, "reasoning_content") and message.reasoning_content:
                self._last_reasoning_content = message.reasoning_content
            
            # Try to extract JSON from the response
            # O1 models may wrap JSON in markdown
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
            
            # Create CommandResult from response
            result = CommandResult(
                command=result_data.get("command", ""),
                explanation=result_data.get("explanation", ""),
                risk_level=result_data.get("risk_level", "Medium"),
                prerequisites=result_data.get("prerequisites", []),
                alternatives=result_data.get("alternatives", []),
                warnings=result_data.get("warnings", []),
                reasoning_tokens=reasoning_tokens,
            )
            
            # Add reasoning content if available
            if self._last_reasoning_content:
                result.thinking = self._last_reasoning_content
            
            return result
            
        except json.JSONDecodeError as e:
            raise RuntimeError(f"Failed to parse LLM response as JSON: {e}")
        except Exception as e:
            raise RuntimeError(f"OpenAI API call failed: {e}")
    
    async def validate_connection(self) -> bool:
        """Validate OpenAI API connection.
        
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
