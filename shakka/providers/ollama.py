"""Ollama LLM provider implementation for local models."""

import json
from typing import Optional

from litellm import acompletion

from shakka.providers.base import CommandResult, LLMProvider


class OllamaProvider(LLMProvider):
    """Ollama LLM provider for running local models.
    
    Supports any model available in Ollama (llama2, mistral, codellama, etc.)
    through LiteLLM's unified interface.
    """
    
    def __init__(
        self,
        base_url: str = "http://localhost:11434",
        model: str = "llama2",
        temperature: float = 0.1,
        **kwargs
    ):
        """Initialize Ollama provider.
        
        Args:
            base_url: Ollama server URL
            model: Model name (e.g., llama2, mistral, codellama)
            temperature: Sampling temperature (0.0 to 1.0)
            **kwargs: Additional LiteLLM parameters
        """
        super().__init__(api_key=None, **kwargs)  # Ollama doesn't need API key
        self.base_url = base_url
        self.model = f"ollama/{model}"  # LiteLLM expects ollama/ prefix
        self.temperature = temperature
    
    async def generate(
        self,
        prompt: str,
        context: Optional[dict] = None
    ) -> CommandResult:
        """Generate security command using Ollama.
        
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
                {"role": "system", "content": self.get_system_prompt()},
                {"role": "user", "content": prompt}
            ]
            
            # Add context if provided
            if context:
                context_str = f"\nContext: {json.dumps(context)}"
                messages[-1]["content"] += context_str
            
            # Call Ollama via LiteLLM
            response = await acompletion(
                model=self.model,
                messages=messages,
                temperature=self.temperature,
                api_base=self.base_url,
            )
            
            # Extract response content
            content = response.choices[0].message.content
            
            # Try to extract JSON from the response
            # Local models sometimes include extra text
            if "```json" in content:
                json_start = content.find("```json") + 7
                json_end = content.find("```", json_start)
                content = content[json_start:json_end].strip()
            elif "```" in content:
                json_start = content.find("```") + 3
                json_end = content.find("```", json_start)
                content = content[json_start:json_end].strip()
            elif "{" in content and "}" in content:
                # Extract just the JSON object
                json_start = content.find("{")
                json_end = content.rfind("}") + 1
                content = content[json_start:json_end]
            
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
            raise RuntimeError(f"Ollama API call failed: {e}")
    
    async def validate_connection(self) -> bool:
        """Validate Ollama server connection.
        
        Returns:
            True if connection is successful, False otherwise
        """
        try:
            # Try a simple completion with minimal tokens
            response = await acompletion(
                model=self.model,
                messages=[{"role": "user", "content": "test"}],
                max_tokens=5,
                api_base=self.base_url
            )
            return response is not None
        except Exception:
            return False
