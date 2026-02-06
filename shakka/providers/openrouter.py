"""OpenRouter LLM provider implementation using LiteLLM.

OpenRouter provides unified access to many LLM models at competitive prices:
- OpenAI (GPT-4, GPT-3.5)
- Anthropic (Claude)
- Meta (Llama)
- Google (Gemini)
- Mistral, Cohere, and more

Docs: https://openrouter.ai/docs/quickstart
"""

import json
import re
from typing import Optional

from litellm import acompletion

from shakka.providers.base import CommandResult, LLMProvider, UsageInfo


# Popular cost-effective models on OpenRouter
RECOMMENDED_MODELS = [
    "deepseek/deepseek-chat",                     # Very cheap, fast
    "google/gemini-2.0-flash-exp:free",           # Free tier
    "meta-llama/llama-3.3-70b-instruct",          # Good quality
    "openai/gpt-4o-mini",                         # Cheap OpenAI
    "anthropic/claude-3.5-haiku",                 # Cheap Claude
    "mistralai/mistral-small-24b-instruct-2501",  # Good quality
]


class OpenRouterProvider(LLMProvider):
    """OpenRouter LLM provider using LiteLLM.
    
    OpenRouter provides access to 200+ models through a single API,
    often at lower prices than direct provider access. Uses OpenAI-compatible
    API format.
    
    Example:
        provider = OpenRouterProvider(
            api_key="sk-or-v1-...",
            model="meta-llama/llama-3.1-8b-instruct:free"  # Free model
        )
        result = await provider.generate("scan ports on 192.168.1.1")
    """
    
    def __init__(
        self,
        api_key: Optional[str] = None,
        model: str = "deepseek/deepseek-chat",
        temperature: float = 0.1,
        site_url: Optional[str] = None,
        app_name: str = "ShakkaShell",
        **kwargs
    ):
        """Initialize OpenRouter provider.
        
        Args:
            api_key: OpenRouter API key (can also be set via OPENROUTER_API_KEY env var)
            model: Model identifier (e.g., "openai/gpt-4o", "anthropic/claude-3.5-sonnet")
                   See https://openrouter.ai/models for full list
            temperature: Sampling temperature (0.0 to 1.0)
            site_url: Optional URL of your site for rankings
            app_name: App name for OpenRouter rankings
            **kwargs: Additional LiteLLM parameters
        """
        super().__init__(api_key=api_key, **kwargs)
        self.model = model
        self.temperature = temperature
        self.site_url = site_url
        self.app_name = app_name
    
    def _get_extra_headers(self) -> dict:
        """Get OpenRouter-specific headers.
        
        Returns:
            Dict of extra headers for OpenRouter API
        """
        headers = {
            "HTTP-Referer": self.site_url or "https://github.com/ShakkaShell",
            "X-Title": self.app_name,
        }
        return headers
    
    async def generate(
        self,
        prompt: str,
        context: Optional[dict] = None
    ) -> CommandResult:
        """Generate security command using OpenRouter.
        
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
            messages = [
                {"role": "system", "content": self.get_system_prompt()},
                {"role": "user", "content": prompt}
            ]
            
            # Add context if provided
            if context:
                context_str = f"\nContext: {json.dumps(context)}"
                messages[-1]["content"] += context_str
            
            # Build request parameters
            # LiteLLM uses "openrouter/" prefix for OpenRouter models
            request_params = {
                "model": f"openrouter/{self.model}",
                "messages": messages,
                "api_key": self.api_key,
                "temperature": self.temperature,
                "extra_headers": self._get_extra_headers(),
            }
            
            # Some models support JSON mode
            if self._supports_json_mode():
                request_params["response_format"] = {"type": "json_object"}
            
            # Call OpenRouter via LiteLLM
            response = await acompletion(**request_params)
            
            # Extract response content
            content = response.choices[0].message.content
            
            # Extract usage info
            usage = None
            if hasattr(response, "usage") and response.usage:
                usage = UsageInfo(
                    input_tokens=response.usage.prompt_tokens or 0,
                    output_tokens=response.usage.completion_tokens or 0,
                    model=self.model
                )
            
            # Parse JSON response
            result = self._parse_json_response(content)
            
            # Add usage info
            if usage:
                result.usage = usage
            
            return result
            
        except json.JSONDecodeError as e:
            raise RuntimeError(f"Failed to parse LLM response as JSON: {e}")
        except Exception as e:
            raise RuntimeError(f"OpenRouter API error: {e}")
    
    def _supports_json_mode(self) -> bool:
        """Check if current model supports JSON mode.
        
        Returns:
            True if model supports response_format JSON mode
        """
        # Models known to support JSON mode well
        json_mode_models = [
            "openai/",
            "anthropic/claude-3",
            "mistralai/mistral-large",
            "google/gemini",
        ]
        return any(self.model.startswith(prefix) for prefix in json_mode_models)
    
    def _parse_json_response(self, content: str) -> CommandResult:
        """Parse JSON from LLM response content.
        
        Handles both raw JSON and JSON wrapped in markdown code blocks.
        
        Args:
            content: Raw response content from LLM
            
        Returns:
            Parsed CommandResult
        """
        # Try to extract JSON from markdown code blocks
        json_match = re.search(r"```(?:json)?\s*\n?(.*?)\n?```", content, re.DOTALL)
        if json_match:
            content = json_match.group(1)
        
        # Try to find JSON object in content
        json_object_match = re.search(r"\{.*\}", content, re.DOTALL)
        if json_object_match:
            content = json_object_match.group(0)
        
        data = json.loads(content)
        
        return CommandResult(
            command=data.get("command", ""),
            explanation=data.get("explanation", ""),
            risk_level=data.get("risk_level", "Medium"),
            prerequisites=data.get("prerequisites", []),
            alternatives=data.get("alternatives", []),
            warnings=data.get("warnings", [])
        )
    
    async def validate_connection(self) -> bool:
        """Validate connection to OpenRouter API.
        
        Returns:
            True if connection is successful
        """
        try:
            # Use a minimal request to test connection
            response = await acompletion(
                model=f"openrouter/{self.model}",
                messages=[{"role": "user", "content": "test"}],
                api_key=self.api_key,
                max_tokens=5,
                extra_headers=self._get_extra_headers(),
            )
            return response is not None
        except Exception:
            return False
    
    @staticmethod
    def list_recommended_models() -> list[str]:
        """List recommended cost-effective models.
        
        Returns:
            List of model identifiers for budget-friendly options
        """
        return RECOMMENDED_MODELS.copy()
