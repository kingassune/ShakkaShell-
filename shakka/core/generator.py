"""Command generation orchestration logic.

This module coordinates the LLM provider to generate security commands from
natural language inputs.
"""

from typing import Optional

from shakka.config import ShakkaConfig
from shakka.providers.base import CommandResult, LLMProvider
from shakka.providers.openai import OpenAIProvider


class CommandGenerator:
    """Orchestrates command generation using configured LLM provider.
    
    This class manages the interaction between the user's request and the
    LLM provider, handling provider selection and configuration.
    """
    
    def __init__(self, config: Optional[ShakkaConfig] = None):
        """Initialize command generator.
        
        Args:
            config: ShakkaConfig instance. If None, loads default config.
        """
        self.config = config or ShakkaConfig()
        self._provider: Optional[LLMProvider] = None
        self._provider_name: Optional[str] = None
    
    def _get_provider(self, provider_name: Optional[str] = None) -> LLMProvider:
        """Get or create LLM provider instance.
        
        Args:
            provider_name: Provider name (openai, anthropic, ollama).
                          If None, uses default from config.
        
        Returns:
            Configured LLMProvider instance
            
        Raises:
            ValueError: If provider name is invalid or API key is missing
        """
        provider_name = provider_name or self.config.default_provider

        if self._provider and self._provider_name == provider_name:
            return self._provider
        
        if provider_name == "openai":
            api_key = self.config.openai_api_key
            if not api_key:
                raise ValueError(
                    "OpenAI API key not found. "
                    "Set OPENAI_API_KEY environment variable or configure in settings."
                )
            provider = OpenAIProvider(api_key=api_key)
        
        elif provider_name == "anthropic":
            api_key = self.config.anthropic_api_key
            if not api_key:
                raise ValueError(
                    "Anthropic API key not found. "
                    "Set ANTHROPIC_API_KEY environment variable or configure in settings."
                )
            # Import here to avoid dependency if not used
            from shakka.providers.anthropic import AnthropicProvider
            provider = AnthropicProvider(api_key=api_key)
        
        elif provider_name == "ollama":
            # Import here to avoid dependency if not used
            from shakka.providers.ollama import OllamaProvider
            provider = OllamaProvider(
                base_url=self.config.ollama_base_url,
                model=self.config.ollama_model
            )
        
        else:
            raise ValueError(
                f"Unknown provider: {provider_name}. "
                f"Valid options: openai, anthropic, ollama"
            )

        self._provider = provider
        self._provider_name = provider_name
        return provider
    
    async def generate(
        self,
        prompt: str,
        provider: Optional[str] = None,
        context: Optional[dict] = None
    ) -> CommandResult:
        """Generate security command from natural language.
        
        Args:
            prompt: User's natural language request
            provider: Optional provider name to override default
            context: Optional context information (history, etc.)
        
        Returns:
            CommandResult with generated command and metadata
            
        Raises:
            ValueError: If prompt is empty or provider is invalid
            RuntimeError: If generation fails
        """
        if not prompt or not prompt.strip():
            raise ValueError("Prompt cannot be empty")
        
        # Get provider instance
        llm_provider = self._get_provider(provider)
        
        # Generate command
        try:
            result = await llm_provider.generate(prompt, context)
            return result
        except Exception as e:
            raise RuntimeError(f"Command generation failed: {e}")
    
    async def validate_provider(self, provider: Optional[str] = None) -> bool:
        """Validate that the specified provider is configured and working.
        
        Args:
            provider: Provider name to validate. If None, uses default.
        
        Returns:
            True if provider is valid and connected, False otherwise
        """
        try:
            llm_provider = self._get_provider(provider)
            return await llm_provider.validate_connection()
        except Exception:
            return False

    def set_provider(self, provider_name: str) -> None:
        """Set the active provider without recreating the generator.

        Args:
            provider_name: Provider name to switch to.

        Raises:
            ValueError: If the provider is not supported.
        """
        if provider_name not in self.list_providers():
            raise ValueError(
                f"Unknown provider: {provider_name}. "
                f"Valid options: {', '.join(self.list_providers())}"
            )

        self.config.default_provider = provider_name
        # Clear cached provider so it will be recreated on next use
        self._provider = None
        self._provider_name = None
    
    def list_providers(self) -> list[str]:
        """List available LLM providers.
        
        Returns:
            List of provider names
        """
        return ["openai", "anthropic", "ollama"]
    
    def get_provider_status(self) -> dict[str, bool]:
        """Get configuration status for all providers.
        
        Returns:
            Dictionary mapping provider names to configuration status
        """
        return {
            "openai": bool(self.config.openai_api_key),
            "anthropic": bool(self.config.anthropic_api_key),
            "ollama": True  # Ollama doesn't require API key
        }
