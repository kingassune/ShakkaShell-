"""Command generation orchestration logic.

This module coordinates the LLM provider to generate security commands from
natural language inputs.
"""

from typing import Callable, Optional

from shakka.config import ShakkaConfig
from shakka.providers.base import CommandResult, LLMProvider


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
        self._current_provider_name: Optional[str] = None
    
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

        if self._provider and self._current_provider_name == provider_name:
            return self._provider
        
        if provider_name == "openai":
            from shakka.providers.openai import OpenAIProvider

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
        self._current_provider_name = provider_name
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
        providers = self.list_providers()

        if not self._is_provider_supported(provider_name, providers):
            raise ValueError(
                f"Unsupported provider: {provider_name}. "
                f"Valid options: {', '.join(providers)}"
            )

        if not self._is_provider_configured(provider_name):
            raise ValueError(
                f"Provider '{provider_name}' is not configured. "
                "Please set the required credentials before switching."
            )

        self.config.default_provider = provider_name
        # Clear cached provider so it will be recreated on next use
        self._provider = None
        self._current_provider_name = None
    
    def list_providers(self) -> list[str]:
        """List available LLM providers.
        
        Returns:
            List of provider names
        """
        return list(self._get_provider_validators().keys())
    
    def get_provider_status(self) -> dict[str, bool]:
        """Get configuration status for all providers.
        
        Returns:
            Dictionary mapping provider names to configuration status
        """
        return {
            provider: self._is_provider_configured(provider)
            for provider in self.list_providers()
        }

    def _is_provider_supported(
        self, provider_name: str, providers: Optional[list[str]] = None
    ) -> bool:
        """Check if provider is supported.

        Args:
            provider_name: Provider name to check.
            providers: Optional cached provider list.

        Returns:
            True if the provider is supported, False otherwise.
        """
        provider_list = providers or self.list_providers()
        return provider_name in provider_list

    def _is_provider_configured(self, provider_name: str) -> bool:
        """Check configuration for a specific provider.

        Args:
            provider_name: Provider name to validate.

        Returns:
            True if the provider has required configuration, False otherwise.
        """
        validators = self._get_provider_validators()
        validator = validators.get(provider_name)
        return validator() if validator else False

    def _get_provider_validators(self) -> dict[str, Callable[[], bool]]:
        """Return configuration validators for each supported provider.

        Returns:
            Mapping of provider names to callables that validate configuration.
        """
        return {
            "openai": lambda: bool(self.config.openai_api_key),
            "anthropic": lambda: bool(self.config.anthropic_api_key),
            "ollama": lambda: True,
        }
