"""Configuration management for ShakkaShell using Pydantic Settings.

Loads configuration from environment variables and YAML config files.
Config file locations:
  - Linux/macOS: ~/.config/shakka/config.yaml
  - Windows: %APPDATA%/shakka/config.yaml
"""

from pathlib import Path
from typing import Literal, Optional

from pydantic import AliasChoices, Field
from pydantic_settings import BaseSettings, SettingsConfigDict
from platformdirs import user_config_dir


class ShakkaConfig(BaseSettings):
    """Main configuration class for ShakkaShell.
    
    Configuration is loaded from:
    1. Environment variables (highest priority)
    2. Config file at ~/.config/shakka/config.yaml
    3. Default values (lowest priority)
    """
    
    model_config = SettingsConfigDict(
        env_prefix="SHAKKA_",
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )
    
    # LLM Provider Settings
    default_provider: Literal["openai", "anthropic", "ollama"] = Field(
        default="openai",
        description="Default LLM provider to use"
    )
    
    openai_api_key: Optional[str] = Field(
        default=None,
        description="OpenAI API key",
        validation_alias=AliasChoices(
            "openai_api_key", "SHAKKA_OPENAI_API_KEY", "OPENAI_API_KEY"
        ),
    )
    
    anthropic_api_key: Optional[str] = Field(
        default=None,
        description="Anthropic API key",
        validation_alias=AliasChoices(
            "anthropic_api_key", "SHAKKA_ANTHROPIC_API_KEY", "ANTHROPIC_API_KEY"
        ),
    )
    
    ollama_base_url: str = Field(
        default="http://localhost:11434",
        description="Ollama base URL for local models"
    )
    
    ollama_model: str = Field(
        default="llama2",
        description="Ollama model name to use"
    )
    
    # Fallback Configuration
    fallback_providers: list[str] = Field(
        default_factory=lambda: ["anthropic", "ollama"],
        description="Ordered list of fallback providers when primary fails"
    )
    
    enable_fallback: bool = Field(
        default=True,
        description="Enable automatic fallback to alternative providers"
    )
    
    # Cost Tracking Configuration
    enable_cost_tracking: bool = Field(
        default=True,
        description="Enable tracking of token usage and costs per provider"
    )
    
    # Application Settings
    config_path: Optional[Path] = Field(
        default=None,
        description="Custom config file path"
    )
    
    debug: bool = Field(
        default=False,
        description="Enable debug mode"
    )
    
    max_history: int = Field(
        default=100,
        description="Maximum number of history entries to keep"
    )
    
    auto_copy: bool = Field(
        default=True,
        description="Automatically copy generated commands to clipboard"
    )
    
    confirm_execution: bool = Field(
        default=True,
        description="Require confirmation before executing commands"
    )
    
    # Database Settings
    db_path: Optional[Path] = Field(
        default=None,
        description="Path to SQLite database file"
    )
    
    def __init__(self, **kwargs):
        """Initialize configuration with default paths."""
        super().__init__(**kwargs)
        
        # Set default config path if not provided
        if self.config_path is None:
            config_dir = Path(user_config_dir("shakka", appauthor=False))
            self.config_path = config_dir / "config.yaml"
        
        # Set default database path if not provided
        if self.db_path is None:
            config_dir = Path(user_config_dir("shakka", appauthor=False))
            self.db_path = config_dir / "history.db"
    
    def get_api_key(self, provider: str) -> Optional[str]:
        """Get API key for specified provider.
        
        Args:
            provider: Provider name (openai, anthropic, ollama)
            
        Returns:
            API key string or None if not configured
        """
        if provider == "openai":
            return self.openai_api_key
        elif provider == "anthropic":
            return self.anthropic_api_key
        return None
    
    @classmethod
    def load_from_file(cls, config_path: Optional[Path] = None) -> "ShakkaConfig":
        """Load configuration from YAML file.
        
        Args:
            config_path: Optional custom config file path
            
        Returns:
            ShakkaConfig instance with loaded settings
        """
        import yaml
        
        if config_path is None:
            config_dir = Path(user_config_dir("shakka", appauthor=False))
            config_path = config_dir / "config.yaml"
        
        if config_path.exists():
            with open(config_path, "r") as f:
                data = yaml.safe_load(f) or {}
            return cls(**data)
        
        return cls()
    
    def save_to_file(self, config_path: Optional[Path] = None) -> None:
        """Save configuration to YAML file.
        
        Args:
            config_path: Optional custom config file path
        """
        import yaml
        
        if config_path is None:
            config_path = self.config_path
        
        # Ensure directory exists
        config_path.parent.mkdir(parents=True, exist_ok=True)
        
        # Convert to dict and save
        data = self.model_dump(exclude_none=True)
        
        # Convert Path objects to strings for YAML serialization
        for key, value in data.items():
            if isinstance(value, Path):
                data[key] = str(value)
        
        with open(config_path, "w") as f:
            yaml.dump(data, f, default_flow_style=False)
