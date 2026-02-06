"""Test configuration management."""

import os
from pathlib import Path
import tempfile
import pytest

from shakka.config import ShakkaConfig


def test_config_defaults():
    """Test default configuration values."""
    config = ShakkaConfig()
    
    assert config.default_provider == "openai"
    assert config.debug is False
    assert config.max_history == 100
    assert config.auto_copy is True
    assert config.confirm_execution is True
    assert config.ollama_base_url == "http://localhost:11434"
    assert config.ollama_model == "llama2"


def test_config_from_env():
    """Test configuration loading from environment variables."""
    os.environ["SHAKKA_DEFAULT_PROVIDER"] = "anthropic"
    os.environ["SHAKKA_DEBUG"] = "true"
    os.environ["SHAKKA_MAX_HISTORY"] = "50"
    
    config = ShakkaConfig()
    
    assert config.default_provider == "anthropic"
    assert config.debug is True
    assert config.max_history == 50
    
    # Clean up
    del os.environ["SHAKKA_DEFAULT_PROVIDER"]
    del os.environ["SHAKKA_DEBUG"]
    del os.environ["SHAKKA_MAX_HISTORY"]


def test_get_api_key():
    """Test getting API keys for different providers."""
    config = ShakkaConfig(
        openai_api_key="sk-test-openai",
        anthropic_api_key="sk-ant-test"
    )
    
    assert config.get_api_key("openai") == "sk-test-openai"
    assert config.get_api_key("anthropic") == "sk-ant-test"
    assert config.get_api_key("ollama") is None


def test_config_paths():
    """Test that config paths are set correctly."""
    config = ShakkaConfig()
    
    assert config.config_path is not None
    assert isinstance(config.config_path, Path)
    assert config.config_path.name == "config.yaml"
    
    assert config.db_path is not None
    assert isinstance(config.db_path, Path)
    assert config.db_path.name == "history.db"


def test_save_and_load_config():
    """Test saving and loading configuration from file."""
    with tempfile.TemporaryDirectory() as tmpdir:
        config_path = Path(tmpdir) / "test_config.yaml"
        
        # Create and save config
        config = ShakkaConfig(
            default_provider="anthropic",
            debug=True,
            max_history=50
        )
        config.save_to_file(config_path)
        
        # Verify file was created
        assert config_path.exists()
        
        # Load config from file
        loaded_config = ShakkaConfig.load_from_file(config_path)
        
        assert loaded_config.default_provider == "anthropic"
        assert loaded_config.debug is True
        assert loaded_config.max_history == 50


def test_load_nonexistent_config():
    """Test loading from non-existent config file returns defaults."""
    with tempfile.TemporaryDirectory() as tmpdir:
        config_path = Path(tmpdir) / "nonexistent.yaml"
        config = ShakkaConfig.load_from_file(config_path)
        
        # Should return default values
        assert config.default_provider == "openai"
        assert config.debug is False


def test_config_standard_env_keys(monkeypatch):
    """Test loading API keys from standard env vars without SHAKKA_ prefix."""
    monkeypatch.setenv("OPENAI_API_KEY", "sk-openai-env")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-anthropic-env")

    config = ShakkaConfig()

    assert config.openai_api_key == "sk-openai-env"
    assert config.anthropic_api_key == "sk-anthropic-env"


def test_config_fallback_defaults():
    """Test default fallback configuration values."""
    config = ShakkaConfig()
    
    assert config.enable_fallback is True
    assert isinstance(config.fallback_providers, list)
    assert "anthropic" in config.fallback_providers
    assert "ollama" in config.fallback_providers


def test_config_fallback_from_env(monkeypatch):
    """Test fallback settings can be configured via env vars."""
    monkeypatch.setenv("SHAKKA_ENABLE_FALLBACK", "false")
    
    config = ShakkaConfig()
    
    assert config.enable_fallback is False


def test_config_fallback_custom_providers():
    """Test custom fallback provider list."""
    config = ShakkaConfig(fallback_providers=["ollama"])
    
    assert config.fallback_providers == ["ollama"]


# =============================================================================
# Agent Model Configuration Tests
# =============================================================================

class TestAgentModelConfig:
    """Tests for per-agent-role model configuration."""
    
    def test_get_agent_model_defaults(self):
        """Test default agent model values."""
        config = ShakkaConfig()
        
        # Orchestrator has its own model
        assert config.get_agent_model("orchestrator") == "gpt-4o"
        
        # Other roles use agent_default_model
        assert config.get_agent_model("recon") == "gpt-4o"
        assert config.get_agent_model("exploit") == "gpt-4o"
        assert config.get_agent_model("persistence") == "gpt-4o"
        assert config.get_agent_model("reporter") == "gpt-4o"
    
    def test_get_agent_model_per_role(self):
        """Test per-role model configuration."""
        config = ShakkaConfig(
            agent_recon_model="claude-sonnet-4",
            agent_exploit_model="o1",
            agent_persistence_model="gpt-4o-mini",
            agent_reporter_model="claude-haiku-3",
        )
        
        assert config.get_agent_model("recon") == "claude-sonnet-4"
        assert config.get_agent_model("exploit") == "o1"
        assert config.get_agent_model("persistence") == "gpt-4o-mini"
        assert config.get_agent_model("reporter") == "claude-haiku-3"
        # Orchestrator still uses its own field
        assert config.get_agent_model("orchestrator") == "gpt-4o"
    
    def test_get_agent_model_case_insensitive(self):
        """Test role name is case-insensitive."""
        config = ShakkaConfig(agent_recon_model="test-model")
        
        assert config.get_agent_model("RECON") == "test-model"
        assert config.get_agent_model("Recon") == "test-model"
        assert config.get_agent_model("recon") == "test-model"
    
    def test_get_agent_model_custom_default(self):
        """Test custom default agent model."""
        config = ShakkaConfig(agent_default_model="custom-model")
        
        # Unset roles should use agent_default_model
        assert config.get_agent_model("recon") == "custom-model"
        assert config.get_agent_model("exploit") == "custom-model"
    
    def test_get_agent_model_orchestrator_model(self):
        """Test orchestrator model configuration."""
        config = ShakkaConfig(agent_orchestrator_model="gpt-4-turbo")
        
        assert config.get_agent_model("orchestrator") == "gpt-4-turbo"
    
    def test_get_agent_provider_defaults(self):
        """Test default agent provider values."""
        config = ShakkaConfig()
        
        # All default to default_provider
        assert config.get_agent_provider("orchestrator") == "openai"
        assert config.get_agent_provider("recon") == "openai"
        assert config.get_agent_provider("exploit") == "openai"
    
    def test_get_agent_provider_per_role(self):
        """Test per-role provider configuration."""
        config = ShakkaConfig(
            agent_recon_provider="anthropic",
            agent_exploit_provider="openai",
            agent_persistence_provider="ollama",
        )
        
        assert config.get_agent_provider("recon") == "anthropic"
        assert config.get_agent_provider("exploit") == "openai"
        assert config.get_agent_provider("persistence") == "ollama"
        # Reporter uses default
        assert config.get_agent_provider("reporter") == "openai"
    
    def test_get_agent_provider_default_agent_provider(self):
        """Test agent_default_provider fallback."""
        config = ShakkaConfig(
            agent_default_provider="anthropic",
        )
        
        # All should use agent_default_provider
        assert config.get_agent_provider("recon") == "anthropic"
        assert config.get_agent_provider("exploit") == "anthropic"
        assert config.get_agent_provider("orchestrator") == "anthropic"
    
    def test_get_agent_provider_role_overrides_default(self):
        """Test role-specific provider overrides default."""
        config = ShakkaConfig(
            agent_default_provider="anthropic",
            agent_recon_provider="openai",
        )
        
        assert config.get_agent_provider("recon") == "openai"
        assert config.get_agent_provider("exploit") == "anthropic"
    
    def test_agent_config_from_env(self, monkeypatch):
        """Test agent model configuration from environment."""
        monkeypatch.setenv("SHAKKA_AGENT_RECON_MODEL", "env-recon-model")
        monkeypatch.setenv("SHAKKA_AGENT_EXPLOIT_PROVIDER", "anthropic")
        
        config = ShakkaConfig()
        
        assert config.agent_recon_model == "env-recon-model"
        assert config.agent_exploit_provider == "anthropic"
    
    def test_agent_config_fields_exist(self):
        """Test all agent config fields exist."""
        config = ShakkaConfig()
        
        # Model fields
        assert hasattr(config, 'agent_orchestrator_model')
        assert hasattr(config, 'agent_default_model')
        assert hasattr(config, 'agent_recon_model')
        assert hasattr(config, 'agent_exploit_model')
        assert hasattr(config, 'agent_persistence_model')
        assert hasattr(config, 'agent_reporter_model')
        
        # Provider fields
        assert hasattr(config, 'agent_default_provider')
        assert hasattr(config, 'agent_orchestrator_provider')
        assert hasattr(config, 'agent_recon_provider')
        assert hasattr(config, 'agent_exploit_provider')
        assert hasattr(config, 'agent_persistence_provider')
        assert hasattr(config, 'agent_reporter_provider')


class TestReasoningModelConfig:
    """Tests for reasoning model configuration."""
    
    def test_extended_thinking_defaults(self):
        """Test extended thinking default values."""
        config = ShakkaConfig()
        
        assert config.enable_extended_thinking is False
        assert config.extended_thinking_budget == 10000
        assert config.o1_reasoning_effort == "medium"
    
    def test_extended_thinking_enabled(self):
        """Test enabling extended thinking."""
        config = ShakkaConfig(enable_extended_thinking=True)
        
        assert config.enable_extended_thinking is True
    
    def test_extended_thinking_budget_custom(self):
        """Test custom thinking budget."""
        config = ShakkaConfig(extended_thinking_budget=5000)
        
        assert config.extended_thinking_budget == 5000
    
    def test_o1_reasoning_effort_values(self):
        """Test valid reasoning effort values."""
        config_low = ShakkaConfig(o1_reasoning_effort="low")
        config_medium = ShakkaConfig(o1_reasoning_effort="medium")
        config_high = ShakkaConfig(o1_reasoning_effort="high")
        
        assert config_low.o1_reasoning_effort == "low"
        assert config_medium.o1_reasoning_effort == "medium"
        assert config_high.o1_reasoning_effort == "high"
    
    def test_reasoning_config_from_env(self, monkeypatch):
        """Test reasoning config from environment variables."""
        monkeypatch.setenv("SHAKKA_ENABLE_EXTENDED_THINKING", "true")
        monkeypatch.setenv("SHAKKA_EXTENDED_THINKING_BUDGET", "8000")
        monkeypatch.setenv("SHAKKA_O1_REASONING_EFFORT", "high")
        
        config = ShakkaConfig()
        
        assert config.enable_extended_thinking is True
        assert config.extended_thinking_budget == 8000
        assert config.o1_reasoning_effort == "high"
    
    def test_reasoning_config_fields_exist(self):
        """Test all reasoning config fields exist."""
        config = ShakkaConfig()
        
        assert hasattr(config, 'enable_extended_thinking')
        assert hasattr(config, 'extended_thinking_budget')
        assert hasattr(config, 'o1_reasoning_effort')
