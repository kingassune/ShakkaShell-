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
