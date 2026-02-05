"""Test command generator orchestration."""

import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from shakka.config import ShakkaConfig
from shakka.core.generator import CommandGenerator
from shakka.providers.base import CommandResult


@pytest.fixture
def mock_config():
    """Mock configuration with API keys."""
    return ShakkaConfig(
        openai_api_key="sk-test-openai",
        anthropic_api_key="sk-ant-test",
        default_provider="openai"
    )


@pytest.fixture
def mock_command_result():
    """Mock command result."""
    return CommandResult(
        command="nmap -sV 10.0.0.1",
        explanation="Service version scan",
        risk_level="Medium",
        prerequisites=["nmap"]
    )


def test_generator_init():
    """Test generator initialization."""
    generator = CommandGenerator()
    assert generator.config is not None
    assert isinstance(generator.config, ShakkaConfig)


def test_generator_init_with_config(mock_config):
    """Test generator initialization with custom config."""
    generator = CommandGenerator(config=mock_config)
    assert generator.config == mock_config


def test_get_provider_openai(mock_config):
    """Test getting OpenAI provider."""
    generator = CommandGenerator(config=mock_config)
    provider = generator._get_provider("openai")
    
    assert provider is not None
    assert provider.api_key == "sk-test-openai"


def test_get_provider_missing_api_key():
    """Test error when API key is missing."""
    config = ShakkaConfig()  # No API keys
    generator = CommandGenerator(config=config)
    
    with pytest.raises(ValueError, match="OpenAI API key not found"):
        generator._get_provider("openai")


def test_get_provider_invalid_name(mock_config):
    """Test error with invalid provider name."""
    generator = CommandGenerator(config=mock_config)
    
    with pytest.raises(ValueError, match="Unknown provider"):
        generator._get_provider("invalid")


def test_get_provider_default(mock_config):
    """Test using default provider from config."""
    generator = CommandGenerator(config=mock_config)
    provider = generator._get_provider()
    
    # Should use default (openai)
    assert provider is not None


@pytest.mark.asyncio
async def test_generate_success(mock_config, mock_command_result):
    """Test successful command generation."""
    generator = CommandGenerator(config=mock_config)
    
    with patch("shakka.providers.openai.OpenAIProvider") as MockProvider:
        mock_provider = AsyncMock()
        mock_provider.generate.return_value = mock_command_result
        MockProvider.return_value = mock_provider
        
        result = await generator.generate("scan ports on 10.0.0.1")
        
        assert isinstance(result, CommandResult)
        assert "nmap" in result.command


@pytest.mark.asyncio
async def test_generate_empty_prompt(mock_config):
    """Test error with empty prompt."""
    generator = CommandGenerator(config=mock_config)
    
    with pytest.raises(ValueError, match="Prompt cannot be empty"):
        await generator.generate("")


@pytest.mark.asyncio
async def test_generate_with_provider_override(mock_config, mock_command_result):
    """Test generating with provider override."""
    generator = CommandGenerator(config=mock_config)
    
    with patch("shakka.providers.openai.OpenAIProvider") as MockProvider:
        mock_provider = AsyncMock()
        mock_provider.generate.return_value = mock_command_result
        MockProvider.return_value = mock_provider
        
        result = await generator.generate("test", provider="openai")
        assert isinstance(result, CommandResult)


@pytest.mark.asyncio
async def test_generate_with_context(mock_config, mock_command_result):
    """Test generating with context."""
    generator = CommandGenerator(config=mock_config)
    context = {"history": ["previous command"]}
    
    with patch("shakka.providers.openai.OpenAIProvider") as MockProvider:
        mock_provider = AsyncMock()
        mock_provider.generate.return_value = mock_command_result
        MockProvider.return_value = mock_provider
        
        result = await generator.generate("test", context=context)
        assert isinstance(result, CommandResult)


@pytest.mark.asyncio
async def test_validate_provider_success(mock_config):
    """Test successful provider validation."""
    generator = CommandGenerator(config=mock_config)
    
    with patch("shakka.providers.openai.OpenAIProvider") as MockProvider:
        mock_provider = AsyncMock()
        mock_provider.validate_connection.return_value = True
        MockProvider.return_value = mock_provider
        
        is_valid = await generator.validate_provider()
        assert is_valid is True


@pytest.mark.asyncio
async def test_validate_provider_failure(mock_config):
    """Test provider validation failure."""
    generator = CommandGenerator(config=mock_config)
    
    with patch("shakka.providers.openai.OpenAIProvider") as MockProvider:
        mock_provider = AsyncMock()
        mock_provider.validate_connection.return_value = False
        MockProvider.return_value = mock_provider
        
        is_valid = await generator.validate_provider()
        assert is_valid is False


def test_list_providers():
    """Test listing available providers."""
    generator = CommandGenerator()
    providers = generator.list_providers()
    
    assert "openai" in providers
    assert "anthropic" in providers
    assert "ollama" in providers


def test_get_provider_status(mock_config):
    """Test getting provider configuration status."""
    generator = CommandGenerator(config=mock_config)
    status = generator.get_provider_status()
    
    assert status["openai"] is True
    assert status["anthropic"] is True
    assert status["ollama"] is True


def test_get_provider_status_no_keys():
    """Test provider status with no API keys."""
    config = ShakkaConfig()  # No API keys
    generator = CommandGenerator(config=config)
    status = generator.get_provider_status()
    
    assert status["openai"] is False
    assert status["anthropic"] is False
    assert status["ollama"] is True  # Doesn't need API key


def test_get_provider_reuses_cached_instance(mock_config):
    """Ensure provider instances are reused until switched."""
    generator = CommandGenerator(config=mock_config)

    with patch("shakka.providers.openai.OpenAIProvider") as MockProvider:
        mock_provider = MagicMock()
        MockProvider.return_value = mock_provider

        first = generator._get_provider()
        second = generator._get_provider()

        assert first is second
        MockProvider.assert_called_once_with(api_key="sk-test-openai")


def test_set_provider_switches_and_clears_cache(mock_config):
    """Switch provider without recreating generator instance."""
    generator = CommandGenerator(config=mock_config)
    generator._provider = MagicMock()
    generator._provider_name = "openai"

    generator.set_provider("anthropic")

    assert generator.config.default_provider == "anthropic"
    assert generator._provider is None
    assert generator._provider_name is None


def test_set_provider_switches_instance(mock_config):
    """Switching provider recreates correct provider on next use."""
    generator = CommandGenerator(config=mock_config)

    with patch("shakka.providers.openai.OpenAIProvider") as MockOpenAI, patch(
        "shakka.providers.anthropic.AnthropicProvider"
    ) as MockAnthropic:
        openai_provider = MagicMock()
        anthropic_provider = MagicMock()
        MockOpenAI.return_value = openai_provider
        MockAnthropic.return_value = anthropic_provider

        first = generator._get_provider()
        generator.set_provider("anthropic")
        second = generator._get_provider()

        assert first is openai_provider
        assert second is anthropic_provider


def test_set_provider_requires_configuration():
    """Prevent switching to providers without credentials configured."""
    config = ShakkaConfig(openai_api_key="sk-test", default_provider="openai")
    generator = CommandGenerator(config=config)

    with pytest.raises(ValueError, match="not configured"):
        generator.set_provider("anthropic")
