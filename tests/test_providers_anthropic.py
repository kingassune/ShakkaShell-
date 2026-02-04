"""Test Anthropic provider implementation."""

import json
import pytest
from unittest.mock import AsyncMock, patch, MagicMock

from shakka.providers.anthropic import AnthropicProvider
from shakka.providers.base import CommandResult


@pytest.fixture
def mock_anthropic_response():
    """Mock Anthropic API response."""
    mock_response = MagicMock()
    mock_response.choices = [MagicMock()]
    mock_response.choices[0].message.content = json.dumps({
        "command": "nmap -sV 10.0.0.1",
        "explanation": "Perform service version detection scan",
        "risk_level": "Medium",
        "prerequisites": ["nmap"],
        "alternatives": ["nmap -sS 10.0.0.1"],
        "warnings": ["May be detected by IDS"]
    })
    return mock_response


def test_anthropic_provider_init():
    """Test Anthropic provider initialization."""
    provider = AnthropicProvider(api_key="test-key", model="claude-3-opus-20240229")
    
    assert provider.api_key == "test-key"
    assert provider.model == "claude-3-opus-20240229"
    assert provider.temperature == 0.1


def test_anthropic_provider_defaults():
    """Test default values."""
    provider = AnthropicProvider()
    
    assert provider.model == "claude-3-sonnet-20240229"
    assert provider.temperature == 0.1


@pytest.mark.asyncio
async def test_generate_with_valid_prompt(mock_anthropic_response):
    """Test generating command with valid prompt."""
    provider = AnthropicProvider(api_key="test-key")
    
    with patch("shakka.providers.anthropic.acompletion", return_value=mock_anthropic_response):
        result = await provider.generate("scan ports on 10.0.0.1")
        
        assert isinstance(result, CommandResult)
        assert "nmap" in result.command
        assert result.risk_level == "Medium"


@pytest.mark.asyncio
async def test_generate_with_markdown_wrapped_json():
    """Test handling JSON wrapped in markdown code blocks."""
    provider = AnthropicProvider(api_key="test-key")
    
    mock_response = MagicMock()
    mock_response.choices = [MagicMock()]
    mock_response.choices[0].message.content = """```json
{
    "command": "nmap -sV 10.0.0.1",
    "explanation": "Service scan",
    "risk_level": "Medium",
    "prerequisites": ["nmap"],
    "alternatives": [],
    "warnings": []
}
```"""
    
    with patch("shakka.providers.anthropic.acompletion", return_value=mock_response):
        result = await provider.generate("test")
        assert "nmap" in result.command


@pytest.mark.asyncio
async def test_generate_with_empty_prompt():
    """Test that empty prompt raises ValueError."""
    provider = AnthropicProvider(api_key="test-key")
    
    with pytest.raises(ValueError, match="Prompt cannot be empty"):
        await provider.generate("")


@pytest.mark.asyncio
async def test_generate_with_context(mock_anthropic_response):
    """Test generating command with context."""
    provider = AnthropicProvider(api_key="test-key")
    context = {"history": ["previous command"]}
    
    with patch("shakka.providers.anthropic.acompletion", return_value=mock_anthropic_response) as mock_call:
        result = await provider.generate("scan target", context=context)
        
        assert isinstance(result, CommandResult)
        # Verify context was included
        call_args = mock_call.call_args
        assert "Context:" in call_args[1]["messages"][-1]["content"]


@pytest.mark.asyncio
async def test_generate_api_failure():
    """Test handling of API failures."""
    provider = AnthropicProvider(api_key="test-key")
    
    with patch("shakka.providers.anthropic.acompletion", side_effect=Exception("API Error")):
        with pytest.raises(RuntimeError, match="Anthropic API call failed"):
            await provider.generate("test prompt")


@pytest.mark.asyncio
async def test_generate_invalid_json():
    """Test handling of invalid JSON response."""
    provider = AnthropicProvider(api_key="test-key")
    
    mock_response = MagicMock()
    mock_response.choices = [MagicMock()]
    mock_response.choices[0].message.content = "not valid json"
    
    with patch("shakka.providers.anthropic.acompletion", return_value=mock_response):
        with pytest.raises(RuntimeError, match="Failed to parse LLM response"):
            await provider.generate("test prompt")


@pytest.mark.asyncio
async def test_validate_connection_success():
    """Test successful connection validation."""
    provider = AnthropicProvider(api_key="test-key")
    
    mock_response = MagicMock()
    with patch("shakka.providers.anthropic.acompletion", return_value=mock_response):
        is_valid = await provider.validate_connection()
        assert is_valid is True


@pytest.mark.asyncio
async def test_validate_connection_failure():
    """Test failed connection validation."""
    provider = AnthropicProvider(api_key="invalid-key")
    
    with patch("shakka.providers.anthropic.acompletion", side_effect=Exception("Auth failed")):
        is_valid = await provider.validate_connection()
        assert is_valid is False
