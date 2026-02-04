"""Test OpenAI provider implementation."""

import json
import pytest
from unittest.mock import AsyncMock, patch, MagicMock

from shakka.providers.openai import OpenAIProvider
from shakka.providers.base import CommandResult


@pytest.fixture
def mock_openai_response():
    """Mock OpenAI API response."""
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


def test_openai_provider_init():
    """Test OpenAI provider initialization."""
    provider = OpenAIProvider(api_key="test-key", model="gpt-4")
    
    assert provider.api_key == "test-key"
    assert provider.model == "gpt-4"
    assert provider.temperature == 0.1


def test_openai_provider_defaults():
    """Test default values."""
    provider = OpenAIProvider()
    
    assert provider.model == "gpt-3.5-turbo"
    assert provider.temperature == 0.1


@pytest.mark.asyncio
async def test_generate_with_valid_prompt(mock_openai_response):
    """Test generating command with valid prompt."""
    provider = OpenAIProvider(api_key="test-key")
    
    with patch("shakka.providers.openai.acompletion", return_value=mock_openai_response):
        result = await provider.generate("scan ports on 10.0.0.1")
        
        assert isinstance(result, CommandResult)
        assert "nmap" in result.command
        assert result.risk_level == "Medium"
        assert "nmap" in result.prerequisites


@pytest.mark.asyncio
async def test_generate_with_empty_prompt():
    """Test that empty prompt raises ValueError."""
    provider = OpenAIProvider(api_key="test-key")
    
    with pytest.raises(ValueError, match="Prompt cannot be empty"):
        await provider.generate("")
    
    with pytest.raises(ValueError, match="Prompt cannot be empty"):
        await provider.generate("   ")


@pytest.mark.asyncio
async def test_generate_with_context(mock_openai_response):
    """Test generating command with context."""
    provider = OpenAIProvider(api_key="test-key")
    context = {"history": ["previous command"]}
    
    with patch("shakka.providers.openai.acompletion", return_value=mock_openai_response) as mock_call:
        result = await provider.generate("scan target", context=context)
        
        assert isinstance(result, CommandResult)
        # Verify context was passed
        call_args = mock_call.call_args
        assert "Context:" in call_args[1]["messages"][-1]["content"]


@pytest.mark.asyncio
async def test_generate_api_failure():
    """Test handling of API failures."""
    provider = OpenAIProvider(api_key="test-key")
    
    with patch("shakka.providers.openai.acompletion", side_effect=Exception("API Error")):
        with pytest.raises(RuntimeError, match="OpenAI API call failed"):
            await provider.generate("test prompt")


@pytest.mark.asyncio
async def test_generate_invalid_json():
    """Test handling of invalid JSON response."""
    provider = OpenAIProvider(api_key="test-key")
    
    mock_response = MagicMock()
    mock_response.choices = [MagicMock()]
    mock_response.choices[0].message.content = "not valid json"
    
    with patch("shakka.providers.openai.acompletion", return_value=mock_response):
        with pytest.raises(RuntimeError, match="Failed to parse LLM response"):
            await provider.generate("test prompt")


@pytest.mark.asyncio
async def test_validate_connection_success():
    """Test successful connection validation."""
    provider = OpenAIProvider(api_key="test-key")
    
    mock_response = MagicMock()
    with patch("shakka.providers.openai.acompletion", return_value=mock_response):
        is_valid = await provider.validate_connection()
        assert is_valid is True


@pytest.mark.asyncio
async def test_validate_connection_failure():
    """Test failed connection validation."""
    provider = OpenAIProvider(api_key="invalid-key")
    
    with patch("shakka.providers.openai.acompletion", side_effect=Exception("Auth failed")):
        is_valid = await provider.validate_connection()
        assert is_valid is False


@pytest.mark.asyncio
async def test_system_prompt_included(mock_openai_response):
    """Test that system prompt is included in API call."""
    provider = OpenAIProvider(api_key="test-key")
    
    with patch("shakka.providers.openai.acompletion", return_value=mock_openai_response) as mock_call:
        await provider.generate("test")
        
        call_args = mock_call.call_args
        messages = call_args[1]["messages"]
        
        # Should have system message first
        assert messages[0]["role"] == "system"
        assert "ShakkaShell" in messages[0]["content"]
