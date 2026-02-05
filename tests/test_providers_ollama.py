"""Test Ollama provider implementation."""

import json
import pytest
from unittest.mock import AsyncMock, patch, MagicMock

from shakka.providers.ollama import OllamaProvider
from shakka.providers.base import CommandResult


@pytest.fixture
def mock_ollama_response():
    """Mock Ollama API response."""
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


def test_ollama_provider_init():
    """Test Ollama provider initialization."""
    provider = OllamaProvider(base_url="http://localhost:11434", model="mistral")
    
    assert provider.base_url == "http://localhost:11434"
    assert provider.model == "ollama/mistral"
    assert provider.temperature == 0.1
    assert provider.api_key is None


def test_ollama_provider_defaults():
    """Test default values."""
    provider = OllamaProvider()
    
    assert provider.base_url == "http://localhost:11434"
    assert provider.model == "ollama/llama2"
    assert provider.temperature == 0.1


@pytest.mark.asyncio
async def test_generate_with_valid_prompt(mock_ollama_response):
    """Test generating command with valid prompt."""
    provider = OllamaProvider()
    
    with patch("shakka.providers.ollama.acompletion", return_value=mock_ollama_response):
        result = await provider.generate("scan ports on 10.0.0.1")
        
        assert isinstance(result, CommandResult)
        assert "nmap" in result.command
        assert result.risk_level == "Medium"


@pytest.mark.asyncio
async def test_generate_with_markdown_wrapped_json():
    """Test handling JSON wrapped in markdown code blocks."""
    provider = OllamaProvider()
    
    mock_response = MagicMock()
    mock_response.choices = [MagicMock()]
    mock_response.choices[0].message.content = """Here's the command:
```json
{
    "command": "nmap -sV 10.0.0.1",
    "explanation": "Service scan",
    "risk_level": "Medium",
    "prerequisites": ["nmap"],
    "alternatives": [],
    "warnings": []
}
```"""
    
    with patch("shakka.providers.ollama.acompletion", return_value=mock_response):
        result = await provider.generate("test")
        assert "nmap" in result.command


@pytest.mark.asyncio
async def test_generate_with_plain_json():
    """Test handling plain JSON with extra text."""
    provider = OllamaProvider()
    
    mock_response = MagicMock()
    mock_response.choices = [MagicMock()]
    mock_response.choices[0].message.content = """Sure, here's the command: {
    "command": "nmap -sV 10.0.0.1",
    "explanation": "Service scan",
    "risk_level": "Medium",
    "prerequisites": ["nmap"],
    "alternatives": [],
    "warnings": []
} Let me know if you need help!"""
    
    with patch("shakka.providers.ollama.acompletion", return_value=mock_response):
        result = await provider.generate("test")
        assert "nmap" in result.command


@pytest.mark.asyncio
async def test_generate_with_empty_prompt():
    """Test that empty prompt raises ValueError."""
    provider = OllamaProvider()
    
    with pytest.raises(ValueError, match="Prompt cannot be empty"):
        await provider.generate("")


@pytest.mark.asyncio
async def test_generate_with_context(mock_ollama_response):
    """Test generating command with context."""
    provider = OllamaProvider()
    context = {"history": ["previous command"]}
    
    with patch("shakka.providers.ollama.acompletion", return_value=mock_ollama_response) as mock_call:
        result = await provider.generate("scan target", context=context)
        
        assert isinstance(result, CommandResult)
        # Verify context was included
        call_args = mock_call.call_args
        assert "Context:" in call_args[1]["messages"][-1]["content"]


@pytest.mark.asyncio
async def test_generate_api_failure():
    """Test handling of API failures."""
    provider = OllamaProvider()
    
    with patch("shakka.providers.ollama.acompletion", side_effect=Exception("API Error")):
        with pytest.raises(RuntimeError, match="Ollama API call failed"):
            await provider.generate("test prompt")


@pytest.mark.asyncio
async def test_generate_invalid_json():
    """Test handling of invalid JSON response."""
    provider = OllamaProvider()
    
    mock_response = MagicMock()
    mock_response.choices = [MagicMock()]
    mock_response.choices[0].message.content = "not valid json at all"
    
    with patch("shakka.providers.ollama.acompletion", return_value=mock_response):
        with pytest.raises(RuntimeError, match="Failed to parse LLM response"):
            await provider.generate("test prompt")


@pytest.mark.asyncio
async def test_validate_connection_success():
    """Test successful connection validation."""
    provider = OllamaProvider()
    
    mock_response = MagicMock()
    with patch("shakka.providers.ollama.acompletion", return_value=mock_response):
        is_valid = await provider.validate_connection()
        assert is_valid is True


@pytest.mark.asyncio
async def test_validate_connection_failure():
    """Test failed connection validation."""
    provider = OllamaProvider()
    
    with patch("shakka.providers.ollama.acompletion", side_effect=Exception("Connection failed")):
        is_valid = await provider.validate_connection()
        assert is_valid is False


def test_ollama_model_prefix():
    """Test that model name gets ollama/ prefix."""
    provider = OllamaProvider(model="codellama")
    assert provider.model == "ollama/codellama"
