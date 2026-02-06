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


# Tests for Extended Thinking Support

class TestExtendedThinking:
    """Tests for Claude extended thinking support."""
    
    def test_model_supports_extended_thinking(self):
        """Test extended thinking model detection."""
        from shakka.providers.anthropic import model_supports_extended_thinking
        
        # Models that support extended thinking
        assert model_supports_extended_thinking("claude-3-5-sonnet-20241022") is True
        assert model_supports_extended_thinking("claude-3-5-sonnet") is True
        assert model_supports_extended_thinking("claude-sonnet-4-20250514") is True
        assert model_supports_extended_thinking("claude-4") is True
        
        # Models that don't support extended thinking
        assert model_supports_extended_thinking("claude-3-sonnet-20240229") is False
        assert model_supports_extended_thinking("claude-3-opus") is False
        assert model_supports_extended_thinking("gpt-4") is False
    
    def test_provider_init_with_extended_thinking(self):
        """Test provider initialization with extended thinking options."""
        provider = AnthropicProvider(
            api_key="test-key",
            model="claude-3-5-sonnet-20241022",
            enable_extended_thinking=True,
            thinking_budget=5000,
        )
        
        assert provider.enable_extended_thinking is True
        assert provider.thinking_budget == 5000
    
    def test_provider_init_default_thinking_disabled(self):
        """Test extended thinking is disabled by default."""
        provider = AnthropicProvider(api_key="test-key")
        
        assert provider.enable_extended_thinking is False
        assert provider.thinking_budget == 10000  # Default
    
    def test_last_thinking_content_initially_none(self):
        """Test last_thinking_content starts as None."""
        provider = AnthropicProvider(api_key="test-key")
        assert provider.last_thinking_content is None
    
    @pytest.mark.asyncio
    async def test_extended_thinking_uses_temperature_1(self):
        """Test that extended thinking uses temperature=1."""
        mock_response = MagicMock()
        mock_response.choices = [MagicMock()]
        mock_response.choices[0].message.content = json.dumps({
            "command": "nmap -sV 10.0.0.1",
            "explanation": "Scan",
            "risk_level": "Medium",
        })
        mock_response.choices[0].message.thinking = None
        mock_response.choices[0].message.reasoning_content = None
        
        provider = AnthropicProvider(
            api_key="test-key",
            model="claude-3-5-sonnet-20241022",
            enable_extended_thinking=True,
        )
        
        with patch("shakka.providers.anthropic.acompletion", return_value=mock_response) as mock_call:
            await provider.generate("scan ports")
            
            call_args = mock_call.call_args
            assert call_args[1]["temperature"] == 1.0
    
    @pytest.mark.asyncio
    async def test_extended_thinking_passes_thinking_param(self):
        """Test that thinking parameter is passed to API."""
        mock_response = MagicMock()
        mock_response.choices = [MagicMock()]
        mock_response.choices[0].message.content = json.dumps({
            "command": "nmap -sV 10.0.0.1",
            "explanation": "Scan",
            "risk_level": "Medium",
        })
        mock_response.choices[0].message.thinking = None
        mock_response.choices[0].message.reasoning_content = None
        
        provider = AnthropicProvider(
            api_key="test-key",
            model="claude-3-5-sonnet-20241022",
            enable_extended_thinking=True,
            thinking_budget=8000,
        )
        
        with patch("shakka.providers.anthropic.acompletion", return_value=mock_response) as mock_call:
            await provider.generate("scan ports")
            
            call_args = mock_call.call_args
            assert call_args[1]["thinking"] == {
                "type": "enabled",
                "budget_tokens": 8000,
            }
    
    @pytest.mark.asyncio
    async def test_extended_thinking_unsupported_model_ignored(self):
        """Test that extended thinking is ignored for unsupported models."""
        mock_response = MagicMock()
        mock_response.choices = [MagicMock()]
        mock_response.choices[0].message.content = json.dumps({
            "command": "nmap -sV 10.0.0.1",
            "explanation": "Scan",
            "risk_level": "Medium",
        })
        mock_response.choices[0].message.thinking = None
        mock_response.choices[0].message.reasoning_content = None
        
        # Using older model that doesn't support extended thinking
        provider = AnthropicProvider(
            api_key="test-key",
            model="claude-3-sonnet-20240229",
            enable_extended_thinking=True,  # Enabled but model doesn't support
        )
        
        with patch("shakka.providers.anthropic.acompletion", return_value=mock_response) as mock_call:
            await provider.generate("scan ports")
            
            call_args = mock_call.call_args
            # Should use normal temperature, not extended thinking
            assert call_args[1]["temperature"] == 0.1
            assert "thinking" not in call_args[1]
    
    @pytest.mark.asyncio
    async def test_thinking_content_captured(self):
        """Test that thinking content is captured from response."""
        mock_response = MagicMock()
        mock_response.choices = [MagicMock()]
        mock_response.choices[0].message.content = json.dumps({
            "command": "nmap -sV 10.0.0.1",
            "explanation": "Scan",
            "risk_level": "Medium",
        })
        mock_response.choices[0].message.thinking = "Let me think about this..."
        mock_response.choices[0].message.reasoning_content = None
        
        provider = AnthropicProvider(
            api_key="test-key",
            model="claude-3-5-sonnet-20241022",
            enable_extended_thinking=True,
        )
        
        with patch("shakka.providers.anthropic.acompletion", return_value=mock_response):
            result = await provider.generate("scan ports")
            
            assert result.thinking == "Let me think about this..."
            assert provider.last_thinking_content == "Let me think about this..."
    
    @pytest.mark.asyncio
    async def test_reasoning_content_captured(self):
        """Test that reasoning_content is captured as thinking."""
        mock_response = MagicMock()
        mock_response.choices = [MagicMock()]
        mock_response.choices[0].message.content = json.dumps({
            "command": "nmap -sV 10.0.0.1",
            "explanation": "Scan",
            "risk_level": "Medium",
        })
        mock_response.choices[0].message.thinking = None
        mock_response.choices[0].message.reasoning_content = "Analyzing the target..."
        
        provider = AnthropicProvider(
            api_key="test-key",
            model="claude-3-5-sonnet-20241022",
            enable_extended_thinking=True,
        )
        
        with patch("shakka.providers.anthropic.acompletion", return_value=mock_response):
            result = await provider.generate("scan ports")
            
            assert result.thinking == "Analyzing the target..."
