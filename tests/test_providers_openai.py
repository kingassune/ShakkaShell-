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


# Tests for O1 Reasoning Model Support

class TestO1ReasoningModels:
    """Tests for O1 reasoning model support."""
    
    def test_is_o1_model_positive(self):
        """Test O1 model detection for known models."""
        from shakka.providers.openai import is_o1_model
        
        assert is_o1_model("o1") is True
        assert is_o1_model("o1-mini") is True
        assert is_o1_model("o1-preview") is True
        assert is_o1_model("o1-2024-12-17") is True
    
    def test_is_o1_model_negative(self):
        """Test O1 model detection for non-O1 models."""
        from shakka.providers.openai import is_o1_model
        
        assert is_o1_model("gpt-4") is False
        assert is_o1_model("gpt-3.5-turbo") is False
        assert is_o1_model("claude-3-opus") is False
    
    def test_provider_is_reasoning_model_property(self):
        """Test is_reasoning_model property."""
        o1_provider = OpenAIProvider(model="o1")
        gpt_provider = OpenAIProvider(model="gpt-4")
        
        assert o1_provider.is_reasoning_model is True
        assert gpt_provider.is_reasoning_model is False
    
    def test_reasoning_effort_default(self):
        """Test default reasoning effort."""
        provider = OpenAIProvider(model="o1")
        assert provider.reasoning_effort == "medium"
    
    def test_reasoning_effort_custom(self):
        """Test custom reasoning effort."""
        provider = OpenAIProvider(model="o1", reasoning_effort="high")
        assert provider.reasoning_effort == "high"
    
    @pytest.mark.asyncio
    async def test_o1_model_no_system_message(self):
        """Test that O1 models combine system prompt into user message."""
        mock_response = MagicMock()
        mock_response.choices = [MagicMock()]
        mock_response.choices[0].message.content = json.dumps({
            "command": "nmap -sV 10.0.0.1",
            "explanation": "Scan",
            "risk_level": "Medium",
        })
        mock_response.choices[0].message.reasoning_content = None
        mock_response.usage = None
        
        provider = OpenAIProvider(api_key="test-key", model="o1")
        
        with patch("shakka.providers.openai.acompletion", return_value=mock_response) as mock_call:
            await provider.generate("scan ports")
            
            call_args = mock_call.call_args
            messages = call_args[1]["messages"]
            
            # O1 should have only user message with system prompt embedded
            assert len(messages) == 1
            assert messages[0]["role"] == "user"
            assert "ShakkaShell" in messages[0]["content"]
    
    @pytest.mark.asyncio
    async def test_o1_model_reasoning_effort_passed(self):
        """Test that reasoning effort is passed to API."""
        mock_response = MagicMock()
        mock_response.choices = [MagicMock()]
        mock_response.choices[0].message.content = json.dumps({
            "command": "nmap -sV 10.0.0.1",
            "explanation": "Scan",
            "risk_level": "Medium",
        })
        mock_response.choices[0].message.reasoning_content = None
        mock_response.usage = None
        
        provider = OpenAIProvider(api_key="test-key", model="o1", reasoning_effort="high")
        
        with patch("shakka.providers.openai.acompletion", return_value=mock_response) as mock_call:
            await provider.generate("scan ports")
            
            call_args = mock_call.call_args
            
            # Should pass reasoning_effort
            assert call_args[1]["reasoning_effort"] == "high"
            # Should not pass temperature or response_format
            assert "temperature" not in call_args[1]
    
    @pytest.mark.asyncio
    async def test_o1_model_reasoning_tokens_tracked(self):
        """Test that reasoning tokens are tracked."""
        mock_response = MagicMock()
        mock_response.choices = [MagicMock()]
        mock_response.choices[0].message.content = json.dumps({
            "command": "nmap -sV 10.0.0.1",
            "explanation": "Scan",
            "risk_level": "Medium",
        })
        mock_response.choices[0].message.reasoning_content = None
        
        # Mock usage with reasoning tokens
        mock_usage = MagicMock()
        mock_details = MagicMock()
        mock_details.reasoning_tokens = 500
        mock_usage.completion_tokens_details = mock_details
        mock_response.usage = mock_usage
        
        provider = OpenAIProvider(api_key="test-key", model="o1")
        
        with patch("shakka.providers.openai.acompletion", return_value=mock_response):
            result = await provider.generate("scan ports")
            
            assert result.reasoning_tokens == 500
    
    @pytest.mark.asyncio
    async def test_o1_model_reasoning_content_captured(self):
        """Test that reasoning content is captured when available."""
        mock_response = MagicMock()
        mock_response.choices = [MagicMock()]
        mock_response.choices[0].message.content = json.dumps({
            "command": "nmap -sV 10.0.0.1",
            "explanation": "Scan",
            "risk_level": "Medium",
        })
        mock_response.choices[0].message.reasoning_content = "Thinking about the best scan approach..."
        mock_response.usage = None
        
        provider = OpenAIProvider(api_key="test-key", model="o1")
        
        with patch("shakka.providers.openai.acompletion", return_value=mock_response):
            result = await provider.generate("scan ports")
            
            assert result.thinking == "Thinking about the best scan approach..."
            assert provider.last_reasoning_content == "Thinking about the best scan approach..."
    
    @pytest.mark.asyncio
    async def test_o1_model_json_in_markdown(self):
        """Test O1 model response with JSON wrapped in markdown."""
        mock_response = MagicMock()
        mock_response.choices = [MagicMock()]
        mock_response.choices[0].message.content = """```json
{
    "command": "nmap -sV 10.0.0.1",
    "explanation": "Scan ports",
    "risk_level": "Medium"
}
```"""
        mock_response.choices[0].message.reasoning_content = None
        mock_response.usage = None
        
        provider = OpenAIProvider(api_key="test-key", model="o1")
        
        with patch("shakka.providers.openai.acompletion", return_value=mock_response):
            result = await provider.generate("scan ports")
            
            assert result.command == "nmap -sV 10.0.0.1"
