"""Test base LLM provider classes."""

import pytest
from pydantic import ValidationError

from shakka.providers.base import CommandResult, LLMProvider


def test_command_result_creation():
    """Test creating a valid CommandResult."""
    result = CommandResult(
        command="nmap -sV 10.0.0.1",
        explanation="Scan ports on target host",
        risk_level="Medium",
        prerequisites=["nmap"],
        alternatives=["nmap -sS 10.0.0.1"],
        warnings=["This will be detected by IDS"]
    )
    
    assert result.command == "nmap -sV 10.0.0.1"
    assert result.explanation == "Scan ports on target host"
    assert result.risk_level == "Medium"
    assert "nmap" in result.prerequisites
    assert len(result.alternatives) == 1
    assert len(result.warnings) == 1


def test_command_result_validation():
    """Test CommandResult validation."""
    # Test valid risk levels
    for risk in ["Low", "Medium", "High", "Critical"]:
        result = CommandResult(
            command="test",
            explanation="test explanation",
            risk_level=risk
        )
        assert result.risk_level == risk
    
    # Test invalid risk level
    with pytest.raises(ValidationError):
        CommandResult(
            command="test",
            explanation="test",
            risk_level="Invalid"
        )


def test_command_result_defaults():
    """Test CommandResult default values."""
    result = CommandResult(
        command="nmap 10.0.0.1",
        explanation="Basic port scan",
        risk_level="Low"
    )
    
    assert result.prerequisites == []
    assert result.alternatives == []
    assert result.warnings == []


def test_command_result_str():
    """Test CommandResult string representation."""
    result = CommandResult(
        command="nmap 10.0.0.1",
        explanation="Port scan",
        risk_level="Low"
    )
    
    str_repr = str(result)
    assert "nmap 10.0.0.1" in str_repr
    assert "Low" in str_repr


def test_llm_provider_is_abstract():
    """Test that LLMProvider cannot be instantiated directly."""
    with pytest.raises(TypeError):
        LLMProvider()


def test_llm_provider_system_prompt():
    """Test that system prompt is accessible."""
    
    class TestProvider(LLMProvider):
        async def generate(self, prompt: str, context=None):
            return CommandResult(
                command="test",
                explanation="test",
                risk_level="Low"
            )
        
        async def validate_connection(self):
            return True
    
    provider = TestProvider()
    system_prompt = provider.get_system_prompt()
    
    assert "ShakkaShell" in system_prompt
    assert "JSON" in system_prompt
    assert "risk_level" in system_prompt


@pytest.mark.asyncio
async def test_provider_implementation():
    """Test that a concrete provider implementation works."""
    
    class MockProvider(LLMProvider):
        async def generate(self, prompt: str, context=None):
            return CommandResult(
                command="nmap -sV 10.0.0.1",
                explanation="Service version detection scan",
                risk_level="Medium",
                prerequisites=["nmap"]
            )
        
        async def validate_connection(self):
            return True
    
    provider = MockProvider(api_key="test-key")
    assert provider.api_key == "test-key"
    
    result = await provider.generate("scan ports on 10.0.0.1")
    assert isinstance(result, CommandResult)
    assert "nmap" in result.command
    assert result.risk_level == "Medium"
    
    is_valid = await provider.validate_connection()
    assert is_valid is True


def test_command_result_empty_string_validation():
    """Test that empty strings are not allowed."""
    with pytest.raises(ValidationError):
        CommandResult(
            command="",
            explanation="test",
            risk_level="Low"
        )
    
    with pytest.raises(ValidationError):
        CommandResult(
            command="test",
            explanation="",
            risk_level="Low"
        )
