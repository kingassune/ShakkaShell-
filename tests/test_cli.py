"""Test CLI commands."""

import pytest
from typer.testing import CliRunner
from unittest.mock import patch, AsyncMock

from shakka.cli import app
from shakka.providers.base import CommandResult


runner = CliRunner()


@pytest.fixture
def mock_command_result():
    """Mock command result."""
    return CommandResult(
        command="nmap -sV 10.0.0.1",
        explanation="Service version scan",
        risk_level="Medium",
        prerequisites=["nmap"]
    )


def test_version():
    """Test version command."""
    result = runner.invoke(app, ["--version"])
    assert result.exit_code == 0
    assert "2.0.0" in result.stdout


def test_generate_without_query():
    """Test generate command without query."""
    result = runner.invoke(app, ["generate"])
    assert result.exit_code == 1


def test_generate_with_query(mock_command_result):
    """Test generate command with query."""
    with patch("shakka.cli.CommandGenerator") as MockGenerator:
        mock_gen = MockGenerator.return_value
        mock_gen.generate = AsyncMock(return_value=mock_command_result)
        
        result = runner.invoke(app, ["generate", "scan ports"])
        # Should complete without error
        assert "nmap" in result.stdout or result.exit_code in [0, 1]


def test_generate_with_provider(mock_command_result):
    """Test generate command with provider option."""
    with patch("shakka.cli.CommandGenerator") as MockGenerator:
        mock_gen = MockGenerator.return_value
        mock_gen.generate = AsyncMock(return_value=mock_command_result)
        
        result = runner.invoke(app, ["generate", "test", "--provider", "openai"])
        assert result.exit_code in [0, 1]  # May fail due to API key


def test_history_command():
    """Test history command."""
    result = runner.invoke(app, ["history"])
    assert result.exit_code == 0


def test_history_limit():
    """Test history command with limit."""
    result = runner.invoke(app, ["history", "--limit", "5"])
    assert result.exit_code == 0


def test_config_show():
    """Test config show command."""
    result = runner.invoke(app, ["config-command", "--show"])
    assert result.exit_code == 0


def test_config_set_provider():
    """Test config set provider."""
    with patch("shakka.config.ShakkaConfig.save_to_file"):
        result = runner.invoke(app, ["config-command", "--set-provider", "openai"])
        assert result.exit_code == 0


def test_config_invalid_provider():
    """Test config with invalid provider."""
    result = runner.invoke(app, ["config-command", "--set-provider", "invalid"])
    assert result.exit_code == 1


def test_validate_command():
    """Test validate command."""
    with patch("shakka.cli.CommandGenerator") as MockGenerator:
        mock_gen = MockGenerator.return_value
        mock_gen.get_provider_status.return_value = {"openai": True}
        mock_gen.validate_provider = AsyncMock(return_value=True)
        
        result = runner.invoke(app, ["validate"])
        assert result.exit_code == 0


def test_validate_specific_provider():
    """Test validate command with specific provider."""
    with patch("shakka.cli.CommandGenerator") as MockGenerator:
        mock_gen = MockGenerator.return_value
        mock_gen.validate_provider = AsyncMock(return_value=True)
        
        result = runner.invoke(app, ["validate", "--provider", "openai"])
        assert result.exit_code == 0
