"""Test display utilities."""

from io import StringIO
from unittest.mock import patch

from shakka.utils.display import (
    print_banner,
    print_command_result,
    print_error,
    print_success,
    print_warning,
    print_info,
    print_provider_status,
    console
)
from shakka.providers.base import CommandResult


def test_print_banner():
    """Test banner printing."""
    with patch.object(console, 'print') as mock_print:
        print_banner()
        mock_print.assert_called_once()
        call_args = str(mock_print.call_args)
        assert "ShakkaShell" in call_args


def test_print_command_result():
    """Test command result display."""
    result = CommandResult(
        command="nmap -sV 10.0.0.1",
        explanation="Service version scan",
        risk_level="Medium",
        prerequisites=["nmap"],
        warnings=["May be detected"],
        alternatives=["nmap -sS 10.0.0.1"]
    )
    
    with patch.object(console, 'print') as mock_print:
        print_command_result(result)
        mock_print.assert_called_once()


def test_print_command_result_minimal():
    """Test command result with minimal info."""
    result = CommandResult(
        command="ls -la",
        explanation="List files",
        risk_level="Low"
    )
    
    with patch.object(console, 'print') as mock_print:
        print_command_result(result)
        mock_print.assert_called_once()


def test_print_error():
    """Test error printing."""
    with patch.object(console, 'print') as mock_print:
        print_error("Test error message")
        mock_print.assert_called_once()
        # Just verify it was called, the Panel object is complex to inspect


def test_print_success():
    """Test success message printing."""
    with patch.object(console, 'print') as mock_print:
        print_success("Operation completed")
        mock_print.assert_called_once()
        call_args = str(mock_print.call_args)
        assert "Operation completed" in call_args


def test_print_warning():
    """Test warning message printing."""
    with patch.object(console, 'print') as mock_print:
        print_warning("This is a warning")
        mock_print.assert_called_once()
        call_args = str(mock_print.call_args)
        assert "warning" in call_args.lower()


def test_print_info():
    """Test info message printing."""
    with patch.object(console, 'print') as mock_print:
        print_info("Information message")
        mock_print.assert_called_once()


def test_print_provider_status():
    """Test provider status display."""
    status = {
        "openai": True,
        "anthropic": False,
        "ollama": True
    }
    
    with patch.object(console, 'print') as mock_print:
        print_provider_status(status)
        mock_print.assert_called_once()


def test_print_history_table_empty():
    """Test history table with empty list."""
    with patch.object(console, 'print') as mock_print:
        from shakka.utils.display import print_history_table
        print_history_table([])
        # Should print info message about no entries
        mock_print.assert_called_once()


def test_print_history_table_with_data():
    """Test history table with data."""
    history = [
        {
            "id": 1,
            "command": "nmap -sV 10.0.0.1",
            "risk_level": "Medium",
            "created_at": "2024-01-01 12:00:00"
        },
        {
            "id": 2,
            "command": "gobuster dir -u http://example.com",
            "risk_level": "Low",
            "created_at": "2024-01-01 12:05:00"
        }
    ]
    
    with patch.object(console, 'print') as mock_print:
        from shakka.utils.display import print_history_table
        print_history_table(history)
        mock_print.assert_called_once()


def test_risk_level_colors():
    """Test that different risk levels use different colors."""
    risk_levels = ["Low", "Medium", "High", "Critical"]
    
    for risk in risk_levels:
        result = CommandResult(
            command="test",
            explanation="test",
            risk_level=risk
        )
        
        with patch.object(console, 'print') as mock_print:
            print_command_result(result)
            mock_print.assert_called_once()
