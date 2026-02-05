"""Test storage models and database operations."""

import tempfile
from pathlib import Path
import pytest

from shakka.config import ShakkaConfig
from shakka.storage.database import init_database, get_db_session, close_database
from shakka.storage.models import CommandHistory
from shakka.storage.history import (
    add_to_history,
    get_history,
    get_history_by_id,
    clear_history,
    mark_as_executed,
    get_history_count,
    search_history
)
from shakka.providers.base import CommandResult


@pytest.fixture
def temp_db():
    """Create a temporary database for testing."""
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = Path(tmpdir) / "test.db"
        config = ShakkaConfig(db_path=db_path)
        init_database(config)
        yield config
        close_database()


@pytest.fixture
def mock_result():
    """Mock command result."""
    return CommandResult(
        command="nmap -sV 10.0.0.1",
        explanation="Service version scan",
        risk_level="Medium",
        prerequisites=["nmap"]
    )


def test_database_initialization(temp_db):
    """Test database initialization."""
    session = get_db_session(temp_db)
    assert session is not None
    session.close()


def test_add_to_history(temp_db, mock_result):
    """Test adding entry to history."""
    entry = add_to_history(
        user_input="scan ports on 10.0.0.1",
        result=mock_result,
        provider="openai"
    )
    
    assert entry.id is not None
    assert entry.user_input == "scan ports on 10.0.0.1"
    assert entry.generated_command == "nmap -sV 10.0.0.1"
    assert entry.risk_level == "Medium"
    assert entry.provider == "openai"
    assert entry.executed is False


def test_get_history(temp_db, mock_result):
    """Test retrieving history."""
    # Add some entries
    add_to_history("test 1", mock_result, "openai")
    add_to_history("test 2", mock_result, "anthropic")
    
    history = get_history(limit=10)
    assert len(history) == 2
    assert history[0].user_input == "test 2"  # Most recent first


def test_get_history_with_limit(temp_db, mock_result):
    """Test history retrieval with limit."""
    # Add multiple entries
    for i in range(5):
        add_to_history(f"test {i}", mock_result, "openai")
    
    history = get_history(limit=3)
    assert len(history) == 3


def test_get_history_by_id(temp_db, mock_result):
    """Test getting specific history entry."""
    entry = add_to_history("test", mock_result, "openai")
    
    retrieved = get_history_by_id(entry.id)
    assert retrieved is not None
    assert retrieved.id == entry.id
    assert retrieved.user_input == "test"


def test_get_history_by_id_not_found(temp_db):
    """Test getting non-existent entry."""
    retrieved = get_history_by_id(999)
    assert retrieved is None


def test_clear_history(temp_db, mock_result):
    """Test clearing all history."""
    # Add some entries
    add_to_history("test 1", mock_result, "openai")
    add_to_history("test 2", mock_result, "openai")
    
    count = clear_history()
    assert count == 2
    
    history = get_history()
    assert len(history) == 0


def test_mark_as_executed(temp_db, mock_result):
    """Test marking entry as executed."""
    entry = add_to_history("test", mock_result, "openai")
    assert entry.executed is False
    
    updated = mark_as_executed(entry.id)
    assert updated is not None
    assert updated.executed is True


def test_get_history_count(temp_db, mock_result):
    """Test getting history count."""
    assert get_history_count() == 0
    
    add_to_history("test 1", mock_result, "openai")
    add_to_history("test 2", mock_result, "openai")
    
    assert get_history_count() == 2


def test_search_history(temp_db, mock_result):
    """Test searching history."""
    add_to_history("scan ports on 10.0.0.1", mock_result, "openai")
    add_to_history("find subdomains", mock_result, "openai")
    add_to_history("brute force ssh", mock_result, "openai")
    
    results = search_history("scan")
    assert len(results) == 1
    assert "scan" in results[0].user_input.lower()


def test_search_history_by_command(temp_db):
    """Test searching by command."""
    result1 = CommandResult(
        command="nmap -sV 10.0.0.1",
        explanation="test",
        risk_level="Low"
    )
    result2 = CommandResult(
        command="gobuster dir -u http://example.com",
        explanation="test",
        risk_level="Low"
    )
    
    add_to_history("test 1", result1, "openai")
    add_to_history("test 2", result2, "openai")
    
    results = search_history("nmap")
    assert len(results) == 1
    assert "nmap" in results[0].generated_command


def test_command_history_to_dict(temp_db, mock_result):
    """Test converting history entry to dict."""
    entry = add_to_history("test", mock_result, "openai")
    
    data = entry.to_dict()
    assert isinstance(data, dict)
    assert data["id"] == entry.id
    assert data["user_input"] == "test"
    assert data["command"] == mock_result.command
    assert data["risk_level"] == "Medium"
