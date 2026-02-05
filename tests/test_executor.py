"""Test command executor."""

import pytest

from shakka.core.executor import CommandExecutor, ExecutionResult


@pytest.fixture
def executor():
    """Create a command executor instance."""
    return CommandExecutor()


@pytest.fixture
def dry_run_executor():
    """Create a dry-run executor."""
    return CommandExecutor(dry_run=True)


def test_executor_initialization():
    """Test executor initialization."""
    executor = CommandExecutor()
    assert executor.default_timeout == 300
    assert executor.dry_run is False


def test_executor_dry_run_initialization():
    """Test dry-run executor initialization."""
    executor = CommandExecutor(dry_run=True)
    assert executor.dry_run is True


@pytest.mark.asyncio
async def test_execute_simple_command(executor):
    """Test executing a simple command."""
    result = await executor.execute("echo 'hello world'", timeout=5)
    
    assert isinstance(result, ExecutionResult)
    assert result.success is True
    assert result.return_code == 0
    assert "hello world" in result.stdout


@pytest.mark.asyncio
async def test_execute_failing_command(executor):
    """Test executing a command that fails."""
    result = await executor.execute("false", timeout=5)
    
    assert result.success is False
    assert result.return_code != 0


@pytest.mark.asyncio
async def test_execute_with_timeout(executor):
    """Test command timeout."""
    result = await executor.execute("sleep 10", timeout=1)
    
    assert result.success is False
    assert "timed out" in result.stderr.lower() or "timeout" in result.error_message.lower()


@pytest.mark.asyncio
async def test_execute_dry_run(dry_run_executor):
    """Test dry-run mode."""
    result = await dry_run_executor.execute("echo 'test'")
    
    assert result.success is True
    assert "[DRY RUN]" in result.stdout


def test_execute_sync_simple_command(executor):
    """Test synchronous execution of simple command."""
    result = executor.execute_sync("echo 'test'", timeout=5)
    
    assert isinstance(result, ExecutionResult)
    assert result.success is True
    assert result.return_code == 0
    assert "test" in result.stdout


def test_execute_sync_failing_command(executor):
    """Test synchronous execution of failing command."""
    result = executor.execute_sync("false", timeout=5)
    
    assert result.success is False
    assert result.return_code != 0


def test_execute_sync_with_timeout(executor):
    """Test synchronous execution with timeout."""
    result = executor.execute_sync("sleep 10", timeout=1)
    
    assert result.success is False
    assert "timed out" in result.stderr.lower() or "timeout" in result.error_message.lower()


def test_execute_sync_dry_run(dry_run_executor):
    """Test synchronous dry-run mode."""
    result = dry_run_executor.execute_sync("echo 'test'")
    
    assert result.success is True
    assert "[DRY RUN]" in result.stdout


def test_execution_result_str():
    """Test ExecutionResult string representation."""
    result = ExecutionResult(
        success=True,
        return_code=0,
        execution_time=1.5
    )
    
    str_repr = str(result)
    assert "Success" in str_repr
    assert "1.50" in str_repr


def test_execution_result_attributes():
    """Test ExecutionResult attributes."""
    result = ExecutionResult(
        success=False,
        return_code=1,
        stdout="output",
        stderr="error",
        execution_time=2.5,
        error_message="Failed"
    )
    
    assert result.success is False
    assert result.return_code == 1
    assert result.stdout == "output"
    assert result.stderr == "error"
    assert result.execution_time == 2.5
    assert result.error_message == "Failed"


@pytest.mark.asyncio
async def test_execute_capture_output_disabled(executor):
    """Test execution without output capture."""
    result = await executor.execute("echo 'test'", timeout=5, capture_output=False)
    
    # Should still succeed but no output captured
    assert result.success is True


def test_custom_timeout(executor):
    """Test executor with custom default timeout."""
    custom_executor = CommandExecutor(default_timeout=60)
    assert custom_executor.default_timeout == 60


@pytest.mark.asyncio
async def test_execute_with_stderr(executor):
    """Test command that outputs to stderr."""
    result = await executor.execute("echo 'error' >&2", timeout=5)
    
    # Command should succeed even with stderr output
    assert result.success is True
    assert "error" in result.stderr
