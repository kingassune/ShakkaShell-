"""Command execution module for ShakkaShell.

Provides optional command execution with safety checks and output capture.
"""

import asyncio
import subprocess
from typing import Optional, Tuple
from datetime import datetime


class ExecutionResult:
    """Result from command execution.
    
    Attributes:
        success: Whether execution was successful
        return_code: Process return code
        stdout: Standard output
        stderr: Standard error
        execution_time: Time taken to execute (seconds)
        error_message: Error message if execution failed
    """
    
    def __init__(
        self,
        success: bool,
        return_code: int,
        stdout: str = "",
        stderr: str = "",
        execution_time: float = 0.0,
        error_message: str = ""
    ):
        self.success = success
        self.return_code = return_code
        self.stdout = stdout
        self.stderr = stderr
        self.execution_time = execution_time
        self.error_message = error_message
    
    def __str__(self) -> str:
        """String representation."""
        status = "Success" if self.success else "Failed"
        return f"ExecutionResult({status}, code={self.return_code}, time={self.execution_time:.2f}s)"


class CommandExecutor:
    """Executes security commands with safety checks.
    
    Provides controlled command execution with timeout, output capture,
    and safety validations.
    """
    
    def __init__(
        self,
        default_timeout: int = 300,  # 5 minutes
        dry_run: bool = False
    ):
        """Initialize command executor.
        
        Args:
            default_timeout: Default timeout in seconds
            dry_run: If True, don't actually execute commands
        """
        self.default_timeout = default_timeout
        self.dry_run = dry_run
    
    async def execute(
        self,
        command: str,
        timeout: Optional[int] = None,
        cwd: Optional[str] = None,
        capture_output: bool = True
    ) -> ExecutionResult:
        """Execute a command asynchronously.
        
        Args:
            command: Command string to execute
            timeout: Timeout in seconds (uses default if None)
            cwd: Working directory for execution
            capture_output: Whether to capture stdout/stderr
            
        Returns:
            ExecutionResult with execution details
        """
        if self.dry_run:
            return ExecutionResult(
                success=True,
                return_code=0,
                stdout="[DRY RUN] Command not executed",
                stderr="",
                execution_time=0.0
            )
        
        timeout = timeout or self.default_timeout
        start_time = datetime.now()
        
        try:
            # Create subprocess
            process = await asyncio.create_subprocess_shell(
                command,
                stdout=subprocess.PIPE if capture_output else None,
                stderr=subprocess.PIPE if capture_output else None,
                cwd=cwd
            )
            
            # Wait for completion with timeout
            try:
                stdout_bytes, stderr_bytes = await asyncio.wait_for(
                    process.communicate(),
                    timeout=timeout
                )
                
                stdout = stdout_bytes.decode('utf-8', errors='replace') if stdout_bytes else ""
                stderr = stderr_bytes.decode('utf-8', errors='replace') if stderr_bytes else ""
                
                execution_time = (datetime.now() - start_time).total_seconds()
                
                return ExecutionResult(
                    success=process.returncode == 0,
                    return_code=process.returncode or 0,
                    stdout=stdout,
                    stderr=stderr,
                    execution_time=execution_time
                )
                
            except asyncio.TimeoutError:
                # Kill the process if it times out
                try:
                    process.kill()
                    await process.wait()
                except Exception:
                    pass
                
                execution_time = (datetime.now() - start_time).total_seconds()
                
                return ExecutionResult(
                    success=False,
                    return_code=-1,
                    stdout="",
                    stderr=f"Command timed out after {timeout} seconds",
                    execution_time=execution_time,
                    error_message=f"Timeout after {timeout}s"
                )
        
        except Exception as e:
            execution_time = (datetime.now() - start_time).total_seconds()
            
            return ExecutionResult(
                success=False,
                return_code=-1,
                stdout="",
                stderr=str(e),
                execution_time=execution_time,
                error_message=f"Execution failed: {str(e)}"
            )
    
    def execute_sync(
        self,
        command: str,
        timeout: Optional[int] = None,
        cwd: Optional[str] = None,
        capture_output: bool = True
    ) -> ExecutionResult:
        """Execute a command synchronously.
        
        Args:
            command: Command string to execute
            timeout: Timeout in seconds (uses default if None)
            cwd: Working directory for execution
            capture_output: Whether to capture stdout/stderr
            
        Returns:
            ExecutionResult with execution details
        """
        if self.dry_run:
            return ExecutionResult(
                success=True,
                return_code=0,
                stdout="[DRY RUN] Command not executed",
                stderr="",
                execution_time=0.0
            )
        
        timeout = timeout or self.default_timeout
        start_time = datetime.now()
        
        try:
            result = subprocess.run(
                command,
                shell=True,
                stdout=subprocess.PIPE if capture_output else None,
                stderr=subprocess.PIPE if capture_output else None,
                timeout=timeout,
                cwd=cwd
            )
            
            execution_time = (datetime.now() - start_time).total_seconds()
            
            stdout = result.stdout.decode('utf-8', errors='replace') if result.stdout else ""
            stderr = result.stderr.decode('utf-8', errors='replace') if result.stderr else ""
            
            return ExecutionResult(
                success=result.returncode == 0,
                return_code=result.returncode,
                stdout=stdout,
                stderr=stderr,
                execution_time=execution_time
            )
            
        except subprocess.TimeoutExpired:
            execution_time = (datetime.now() - start_time).total_seconds()
            
            return ExecutionResult(
                success=False,
                return_code=-1,
                stdout="",
                stderr=f"Command timed out after {timeout} seconds",
                execution_time=execution_time,
                error_message=f"Timeout after {timeout}s"
            )
        
        except Exception as e:
            execution_time = (datetime.now() - start_time).total_seconds()
            
            return ExecutionResult(
                success=False,
                return_code=-1,
                stdout="",
                stderr=str(e),
                execution_time=execution_time,
                error_message=f"Execution failed: {str(e)}"
            )
