"""Command validation module for ShakkaShell.

Validates generated commands for syntax correctness and safety.
"""

import re
import subprocess
from typing import Optional, List, Tuple

from shakka.providers.base import CommandResult


class CommandValidator:
    """Validates security commands for syntax and safety.
    
    Performs basic syntax validation and safety checks on generated commands.
    """
    
    # Dangerous commands that should always trigger warnings
    DANGEROUS_PATTERNS = [
        r"rm\s+-rf\s+/",  # Recursive delete from root
        r":\(\)\{\s*:\|:&\s*\};:",  # Fork bomb
        r"dd\s+if=/dev/.*\s+of=/dev/[sh]d[a-z]",  # Disk wipe
        r"mkfs\.",  # Format filesystem
        r">/dev/sd[a-z]",  # Write to disk directly
        r"wget.*\|.*sh",  # Download and execute
        r"curl.*\|.*bash",  # Download and execute
    ]
    
    # Tools commonly used in offensive security
    KNOWN_TOOLS = [
        "nmap", "nikto", "gobuster", "ffuf", "sqlmap", "hydra",
        "metasploit", "msfvenom", "burpsuite", "wireshark", "tcpdump",
        "aircrack-ng", "hashcat", "john", "crackmapexec", "enum4linux",
        "smbclient", "rpcclient", "wfuzz", "dirb", "dirbuster",
        "masscan", "zap", "netcat", "nc", "socat", "chisel",
        "mimikatz", "responder", "bloodhound", "impacket"
    ]
    
    def __init__(self):
        """Initialize the command validator."""
        self.validation_errors: List[str] = []
        self.validation_warnings: List[str] = []
    
    def validate(self, result: CommandResult) -> Tuple[bool, List[str], List[str]]:
        """Validate a command result.
        
        Args:
            result: CommandResult to validate
            
        Returns:
            Tuple of (is_valid, errors, warnings)
        """
        self.validation_errors = []
        self.validation_warnings = []
        
        # Basic validation
        self._validate_command_structure(result.command)
        self._check_dangerous_patterns(result.command)
        self._validate_risk_consistency(result)
        self._check_tool_availability(result)
        
        is_valid = len(self.validation_errors) == 0
        return is_valid, self.validation_errors, self.validation_warnings
    
    def _validate_command_structure(self, command: str) -> None:
        """Validate basic command structure.
        
        Args:
            command: Command string to validate
        """
        if not command or not command.strip():
            self.validation_errors.append("Command is empty")
            return
        
        # Check for balanced quotes
        single_quotes = command.count("'")
        double_quotes = command.count('"')
        
        if single_quotes % 2 != 0:
            self.validation_errors.append("Unbalanced single quotes")
        
        if double_quotes % 2 != 0:
            self.validation_errors.append("Unbalanced double quotes")
        
        # Check for balanced parentheses and brackets
        if command.count("(") != command.count(")"):
            self.validation_errors.append("Unbalanced parentheses")
        
        if command.count("[") != command.count("]"):
            self.validation_errors.append("Unbalanced brackets")
        
        if command.count("{") != command.count("}"):
            self.validation_errors.append("Unbalanced braces")
    
    def _check_dangerous_patterns(self, command: str) -> None:
        """Check for dangerous command patterns.
        
        Args:
            command: Command string to check
        """
        for pattern in self.DANGEROUS_PATTERNS:
            if re.search(pattern, command, re.IGNORECASE):
                self.validation_warnings.append(
                    f"Command contains potentially destructive pattern: {pattern}"
                )
    
    def _validate_risk_consistency(self, result: CommandResult) -> None:
        """Validate that risk level is consistent with command and warnings.
        
        Args:
            result: CommandResult to validate
        """
        command = result.command.lower()
        risk_level = result.risk_level
        
        # Commands with privilege escalation should be High/Critical
        if any(word in command for word in ["sudo", "su -", "pkexec"]):
            if risk_level not in ["High", "Critical"]:
                self.validation_warnings.append(
                    "Command uses privilege escalation but risk level is not High/Critical"
                )
        
        # Exploitation tools should be at least Medium risk
        exploit_tools = ["sqlmap", "metasploit", "msfvenom", "exploit"]
        if any(tool in command for tool in exploit_tools):
            if risk_level == "Low":
                self.validation_warnings.append(
                    "Command uses exploitation tools but risk level is Low"
                )
        
        # If there are warnings but risk is Low, flag inconsistency
        if result.warnings and risk_level == "Low":
            self.validation_warnings.append(
                "Command has warnings but risk level is Low - consider increasing risk level"
            )
    
    def _check_tool_availability(self, result: CommandResult) -> None:
        """Check if required tools are available.
        
        Args:
            result: CommandResult to check
        """
        # Extract the main command (first word)
        command_parts = result.command.split()
        if not command_parts:
            return
        
        main_command = command_parts[0]
        
        # Try to check if the command exists (basic check)
        try:
            # Use 'which' on Unix-like systems
            subprocess.run(
                ["which", main_command],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=1
            )
            # If we get here, command exists
        except (subprocess.TimeoutExpired, FileNotFoundError):
            # Command not found or which doesn't exist
            if main_command in self.KNOWN_TOOLS:
                self.validation_warnings.append(
                    f"Tool '{main_command}' may not be installed"
                )
    
    def get_validation_summary(self) -> str:
        """Get a summary of validation results.
        
        Returns:
            String summary of validation
        """
        if not self.validation_errors and not self.validation_warnings:
            return "✓ Command validation passed"
        
        summary = []
        
        if self.validation_errors:
            summary.append(f"Errors ({len(self.validation_errors)}):")
            for error in self.validation_errors:
                summary.append(f"  • {error}")
        
        if self.validation_warnings:
            summary.append(f"Warnings ({len(self.validation_warnings)}):")
            for warning in self.validation_warnings:
                summary.append(f"  • {warning}")
        
        return "\n".join(summary)
