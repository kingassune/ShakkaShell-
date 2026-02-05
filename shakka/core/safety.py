"""Command Safety Layer for ShakkaShell.

This module provides comprehensive safety validation for generated commands,
detecting dangerous patterns and requiring user confirmation before execution.
"""

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class RiskCategory(str, Enum):
    """Categories of security risk for commands."""
    
    DESTRUCTIVE = "destructive"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    NETWORK_EXFIL = "network_exfil"
    CREDENTIAL_EXPOSURE = "credential_exposure"
    SYSTEM_MODIFICATION = "system_modification"
    DISK_OPERATION = "disk_operation"


class RiskSeverity(str, Enum):
    """Severity levels for risks."""
    
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class RiskFinding:
    """A single risk finding from safety analysis."""
    
    category: RiskCategory
    severity: RiskSeverity
    pattern_matched: str
    description: str
    recommendation: str = ""


@dataclass
class SafetyResult:
    """Result of safety analysis on a command."""
    
    command: str
    is_safe: bool
    is_blocked: bool
    requires_confirmation: bool
    findings: list[RiskFinding] = field(default_factory=list)
    
    @property
    def highest_severity(self) -> Optional[RiskSeverity]:
        """Get the highest severity from all findings."""
        if not self.findings:
            return None
        
        severity_order = [RiskSeverity.LOW, RiskSeverity.MEDIUM, RiskSeverity.HIGH, RiskSeverity.CRITICAL]
        max_idx = -1
        
        for finding in self.findings:
            idx = severity_order.index(finding.severity)
            if idx > max_idx:
                max_idx = idx
        
        return severity_order[max_idx] if max_idx >= 0 else None
    
    def get_risk_summary(self) -> str:
        """Get human-readable summary of risks."""
        if not self.findings:
            return "No risks identified"
        
        lines = []
        for finding in self.findings:
            lines.append(f"• {finding.description}")
        
        return "\n".join(lines)


@dataclass
class SafetyConfig:
    """Configuration for the safety checker."""
    
    # Confirmation settings
    confirm_dangerous: bool = True
    block_destructive: bool = False
    
    # Whitelists/Blocklists
    allowed_targets: list[str] = field(default_factory=list)
    blocked_commands: list[str] = field(default_factory=lambda: ["rm -rf /", ":(){ :|:& };:"])
    blocked_patterns: list[str] = field(default_factory=list)
    
    # Bypass options
    yolo_mode: bool = False
    
    # Audit settings
    enable_audit_log: bool = True


# Dangerous command patterns organized by category
DANGER_PATTERNS: dict[RiskCategory, list[tuple[str, RiskSeverity, str]]] = {
    RiskCategory.DESTRUCTIVE: [
        (r"rm\s+(-[^\s]*\s+)*-r", RiskSeverity.HIGH, "Recursive file deletion"),
        (r"rm\s+(-[^\s]*\s+)*-f", RiskSeverity.MEDIUM, "Forced file deletion (no confirmation)"),
        (r"rm\s+-rf\s+/(?:\s|$)", RiskSeverity.CRITICAL, "Recursive deletion from root - WILL DESTROY SYSTEM"),
        (r"rm\s+-rf\s+/\*", RiskSeverity.CRITICAL, "Recursive deletion of all root contents"),
        (r"rm\s+-rf\s+~", RiskSeverity.HIGH, "Recursive deletion of home directory"),
        (r"rm\s+-rf\s+\.", RiskSeverity.HIGH, "Recursive deletion of current directory"),
        (r"mkfs\.\w+", RiskSeverity.CRITICAL, "Filesystem format - will destroy data"),
        (r":\(\)\s*\{\s*:\|:&\s*\}\s*;:", RiskSeverity.CRITICAL, "Fork bomb - will crash system"),
        (r">\s*/dev/sd[a-z]", RiskSeverity.CRITICAL, "Direct write to disk device"),
        (r"shred\s+", RiskSeverity.HIGH, "Secure file deletion (unrecoverable)"),
    ],
    RiskCategory.PRIVILEGE_ESCALATION: [
        (r"^\s*sudo\s+", RiskSeverity.MEDIUM, "Requires root privileges"),
        (r"\|\s*sudo\s+", RiskSeverity.HIGH, "Piping to privileged command"),
        (r";\s*sudo\s+", RiskSeverity.MEDIUM, "Chained privileged command"),
        (r"su\s+-\s*$", RiskSeverity.HIGH, "Switch to root user"),
        (r"su\s+root", RiskSeverity.HIGH, "Switch to root user"),
        (r"chmod\s+777", RiskSeverity.MEDIUM, "Setting world-writable permissions"),
        (r"chmod\s+[0-7]*777", RiskSeverity.MEDIUM, "Setting world-writable permissions"),
        (r"chmod\s+\+s", RiskSeverity.HIGH, "Setting SUID/SGID bit"),
        (r"chown\s+root", RiskSeverity.MEDIUM, "Changing ownership to root"),
        (r"setcap\s+", RiskSeverity.HIGH, "Setting file capabilities"),
        (r"pkexec\s+", RiskSeverity.MEDIUM, "PolicyKit privilege escalation"),
    ],
    RiskCategory.NETWORK_EXFIL: [
        (r"curl\s+[^|]*\|\s*(?:ba)?sh", RiskSeverity.CRITICAL, "Download and execute - potential malware"),
        (r"wget\s+[^|]*\|\s*(?:ba)?sh", RiskSeverity.CRITICAL, "Download and execute - potential malware"),
        (r"curl\s+.*-o\s*-\s*\|", RiskSeverity.HIGH, "Download and pipe to command"),
        (r"wget\s+.*-O\s*-\s*\|", RiskSeverity.HIGH, "Download and pipe to command"),
        (r"nc\s+.*-e", RiskSeverity.CRITICAL, "Netcat with command execution - reverse shell"),
        (r"bash\s+-i\s+>&\s*/dev/tcp", RiskSeverity.CRITICAL, "Bash reverse shell"),
        (r"/dev/tcp/", RiskSeverity.HIGH, "TCP connection via bash"),
        (r"curl\s+.*--data.*@/etc/", RiskSeverity.CRITICAL, "Exfiltrating system files"),
        (r"base64\s+.*\|\s*curl", RiskSeverity.HIGH, "Encoding and sending data"),
    ],
    RiskCategory.CREDENTIAL_EXPOSURE: [
        (r"cat\s+.*/etc/shadow", RiskSeverity.HIGH, "Reading password hashes"),
        (r"cat\s+.*/etc/passwd", RiskSeverity.LOW, "Reading user list"),
        (r"cat\s+.*\.ssh/", RiskSeverity.HIGH, "Reading SSH keys"),
        (r"cat\s+.*id_rsa", RiskSeverity.HIGH, "Reading private SSH key"),
        (r"cat\s+.*\.aws/", RiskSeverity.HIGH, "Reading AWS credentials"),
        (r"cat\s+.*\.env", RiskSeverity.MEDIUM, "Reading environment file (may contain secrets)"),
        (r"echo\s+.*password", RiskSeverity.MEDIUM, "Echoing password (visible in history)"),
        (r"export\s+.*PASSWORD=", RiskSeverity.MEDIUM, "Setting password in environment"),
        (r"export\s+.*SECRET=", RiskSeverity.MEDIUM, "Setting secret in environment"),
        (r"export\s+.*API_KEY=", RiskSeverity.MEDIUM, "Setting API key in environment"),
        (r"--password[=\s]", RiskSeverity.MEDIUM, "Password in command line (visible in ps)"),
    ],
    RiskCategory.DISK_OPERATION: [
        (r"dd\s+.*if=/dev/", RiskSeverity.HIGH, "Direct disk read operation"),
        (r"dd\s+.*of=/dev/sd", RiskSeverity.CRITICAL, "Direct disk write - will destroy data"),
        (r"dd\s+.*of=/dev/nvme", RiskSeverity.CRITICAL, "Direct NVMe write - will destroy data"),
        (r"fdisk\s+/dev/", RiskSeverity.HIGH, "Disk partitioning"),
        (r"parted\s+/dev/", RiskSeverity.HIGH, "Disk partitioning"),
        (r"wipefs\s+", RiskSeverity.CRITICAL, "Wiping filesystem signatures"),
    ],
    RiskCategory.SYSTEM_MODIFICATION: [
        (r"systemctl\s+disable", RiskSeverity.MEDIUM, "Disabling system service"),
        (r"systemctl\s+stop", RiskSeverity.LOW, "Stopping system service"),
        (r"systemctl\s+mask", RiskSeverity.HIGH, "Masking system service (hard disable)"),
        (r"kill\s+-9", RiskSeverity.LOW, "Force-killing process"),
        (r"killall\s+", RiskSeverity.MEDIUM, "Killing all processes by name"),
        (r"pkill\s+", RiskSeverity.MEDIUM, "Killing processes by pattern"),
        (r"init\s+0", RiskSeverity.CRITICAL, "System shutdown"),
        (r"init\s+6", RiskSeverity.HIGH, "System reboot"),
        (r"shutdown\s+", RiskSeverity.HIGH, "System shutdown"),
        (r"reboot", RiskSeverity.MEDIUM, "System reboot"),
        (r"halt\s*$", RiskSeverity.CRITICAL, "System halt"),
        (r"poweroff", RiskSeverity.CRITICAL, "System power off"),
        (r"history\s+-c", RiskSeverity.MEDIUM, "Clearing command history"),
        (r">\s+~/.bash_history", RiskSeverity.MEDIUM, "Truncating bash history"),
    ],
}


class SafetyChecker:
    """Comprehensive safety checker for security commands.
    
    Analyzes commands for dangerous patterns and provides risk assessments
    with explanations.
    
    Example:
        checker = SafetyChecker()
        result = checker.check("sudo rm -rf /var/log/*")
        if result.requires_confirmation:
            print(result.get_risk_summary())
    """
    
    def __init__(self, config: Optional[SafetyConfig] = None):
        """Initialize the safety checker.
        
        Args:
            config: Safety configuration. Uses defaults if not provided.
        """
        self.config = config or SafetyConfig()
        self._audit_log: list[dict] = []
    
    def check(self, command: str) -> SafetyResult:
        """Analyze a command for safety risks.
        
        Args:
            command: Command string to analyze.
            
        Returns:
            SafetyResult with findings and recommendations.
        """
        findings: list[RiskFinding] = []
        is_blocked = False
        
        # Check against blocklist first
        if self._is_blocked(command):
            is_blocked = True
            findings.append(RiskFinding(
                category=RiskCategory.DESTRUCTIVE,
                severity=RiskSeverity.CRITICAL,
                pattern_matched="blocklist",
                description="Command is in the blocklist and cannot be executed",
                recommendation="This command has been explicitly blocked for safety.",
            ))
        
        # Check all danger patterns
        for category, patterns in DANGER_PATTERNS.items():
            for pattern, severity, description in patterns:
                if re.search(pattern, command, re.IGNORECASE | re.MULTILINE):
                    findings.append(RiskFinding(
                        category=category,
                        severity=severity,
                        pattern_matched=pattern,
                        description=description,
                        recommendation=self._get_recommendation(category, severity),
                    ))
        
        # Determine if confirmation is required
        requires_confirmation = False
        if not self.config.yolo_mode:
            if findings:
                if self.config.confirm_dangerous:
                    requires_confirmation = True
                
                # Block if configured and destructive patterns found
                if self.config.block_destructive:
                    for finding in findings:
                        if finding.category == RiskCategory.DESTRUCTIVE:
                            if finding.severity in [RiskSeverity.HIGH, RiskSeverity.CRITICAL]:
                                is_blocked = True
        
        # Determine overall safety
        is_safe = len(findings) == 0
        
        result = SafetyResult(
            command=command,
            is_safe=is_safe,
            is_blocked=is_blocked,
            requires_confirmation=requires_confirmation and not is_blocked,
            findings=findings,
        )
        
        # Audit log
        if self.config.enable_audit_log:
            self._log_check(result)
        
        return result
    
    def _is_blocked(self, command: str) -> bool:
        """Check if command matches blocklist.
        
        Args:
            command: Command to check.
            
        Returns:
            True if command is blocked.
        """
        command_lower = command.lower().strip()
        
        # Check exact blocklist
        for blocked in self.config.blocked_commands:
            blocked_lower = blocked.lower()
            # Match if command equals blocked or blocked is at start followed by space/end
            if command_lower == blocked_lower:
                return True
            if command_lower.startswith(blocked_lower + " "):
                return True
            # Also match if it's a complete dangerous pattern like fork bomb
            if blocked_lower in command_lower and blocked_lower.startswith(":"):
                return True
        
        # Check pattern blocklist
        for pattern in self.config.blocked_patterns:
            if re.search(pattern, command, re.IGNORECASE):
                return True
        
        return False
    
    def _get_recommendation(self, category: RiskCategory, severity: RiskSeverity) -> str:
        """Get a recommendation based on risk category and severity.
        
        Args:
            category: Risk category.
            severity: Risk severity.
            
        Returns:
            Recommendation string.
        """
        recommendations = {
            RiskCategory.DESTRUCTIVE: {
                RiskSeverity.CRITICAL: "DO NOT EXECUTE. This will cause irreversible data loss.",
                RiskSeverity.HIGH: "Verify target carefully. Consider creating a backup first.",
                RiskSeverity.MEDIUM: "Double-check the files/directories being affected.",
                RiskSeverity.LOW: "Review the command before executing.",
            },
            RiskCategory.PRIVILEGE_ESCALATION: {
                RiskSeverity.CRITICAL: "Avoid running with elevated privileges unless necessary.",
                RiskSeverity.HIGH: "Ensure you understand why root access is needed.",
                RiskSeverity.MEDIUM: "Running with sudo - verify the command is correct.",
                RiskSeverity.LOW: "Minor privilege change detected.",
            },
            RiskCategory.NETWORK_EXFIL: {
                RiskSeverity.CRITICAL: "This could execute arbitrary code from the internet.",
                RiskSeverity.HIGH: "Verify the source URL is trusted before executing.",
                RiskSeverity.MEDIUM: "Be cautious with network-based commands.",
                RiskSeverity.LOW: "Monitor network activity.",
            },
            RiskCategory.CREDENTIAL_EXPOSURE: {
                RiskSeverity.CRITICAL: "This may expose sensitive credentials.",
                RiskSeverity.HIGH: "Credentials may be visible - use secure methods.",
                RiskSeverity.MEDIUM: "Consider using environment variables or secret stores.",
                RiskSeverity.LOW: "Be aware of potential credential exposure.",
            },
            RiskCategory.DISK_OPERATION: {
                RiskSeverity.CRITICAL: "Direct disk operations can cause permanent data loss.",
                RiskSeverity.HIGH: "Verify disk device and operation carefully.",
                RiskSeverity.MEDIUM: "Back up data before disk operations.",
                RiskSeverity.LOW: "Review disk operation parameters.",
            },
            RiskCategory.SYSTEM_MODIFICATION: {
                RiskSeverity.CRITICAL: "This will affect system availability.",
                RiskSeverity.HIGH: "System changes may require restart or cause downtime.",
                RiskSeverity.MEDIUM: "Verify system modification is intended.",
                RiskSeverity.LOW: "Minor system change detected.",
            },
        }
        
        return recommendations.get(category, {}).get(severity, "Review carefully before executing.")
    
    def _log_check(self, result: SafetyResult) -> None:
        """Log a safety check to the audit log.
        
        Args:
            result: SafetyResult to log.
        """
        from datetime import datetime
        
        self._audit_log.append({
            "timestamp": datetime.now().isoformat(),
            "command": result.command,
            "is_safe": result.is_safe,
            "is_blocked": result.is_blocked,
            "finding_count": len(result.findings),
            "highest_severity": result.highest_severity.value if result.highest_severity else None,
        })
    
    def get_audit_log(self) -> list[dict]:
        """Get the audit log of all safety checks.
        
        Returns:
            List of audit log entries.
        """
        return list(self._audit_log)
    
    def clear_audit_log(self) -> None:
        """Clear the audit log."""
        self._audit_log.clear()
    
    def format_warning(self, result: SafetyResult) -> str:
        """Format a safety warning for display.
        
        Args:
            result: SafetyResult to format.
            
        Returns:
            Formatted warning string.
        """
        if result.is_safe:
            return ""
        
        lines = []
        
        if result.is_blocked:
            lines.append("🚫 BLOCKED COMMAND")
        else:
            severity = result.highest_severity
            if severity == RiskSeverity.CRITICAL:
                lines.append("🔴 CRITICAL DANGER DETECTED")
            elif severity == RiskSeverity.HIGH:
                lines.append("🟠 HIGH RISK COMMAND DETECTED")
            elif severity == RiskSeverity.MEDIUM:
                lines.append("🟡 MEDIUM RISK COMMAND DETECTED")
            else:
                lines.append("⚠️  POTENTIAL RISKS DETECTED")
        
        lines.append("")
        lines.append("Generated command:")
        lines.append(f"  {result.command}")
        lines.append("")
        lines.append("Risks identified:")
        
        for finding in result.findings:
            lines.append(f"  • {finding.description}")
        
        # Include recommendations for all warnings
        lines.append("")
        lines.append("Recommendations:")
        seen_recommendations = set()
        for finding in result.findings:
            if finding.recommendation and finding.recommendation not in seen_recommendations:
                lines.append(f"  • {finding.recommendation}")
                seen_recommendations.add(finding.recommendation)
        
        return "\n".join(lines)
