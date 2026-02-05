"""Detection patterns for honeypot identification.

Defines pattern categories, severity levels, and matching logic.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import List, Optional, Dict, Any, Pattern
import re


class PatternCategory(Enum):
    """Categories of honeypot detection patterns."""
    
    EASY_CREDENTIALS = "easy_credentials"
    UNICODE_MANIPULATION = "unicode_manipulation"
    PLANTED_EVIDENCE = "planted_evidence"
    CANARY_FILES = "canary_files"
    TIMING_ANOMALY = "timing_anomaly"
    BANNER_ANOMALY = "banner_anomaly"
    SERVICE_ANOMALY = "service_anomaly"
    NETWORK_ANOMALY = "network_anomaly"


class PatternSeverity(Enum):
    """Severity levels for pattern matches."""
    
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"
    
    @property
    def score(self) -> int:
        """Get numeric score for severity."""
        scores = {
            "low": 1,
            "medium": 2,
            "high": 3,
            "critical": 4,
        }
        return scores[self.value]


@dataclass
class PatternMatch:
    """Result of a pattern match check."""
    
    matched: bool
    pattern_name: str
    category: PatternCategory
    severity: PatternSeverity
    description: str
    evidence: str = ""
    location: str = ""
    recommendation: str = ""
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "matched": self.matched,
            "pattern_name": self.pattern_name,
            "category": self.category.value,
            "severity": self.severity.value,
            "description": self.description,
            "evidence": self.evidence,
            "location": self.location,
            "recommendation": self.recommendation,
        }
    
    def format(self) -> str:
        """Format for display."""
        severity_icons = {
            PatternSeverity.LOW: "ℹ",
            PatternSeverity.MEDIUM: "⚠",
            PatternSeverity.HIGH: "⚠",
            PatternSeverity.CRITICAL: "🚨",
        }
        icon = severity_icons.get(self.severity, "?")
        loc = f" at {self.location}" if self.location else ""
        return f"[{icon}] {self.description}{loc}"


@dataclass
class DetectionPattern:
    """A honeypot detection pattern."""
    
    name: str
    description: str
    category: PatternCategory
    severity: PatternSeverity
    pattern: Optional[str] = None  # Regex pattern
    keywords: List[str] = field(default_factory=list)
    check_function: Optional[str] = None  # Name of custom check function
    enabled: bool = True
    
    _compiled_pattern: Optional[Pattern] = field(
        default=None, init=False, repr=False
    )
    
    def __post_init__(self):
        """Compile regex pattern if provided."""
        if self.pattern:
            try:
                self._compiled_pattern = re.compile(
                    self.pattern, re.IGNORECASE | re.MULTILINE
                )
            except re.error:
                self._compiled_pattern = None
    
    def match(self, text: str) -> Optional[PatternMatch]:
        """Check if pattern matches the text.
        
        Args:
            text: Text to check
            
        Returns:
            PatternMatch if matched, None otherwise
        """
        if not self.enabled:
            return None
        
        matched = False
        evidence = ""
        
        # Check regex pattern
        if self._compiled_pattern:
            match = self._compiled_pattern.search(text)
            if match:
                matched = True
                evidence = match.group(0)
        
        # Check keywords
        if not matched and self.keywords:
            text_lower = text.lower()
            for keyword in self.keywords:
                if keyword.lower() in text_lower:
                    matched = True
                    evidence = keyword
                    break
        
        if matched:
            return PatternMatch(
                matched=True,
                pattern_name=self.name,
                category=self.category,
                severity=self.severity,
                description=self.description,
                evidence=evidence,
            )
        
        return None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "name": self.name,
            "description": self.description,
            "category": self.category.value,
            "severity": self.severity.value,
            "pattern": self.pattern,
            "keywords": self.keywords,
            "enabled": self.enabled,
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "DetectionPattern":
        """Create from dictionary."""
        return cls(
            name=data["name"],
            description=data["description"],
            category=PatternCategory(data["category"]),
            severity=PatternSeverity(data["severity"]),
            pattern=data.get("pattern"),
            keywords=data.get("keywords", []),
            check_function=data.get("check_function"),
            enabled=data.get("enabled", True),
        )


# =============================================================================
# Default Detection Patterns
# =============================================================================

DEFAULT_PATTERNS: List[DetectionPattern] = [
    # Easy Credentials
    DetectionPattern(
        name="obvious_password_file",
        description="Password file in obvious web-accessible location",
        category=PatternCategory.EASY_CREDENTIALS,
        severity=PatternSeverity.HIGH,
        pattern=r"(?:password|passwd|credentials|secret|admin)\s*[:=]\s*\S+",
        keywords=["passwords.txt", "credentials.txt", "admin_password"],
    ),
    DetectionPattern(
        name="robots_txt_password",
        description="Credentials exposed in robots.txt (likely bait)",
        category=PatternCategory.EASY_CREDENTIALS,
        severity=PatternSeverity.HIGH,
        pattern=r"(?:admin|root|administrator).*(?:password|pass|pwd)\s*[:=]\s*\S+",
        keywords=["password:", "admin:", "secret:"],
    ),
    DetectionPattern(
        name="default_high_value_creds",
        description="Default credentials with high-value account names",
        category=PatternCategory.EASY_CREDENTIALS,
        severity=PatternSeverity.MEDIUM,
        pattern=r"(?:root|admin|administrator|sa|postgres|mysql)[:@/]\s*(?:password|admin|root|123456|password123)",
    ),
    DetectionPattern(
        name="too_obvious_secrets",
        description="Suspiciously easy-to-find secrets",
        category=PatternCategory.EASY_CREDENTIALS,
        severity=PatternSeverity.HIGH,
        keywords=[
            "aws_secret_access_key",
            "private_key_here",
            "api_key_secret",
            "hunter2",
        ],
    ),
    
    # Unicode Manipulation
    DetectionPattern(
        name="backspace_injection",
        description="Hidden content using backspace characters (U+0008)",
        category=PatternCategory.UNICODE_MANIPULATION,
        severity=PatternSeverity.CRITICAL,
        pattern=r"[\x08\u0008]+",
    ),
    DetectionPattern(
        name="invisible_characters",
        description="Zero-width or invisible Unicode characters",
        category=PatternCategory.UNICODE_MANIPULATION,
        severity=PatternSeverity.HIGH,
        pattern=r"[\u200b\u200c\u200d\u2060\ufeff]+",
    ),
    DetectionPattern(
        name="rtl_override",
        description="Right-to-left override characters hiding content",
        category=PatternCategory.UNICODE_MANIPULATION,
        severity=PatternSeverity.HIGH,
        pattern=r"[\u202e\u202d\u202c]+",
    ),
    DetectionPattern(
        name="homoglyph_attack",
        description="Lookalike Unicode characters replacing ASCII",
        category=PatternCategory.UNICODE_MANIPULATION,
        severity=PatternSeverity.MEDIUM,
        pattern=r"[\u0430\u0435\u043e\u0440\u0441\u0445\u0443]+",  # Cyrillic lookalikes
    ),
    
    # Planted Evidence
    DetectionPattern(
        name="patched_cve_claim",
        description="Suspicious 'all CVEs patched' or similar claims",
        category=PatternCategory.PLANTED_EVIDENCE,
        severity=PatternSeverity.MEDIUM,
        pattern=r"(?:all\s+)?(?:cve|vulnerabilit(?:y|ies)|security\s+issues?)\s+(?:patched|fixed|resolved)",
        keywords=["fully patched", "no vulnerabilities", "100% secure"],
    ),
    DetectionPattern(
        name="fake_flag",
        description="CTF-style flag in production environment",
        category=PatternCategory.PLANTED_EVIDENCE,
        severity=PatternSeverity.HIGH,
        pattern=r"(?:flag|ctf|capture.the.flag)\s*[{:=]\s*[a-zA-Z0-9_-]+",
        keywords=["flag{", "CTF{", "honeypot_flag"],
    ),
    DetectionPattern(
        name="planted_ssh_key",
        description="SSH private key in suspicious location",
        category=PatternCategory.PLANTED_EVIDENCE,
        severity=PatternSeverity.HIGH,
        keywords=["id_rsa", "private_key.pem", "server.key"],
    ),
    
    # Canary Files
    DetectionPattern(
        name="canary_password_file",
        description="Password file in unexpected location (canary trap)",
        category=PatternCategory.CANARY_FILES,
        severity=PatternSeverity.HIGH,
        keywords=[
            "passwords.txt",
            "secrets.txt",
            "credentials.csv",
            "users.txt",
            "admin_backup.txt",
        ],
    ),
    DetectionPattern(
        name="canary_database",
        description="Database backup in web root (canary trap)",
        category=PatternCategory.CANARY_FILES,
        severity=PatternSeverity.HIGH,
        keywords=[
            "database.sql",
            "backup.sql",
            "users.db",
            "dump.sql",
            "data.sqlite",
        ],
    ),
    DetectionPattern(
        name="canary_config",
        description="Configuration file with secrets exposed",
        category=PatternCategory.CANARY_FILES,
        severity=PatternSeverity.MEDIUM,
        keywords=[
            ".env",
            "config.php.bak",
            "wp-config.php.old",
            ".git/config",
            "settings.py.bak",
        ],
    ),
    
    # Banner Anomalies
    DetectionPattern(
        name="kippo_banner",
        description="Known Kippo honeypot SSH banner",
        category=PatternCategory.BANNER_ANOMALY,
        severity=PatternSeverity.CRITICAL,
        pattern=r"SSH-2\.0-OpenSSH_5\.1p1\s+Debian",
        keywords=["Kippo"],
    ),
    DetectionPattern(
        name="cowrie_banner",
        description="Known Cowrie honeypot SSH banner",
        category=PatternCategory.BANNER_ANOMALY,
        severity=PatternSeverity.CRITICAL,
        keywords=["Cowrie", "SSH-2.0-OpenSSH_6.0p1"],
    ),
    DetectionPattern(
        name="dionaea_banner",
        description="Known Dionaea honeypot signature",
        category=PatternCategory.BANNER_ANOMALY,
        severity=PatternSeverity.CRITICAL,
        keywords=["Dionaea", "dionaea"],
    ),
    DetectionPattern(
        name="generic_honeypot_banner",
        description="Suspicious generic service banner",
        category=PatternCategory.BANNER_ANOMALY,
        severity=PatternSeverity.MEDIUM,
        keywords=["honeypot", "canary", "decoy", "trap"],
    ),
    
    # Service Anomalies
    DetectionPattern(
        name="too_many_open_ports",
        description="Unusually high number of open ports (>50)",
        category=PatternCategory.SERVICE_ANOMALY,
        severity=PatternSeverity.MEDIUM,
        check_function="check_port_count",
    ),
    DetectionPattern(
        name="unusual_service_combo",
        description="Unusual combination of services running",
        category=PatternCategory.SERVICE_ANOMALY,
        severity=PatternSeverity.LOW,
        check_function="check_service_combination",
    ),
    DetectionPattern(
        name="fake_vulnerability",
        description="Service reporting obviously fake vulnerability",
        category=PatternCategory.SERVICE_ANOMALY,
        severity=PatternSeverity.HIGH,
        keywords=["CVE-1999-0001", "test-vuln", "fake-cve"],
    ),
    
    # Timing Anomalies
    DetectionPattern(
        name="instant_response",
        description="Service responding with no latency (simulated)",
        category=PatternCategory.TIMING_ANOMALY,
        severity=PatternSeverity.LOW,
        check_function="check_response_time",
    ),
    DetectionPattern(
        name="consistent_timing",
        description="Suspiciously consistent response times",
        category=PatternCategory.TIMING_ANOMALY,
        severity=PatternSeverity.LOW,
        check_function="check_timing_variance",
    ),
    
    # Network Anomalies
    DetectionPattern(
        name="tarpit_behavior",
        description="Connection exhibiting tarpit behavior",
        category=PatternCategory.NETWORK_ANOMALY,
        severity=PatternSeverity.MEDIUM,
        check_function="check_tarpit",
    ),
    DetectionPattern(
        name="promiscuous_accept",
        description="Service accepting any input without error",
        category=PatternCategory.NETWORK_ANOMALY,
        severity=PatternSeverity.MEDIUM,
        check_function="check_input_validation",
    ),
]


def get_patterns_by_category(
    category: PatternCategory,
) -> List[DetectionPattern]:
    """Get all patterns for a category."""
    return [p for p in DEFAULT_PATTERNS if p.category == category]


def get_patterns_by_severity(
    min_severity: PatternSeverity,
) -> List[DetectionPattern]:
    """Get patterns at or above minimum severity."""
    return [
        p for p in DEFAULT_PATTERNS
        if p.severity.score >= min_severity.score
    ]


def get_enabled_patterns() -> List[DetectionPattern]:
    """Get all enabled patterns."""
    return [p for p in DEFAULT_PATTERNS if p.enabled]
