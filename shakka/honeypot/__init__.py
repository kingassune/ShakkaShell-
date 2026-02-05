"""Anti-Honeypot Detection module.

Provides heuristics to detect and avoid security traps like honeypots,
canary files, and deceptive patterns in target environments.
"""

from shakka.honeypot.detector import (
    HoneypotDetector,
    DetectionResult,
    DetectionContext,
    Sensitivity,
)
from shakka.honeypot.patterns import (
    DetectionPattern,
    PatternCategory,
    PatternMatch,
    PatternSeverity,
    DEFAULT_PATTERNS,
    get_enabled_patterns,
    get_patterns_by_category,
    get_patterns_by_severity,
)
from shakka.honeypot.indicators import (
    HoneypotIndicator,
    IndicatorType,
    IndicatorConfidence,
    IndicatorGroup,
    IndicatorSummary,
)

__all__ = [
    # Detector
    "HoneypotDetector",
    "DetectionResult",
    "DetectionContext",
    "Sensitivity",
    # Patterns
    "DetectionPattern",
    "PatternCategory",
    "PatternMatch",
    "PatternSeverity",
    "DEFAULT_PATTERNS",
    "get_enabled_patterns",
    "get_patterns_by_category",
    "get_patterns_by_severity",
    # Indicators
    "HoneypotIndicator",
    "IndicatorType",
    "IndicatorConfidence",
    "IndicatorGroup",
    "IndicatorSummary",
]
