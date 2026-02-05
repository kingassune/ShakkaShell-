"""Honeypot detection engine.

Main detector class that orchestrates pattern matching and indicator generation.
"""

import re
import logging
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import List, Dict, Any, Optional, Set, Callable

from shakka.honeypot.patterns import (
    DetectionPattern,
    PatternCategory,
    PatternMatch,
    PatternSeverity,
    DEFAULT_PATTERNS,
    get_enabled_patterns,
)
from shakka.honeypot.indicators import (
    HoneypotIndicator,
    IndicatorType,
    IndicatorConfidence,
    IndicatorGroup,
    IndicatorSummary,
)


logger = logging.getLogger(__name__)


class Sensitivity(Enum):
    """Detection sensitivity levels."""
    
    LOW = "low"        # Only definite honeypots
    MEDIUM = "medium"  # Likely and definite
    HIGH = "high"      # Include suspicious
    PARANOID = "paranoid"  # Flag everything suspicious
    
    @property
    def min_severity(self) -> PatternSeverity:
        """Minimum pattern severity to consider."""
        mapping = {
            "low": PatternSeverity.CRITICAL,
            "medium": PatternSeverity.HIGH,
            "high": PatternSeverity.MEDIUM,
            "paranoid": PatternSeverity.LOW,
        }
        return mapping[self.value]
    
    @property
    def min_confidence(self) -> IndicatorConfidence:
        """Minimum indicator confidence to report."""
        mapping = {
            "low": IndicatorConfidence.DEFINITE,
            "medium": IndicatorConfidence.HIGH,
            "high": IndicatorConfidence.MEDIUM,
            "paranoid": IndicatorConfidence.LOW,
        }
        return mapping[self.value]


@dataclass
class DetectionContext:
    """Context for a honeypot detection run."""
    
    target: str
    target_type: str = "host"  # host, file, url, content
    content: str = ""
    banners: Dict[int, str] = field(default_factory=dict)  # port -> banner
    files: List[str] = field(default_factory=list)
    ports: List[int] = field(default_factory=list)
    services: Dict[int, str] = field(default_factory=dict)  # port -> service
    response_times: List[float] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def add_banner(self, port: int, banner: str):
        """Add a service banner."""
        self.banners[port] = banner
    
    def add_file(self, path: str):
        """Add a discovered file."""
        self.files.append(path)
    
    def add_port(self, port: int, service: Optional[str] = None):
        """Add an open port."""
        self.ports.append(port)
        if service:
            self.services[port] = service
    
    def add_response_time(self, time_ms: float):
        """Add a response time measurement."""
        self.response_times.append(time_ms)
    
    @property
    def all_text(self) -> str:
        """Get all text content for pattern matching."""
        parts = [self.content]
        parts.extend(self.banners.values())
        parts.extend(self.files)
        return "\n".join(parts)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "target": self.target,
            "target_type": self.target_type,
            "content": self.content[:500] if self.content else "",
            "banner_count": len(self.banners),
            "file_count": len(self.files),
            "port_count": len(self.ports),
            "metadata": self.metadata,
        }


@dataclass
class DetectionResult:
    """Result of honeypot detection analysis."""
    
    target: str
    is_honeypot: bool
    confidence: IndicatorConfidence
    score: float
    indicators: List[HoneypotIndicator] = field(default_factory=list)
    matches: List[PatternMatch] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)
    detection_time: datetime = field(default_factory=datetime.now)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "target": self.target,
            "is_honeypot": self.is_honeypot,
            "confidence": self.confidence.value,
            "score": self.score,
            "indicator_count": len(self.indicators),
            "match_count": len(self.matches),
            "recommendations": self.recommendations,
            "detection_time": self.detection_time.isoformat(),
            "indicators": [i.to_dict() for i in self.indicators],
            "matches": [m.to_dict() for m in self.matches],
        }
    
    def format(self) -> str:
        """Format for display."""
        lines = []
        
        if self.is_honeypot:
            if self.confidence == IndicatorConfidence.DEFINITE:
                lines.append(f"🚨 {self.target} - DEFINITE HONEYPOT")
            elif self.confidence == IndicatorConfidence.HIGH:
                lines.append(f"⚠ {self.target} - LIKELY HONEYPOT")
            else:
                lines.append(f"⚠ {self.target} - POSSIBLE HONEYPOT")
        else:
            lines.append(f"✓ {self.target} - No honeypot indicators")
            return "\n".join(lines)
        
        lines.append(f"   Confidence: {self.confidence.value} ({self.score:.0%})")
        lines.append("")
        
        # Show indicators
        for indicator in self.indicators[:5]:  # Limit to top 5
            lines.append(f"   {indicator.format()}")
        
        if len(self.indicators) > 5:
            lines.append(f"   ... and {len(self.indicators) - 5} more")
        
        # Recommendations
        if self.recommendations:
            lines.append("")
            lines.append("   Recommendations:")
            for rec in self.recommendations[:3]:
                lines.append(f"   • {rec}")
        
        return "\n".join(lines)


# Type for custom check functions
CheckFunction = Callable[[DetectionContext], Optional[PatternMatch]]


class HoneypotDetector:
    """Main honeypot detection engine.
    
    Analyzes targets for honeypot indicators using pattern matching
    and heuristic checks.
    """
    
    def __init__(
        self,
        sensitivity: Sensitivity = Sensitivity.MEDIUM,
        patterns: Optional[List[DetectionPattern]] = None,
        log_detections: bool = True,
    ):
        """Initialize the detector.
        
        Args:
            sensitivity: Detection sensitivity level
            patterns: Custom patterns (uses defaults if None)
            log_detections: Whether to log suspected honeypots
        """
        self.sensitivity = sensitivity
        self._patterns = patterns or list(DEFAULT_PATTERNS)
        self.log_detections = log_detections
        self._custom_checks: Dict[str, CheckFunction] = {}
        self._detection_log: List[DetectionResult] = []
        
        # Register built-in checks
        self._register_builtin_checks()
    
    def _register_builtin_checks(self):
        """Register built-in check functions."""
        self._custom_checks["check_port_count"] = self._check_port_count
        self._custom_checks["check_service_combination"] = self._check_service_combination
        self._custom_checks["check_response_time"] = self._check_response_time
        self._custom_checks["check_timing_variance"] = self._check_timing_variance
        self._custom_checks["check_tarpit"] = self._check_tarpit
        self._custom_checks["check_input_validation"] = self._check_input_validation
    
    @property
    def patterns(self) -> List[DetectionPattern]:
        """Get active patterns based on sensitivity."""
        min_severity = self.sensitivity.min_severity
        return [
            p for p in self._patterns
            if p.enabled and p.severity.score >= min_severity.score
        ]
    
    @property
    def detection_log(self) -> List[DetectionResult]:
        """Get logged detections."""
        return self._detection_log.copy()
    
    def add_pattern(self, pattern: DetectionPattern):
        """Add a custom detection pattern."""
        self._patterns.append(pattern)
    
    def remove_pattern(self, name: str) -> bool:
        """Remove a pattern by name."""
        for i, p in enumerate(self._patterns):
            if p.name == name:
                self._patterns.pop(i)
                return True
        return False
    
    def add_check(self, name: str, check_fn: CheckFunction):
        """Add a custom check function."""
        self._custom_checks[name] = check_fn
    
    def detect(self, context: DetectionContext) -> DetectionResult:
        """Run honeypot detection on a context.
        
        Args:
            context: Detection context with target information
            
        Returns:
            DetectionResult with analysis results
        """
        matches: List[PatternMatch] = []
        indicators: List[HoneypotIndicator] = []
        
        # Run pattern matching
        text = context.all_text
        for pattern in self.patterns:
            # Regular pattern matching
            match = pattern.match(text)
            if match:
                matches.append(match)
                indicator = self._match_to_indicator(match, context.target)
                indicators.append(indicator)
            
            # Custom check functions
            if pattern.check_function and pattern.check_function in self._custom_checks:
                check_fn = self._custom_checks[pattern.check_function]
                check_match = check_fn(context)
                if check_match:
                    matches.append(check_match)
                    indicator = self._match_to_indicator(check_match, context.target)
                    indicators.append(indicator)
        
        # Check individual file paths for canary patterns
        for file_path in context.files:
            file_matches = self._check_file_path(file_path)
            for match in file_matches:
                matches.append(match)
                indicator = self._match_to_indicator(match, context.target)
                indicator.evidence = file_path
                indicators.append(indicator)
        
        # Check banners for honeypot signatures
        for port, banner in context.banners.items():
            banner_matches = self._check_banner(banner, port)
            for match in banner_matches:
                matches.append(match)
                indicator = self._match_to_indicator(match, context.target)
                indicator.metadata["port"] = port
                indicators.append(indicator)
        
        # Calculate overall score and confidence
        score = self._calculate_score(indicators)
        confidence = IndicatorConfidence.from_score(score)
        is_honeypot = score >= 0.5  # 50% threshold
        
        # Filter indicators by sensitivity
        min_conf = self.sensitivity.min_confidence
        filtered_indicators = [
            i for i in indicators
            if i.confidence.score >= min_conf.score
        ]
        
        # Generate recommendations
        recommendations = self._generate_recommendations(matches, is_honeypot)
        
        result = DetectionResult(
            target=context.target,
            is_honeypot=is_honeypot,
            confidence=confidence,
            score=score,
            indicators=filtered_indicators,
            matches=matches,
            recommendations=recommendations,
        )
        
        # Log detection
        if self.log_detections and is_honeypot:
            self._detection_log.append(result)
            logger.warning(
                f"Honeypot detected: {context.target} "
                f"(confidence: {confidence.value}, score: {score:.0%})"
            )
        
        return result
    
    def detect_text(self, target: str, text: str) -> DetectionResult:
        """Quick detection on text content.
        
        Args:
            target: Target identifier
            text: Text content to analyze
            
        Returns:
            DetectionResult
        """
        context = DetectionContext(
            target=target,
            target_type="content",
            content=text,
        )
        return self.detect(context)
    
    def detect_banner(
        self, target: str, port: int, banner: str
    ) -> DetectionResult:
        """Detect honeypot from service banner.
        
        Args:
            target: Target host
            port: Service port
            banner: Banner text
            
        Returns:
            DetectionResult
        """
        context = DetectionContext(
            target=target,
            target_type="host",
        )
        context.add_banner(port, banner)
        return self.detect(context)
    
    def detect_files(
        self, target: str, files: List[str]
    ) -> DetectionResult:
        """Detect honeypot from file list.
        
        Args:
            target: Target identifier
            files: List of file paths
            
        Returns:
            DetectionResult
        """
        context = DetectionContext(
            target=target,
            target_type="file",
            files=files,
        )
        return self.detect(context)
    
    def batch_detect(
        self, contexts: List[DetectionContext]
    ) -> IndicatorSummary:
        """Run detection on multiple targets.
        
        Args:
            contexts: List of detection contexts
            
        Returns:
            IndicatorSummary with all results
        """
        summary = IndicatorSummary()
        
        for context in contexts:
            result = self.detect(context)
            for indicator in result.indicators:
                summary.add_indicator(context.target, indicator)
        
        return summary
    
    def clear_log(self):
        """Clear the detection log."""
        self._detection_log.clear()
    
    def format_warning(self, result: DetectionResult) -> str:
        """Format a warning message for detected honeypot.
        
        Args:
            result: Detection result
            
        Returns:
            Formatted warning string
        """
        if not result.is_honeypot:
            return ""
        
        lines = ["", "=" * 50]
        lines.append("⚠️  POTENTIAL HONEYPOT INDICATORS DETECTED")
        lines.append("=" * 50)
        lines.append("")
        
        for indicator in result.indicators:
            lines.append(indicator.format())
        
        lines.append("")
        
        if result.recommendations:
            lines.append("Recommended:")
            for rec in result.recommendations:
                lines.append(f"  • {rec}")
        
        lines.append("")
        return "\n".join(lines)
    
    # =========================================================================
    # Internal Methods
    # =========================================================================
    
    def _match_to_indicator(
        self, match: PatternMatch, target: str
    ) -> HoneypotIndicator:
        """Convert a pattern match to an indicator."""
        # Map severity to confidence
        confidence_map = {
            PatternSeverity.LOW: IndicatorConfidence.LOW,
            PatternSeverity.MEDIUM: IndicatorConfidence.MEDIUM,
            PatternSeverity.HIGH: IndicatorConfidence.HIGH,
            PatternSeverity.CRITICAL: IndicatorConfidence.DEFINITE,
        }
        
        # Map category to indicator type
        type_map = {
            PatternCategory.EASY_CREDENTIALS: IndicatorType.CREDENTIAL,
            PatternCategory.UNICODE_MANIPULATION: IndicatorType.CONTENT,
            PatternCategory.PLANTED_EVIDENCE: IndicatorType.CONTENT,
            PatternCategory.CANARY_FILES: IndicatorType.FILE,
            PatternCategory.TIMING_ANOMALY: IndicatorType.TIMING,
            PatternCategory.BANNER_ANOMALY: IndicatorType.BANNER,
            PatternCategory.SERVICE_ANOMALY: IndicatorType.BEHAVIOR,
            PatternCategory.NETWORK_ANOMALY: IndicatorType.NETWORK,
        }
        
        return HoneypotIndicator(
            indicator_type=type_map.get(match.category, IndicatorType.CONTENT),
            confidence=confidence_map.get(match.severity, IndicatorConfidence.MEDIUM),
            description=match.description,
            target=target,
            evidence=match.evidence,
            source=match.pattern_name,
        )
    
    def _calculate_score(self, indicators: List[HoneypotIndicator]) -> float:
        """Calculate aggregate honeypot score from indicators."""
        if not indicators:
            return 0.0
        
        # Sum scores with diminishing returns
        total = 0.0
        sorted_indicators = sorted(
            indicators, key=lambda i: -i.confidence.score
        )
        
        for i, ind in enumerate(sorted_indicators):
            weight = 1.0 / (1 + i * 0.3)
            total += ind.confidence.score * weight
        
        # Normalize to 0-1, cap at 1.0
        return min(1.0, total / 2.0)
    
    def _generate_recommendations(
        self, matches: List[PatternMatch], is_honeypot: bool
    ) -> List[str]:
        """Generate recommendations based on detection results."""
        recommendations = []
        
        if not is_honeypot:
            return recommendations
        
        # General recommendation
        recommendations.append("Skip flagged hosts or proceed with caution")
        
        # Category-specific recommendations
        categories = {m.category for m in matches}
        
        if PatternCategory.EASY_CREDENTIALS in categories:
            recommendations.append(
                "Avoid using discovered credentials - likely canary tokens"
            )
        
        if PatternCategory.UNICODE_MANIPULATION in categories:
            recommendations.append(
                "Content contains hidden/invisible characters - sanitize before use"
            )
        
        if PatternCategory.CANARY_FILES in categories:
            recommendations.append(
                "Do not download or access flagged files - likely canary traps"
            )
        
        if PatternCategory.BANNER_ANOMALY in categories:
            recommendations.append(
                "Service banners match known honeypot signatures"
            )
        
        if PatternCategory.TIMING_ANOMALY in categories:
            recommendations.append(
                "Timing characteristics are suspicious - may be emulated"
            )
        
        return recommendations
    
    def _check_file_path(self, file_path: str) -> List[PatternMatch]:
        """Check a file path for canary patterns."""
        matches = []
        file_lower = file_path.lower()
        
        for pattern in self.patterns:
            if pattern.category != PatternCategory.CANARY_FILES:
                continue
            
            # Check keywords
            for keyword in pattern.keywords:
                if keyword.lower() in file_lower:
                    matches.append(PatternMatch(
                        matched=True,
                        pattern_name=pattern.name,
                        category=pattern.category,
                        severity=pattern.severity,
                        description=pattern.description,
                        evidence=file_path,
                        location=file_path,
                    ))
                    break
        
        return matches
    
    def _check_banner(self, banner: str, port: int) -> List[PatternMatch]:
        """Check a service banner for honeypot signatures."""
        matches = []
        
        for pattern in self.patterns:
            if pattern.category != PatternCategory.BANNER_ANOMALY:
                continue
            
            match = pattern.match(banner)
            if match:
                match.location = f"port {port}"
                matches.append(match)
        
        return matches
    
    # =========================================================================
    # Built-in Check Functions
    # =========================================================================
    
    def _check_port_count(self, context: DetectionContext) -> Optional[PatternMatch]:
        """Check for unusually high number of open ports."""
        if len(context.ports) > 50:
            return PatternMatch(
                matched=True,
                pattern_name="too_many_open_ports",
                category=PatternCategory.SERVICE_ANOMALY,
                severity=PatternSeverity.MEDIUM,
                description=f"Unusually high number of open ports ({len(context.ports)})",
                evidence=f"open ports: {len(context.ports)}",
            )
        return None
    
    def _check_service_combination(
        self, context: DetectionContext
    ) -> Optional[PatternMatch]:
        """Check for unusual service combinations."""
        # Unusual to have both old and new versions of same service
        services = set(context.services.values())
        
        unusual_combos = [
            {"telnet", "ssh", "rdp"},  # All remote access at once
            {"mysql", "mssql", "postgres", "oracle"},  # All DBs
        ]
        
        for combo in unusual_combos:
            if len(services & combo) >= 3:
                return PatternMatch(
                    matched=True,
                    pattern_name="unusual_service_combo",
                    category=PatternCategory.SERVICE_ANOMALY,
                    severity=PatternSeverity.LOW,
                    description="Unusual combination of services running",
                    evidence=", ".join(services & combo),
                )
        
        return None
    
    def _check_response_time(
        self, context: DetectionContext
    ) -> Optional[PatternMatch]:
        """Check for instant response times (simulated service)."""
        if not context.response_times:
            return None
        
        # Check if any response is suspiciously fast (< 1ms)
        instant = [t for t in context.response_times if t < 1.0]
        if len(instant) > len(context.response_times) * 0.5:
            return PatternMatch(
                matched=True,
                pattern_name="instant_response",
                category=PatternCategory.TIMING_ANOMALY,
                severity=PatternSeverity.LOW,
                description="Service responding with no latency (simulated)",
                evidence=f"avg response: {sum(context.response_times)/len(context.response_times):.2f}ms",
            )
        return None
    
    def _check_timing_variance(
        self, context: DetectionContext
    ) -> Optional[PatternMatch]:
        """Check for suspiciously consistent timing."""
        if len(context.response_times) < 5:
            return None
        
        times = context.response_times
        avg = sum(times) / len(times)
        
        if avg == 0:
            return None
        
        variance = sum((t - avg) ** 2 for t in times) / len(times)
        std_dev = variance ** 0.5
        
        # Coefficient of variation < 0.01 is suspiciously consistent
        cv = std_dev / avg if avg > 0 else 0
        if cv < 0.01:
            return PatternMatch(
                matched=True,
                pattern_name="consistent_timing",
                category=PatternCategory.TIMING_ANOMALY,
                severity=PatternSeverity.LOW,
                description="Suspiciously consistent response times",
                evidence=f"CV: {cv:.4f}",
            )
        return None
    
    def _check_tarpit(self, context: DetectionContext) -> Optional[PatternMatch]:
        """Check for tarpit behavior."""
        if not context.response_times:
            return None
        
        # Tarpit: responses get progressively slower
        if len(context.response_times) >= 5:
            times = context.response_times
            increasing = all(
                times[i] < times[i+1] 
                for i in range(len(times) - 1)
            )
            
            if increasing and times[-1] / times[0] > 10:
                return PatternMatch(
                    matched=True,
                    pattern_name="tarpit_behavior",
                    category=PatternCategory.NETWORK_ANOMALY,
                    severity=PatternSeverity.MEDIUM,
                    description="Connection exhibiting tarpit behavior",
                    evidence=f"slowdown ratio: {times[-1] / times[0]:.1f}x",
                )
        return None
    
    def _check_input_validation(
        self, context: DetectionContext
    ) -> Optional[PatternMatch]:
        """Check for service accepting any input without error.
        
        Note: This requires metadata from actual testing, just pattern for now.
        """
        # This would require actual interaction data
        # For now, check metadata flag
        if context.metadata.get("accepts_any_input"):
            return PatternMatch(
                matched=True,
                pattern_name="promiscuous_accept",
                category=PatternCategory.NETWORK_ANOMALY,
                severity=PatternSeverity.MEDIUM,
                description="Service accepting any input without error",
                evidence="no input validation detected",
            )
        return None
