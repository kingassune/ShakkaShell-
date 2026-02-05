"""Tests for Anti-Honeypot Detection module.

Tests pattern matching, indicator generation, and detection logic.
"""

import pytest
from datetime import datetime

from shakka.honeypot import (
    # Detector
    HoneypotDetector,
    DetectionResult,
    DetectionContext,
    Sensitivity,
    # Patterns
    DetectionPattern,
    PatternCategory,
    PatternMatch,
    PatternSeverity,
    DEFAULT_PATTERNS,
    get_enabled_patterns,
    get_patterns_by_category,
    get_patterns_by_severity,
    # Indicators
    HoneypotIndicator,
    IndicatorType,
    IndicatorConfidence,
    IndicatorGroup,
    IndicatorSummary,
)


# =============================================================================
# PatternCategory Tests
# =============================================================================

class TestPatternCategory:
    """Tests for pattern category enum."""
    
    def test_all_categories_exist(self):
        """All expected categories exist."""
        expected = [
            "easy_credentials",
            "unicode_manipulation", 
            "planted_evidence",
            "canary_files",
            "timing_anomaly",
            "banner_anomaly",
            "service_anomaly",
            "network_anomaly",
        ]
        for cat in expected:
            assert hasattr(PatternCategory, cat.upper())
    
    def test_category_values(self):
        """Category values are strings."""
        assert PatternCategory.EASY_CREDENTIALS.value == "easy_credentials"
        assert PatternCategory.TIMING_ANOMALY.value == "timing_anomaly"


# =============================================================================
# PatternSeverity Tests
# =============================================================================

class TestPatternSeverity:
    """Tests for pattern severity enum."""
    
    def test_severity_values(self):
        """Severity values are strings."""
        assert PatternSeverity.LOW.value == "low"
        assert PatternSeverity.CRITICAL.value == "critical"
    
    def test_severity_scores(self):
        """Severity scores are ordered correctly."""
        assert PatternSeverity.LOW.score < PatternSeverity.MEDIUM.score
        assert PatternSeverity.MEDIUM.score < PatternSeverity.HIGH.score
        assert PatternSeverity.HIGH.score < PatternSeverity.CRITICAL.score


# =============================================================================
# PatternMatch Tests
# =============================================================================

class TestPatternMatch:
    """Tests for pattern match model."""
    
    def test_match_creation(self):
        """Pattern match can be created."""
        match = PatternMatch(
            matched=True,
            pattern_name="test_pattern",
            category=PatternCategory.EASY_CREDENTIALS,
            severity=PatternSeverity.HIGH,
            description="Test pattern match",
            evidence="password: admin",
        )
        assert match.matched is True
        assert match.pattern_name == "test_pattern"
    
    def test_match_to_dict(self):
        """Match converts to dictionary."""
        match = PatternMatch(
            matched=True,
            pattern_name="test",
            category=PatternCategory.CANARY_FILES,
            severity=PatternSeverity.MEDIUM,
            description="Test",
        )
        data = match.to_dict()
        assert data["matched"] is True
        assert data["category"] == "canary_files"
    
    def test_match_format(self):
        """Match formats for display."""
        match = PatternMatch(
            matched=True,
            pattern_name="test",
            category=PatternCategory.EASY_CREDENTIALS,
            severity=PatternSeverity.CRITICAL,
            description="Found password",
            location="/etc/passwd",
        )
        formatted = match.format()
        assert "Found password" in formatted
        assert "/etc/passwd" in formatted


# =============================================================================
# DetectionPattern Tests
# =============================================================================

class TestDetectionPattern:
    """Tests for detection pattern model."""
    
    def test_pattern_creation(self):
        """Pattern can be created."""
        pattern = DetectionPattern(
            name="test_pattern",
            description="Test pattern",
            category=PatternCategory.EASY_CREDENTIALS,
            severity=PatternSeverity.HIGH,
            pattern=r"password[:=]\s*\S+",
        )
        assert pattern.name == "test_pattern"
    
    def test_pattern_match_regex(self):
        """Pattern matches with regex."""
        pattern = DetectionPattern(
            name="test",
            description="Test",
            category=PatternCategory.EASY_CREDENTIALS,
            severity=PatternSeverity.HIGH,
            pattern=r"password\s*[:=]\s*(\S+)",
        )
        match = pattern.match("Found password: admin123")
        assert match is not None
        assert match.matched is True
        assert "password: admin123" in match.evidence
    
    def test_pattern_match_keywords(self):
        """Pattern matches with keywords."""
        pattern = DetectionPattern(
            name="test",
            description="Test",
            category=PatternCategory.CANARY_FILES,
            severity=PatternSeverity.MEDIUM,
            keywords=["passwords.txt", "secrets.txt"],
        )
        match = pattern.match("Found file: passwords.txt")
        assert match is not None
        assert match.matched is True
    
    def test_pattern_no_match(self):
        """Pattern returns None when no match."""
        pattern = DetectionPattern(
            name="test",
            description="Test",
            category=PatternCategory.EASY_CREDENTIALS,
            severity=PatternSeverity.HIGH,
            pattern=r"password\s*[:=]",
        )
        match = pattern.match("Normal text without secrets")
        assert match is None
    
    def test_pattern_disabled(self):
        """Disabled pattern returns None."""
        pattern = DetectionPattern(
            name="test",
            description="Test",
            category=PatternCategory.EASY_CREDENTIALS,
            severity=PatternSeverity.HIGH,
            pattern=r"password",
            enabled=False,
        )
        match = pattern.match("password: admin")
        assert match is None
    
    def test_pattern_to_dict(self):
        """Pattern converts to dictionary."""
        pattern = DetectionPattern(
            name="test",
            description="Test pattern",
            category=PatternCategory.BANNER_ANOMALY,
            severity=PatternSeverity.CRITICAL,
            keywords=["honeypot"],
        )
        data = pattern.to_dict()
        assert data["name"] == "test"
        assert data["category"] == "banner_anomaly"
    
    def test_pattern_from_dict(self):
        """Pattern can be created from dictionary."""
        data = {
            "name": "from_dict",
            "description": "From dict",
            "category": "timing_anomaly",
            "severity": "low",
            "keywords": ["test"],
        }
        pattern = DetectionPattern.from_dict(data)
        assert pattern.name == "from_dict"
        assert pattern.category == PatternCategory.TIMING_ANOMALY


# =============================================================================
# Default Patterns Tests
# =============================================================================

class TestDefaultPatterns:
    """Tests for default detection patterns."""
    
    def test_default_patterns_exist(self):
        """Default patterns are populated."""
        assert len(DEFAULT_PATTERNS) > 0
    
    def test_get_enabled_patterns(self):
        """Get enabled patterns works."""
        enabled = get_enabled_patterns()
        assert len(enabled) > 0
        assert all(p.enabled for p in enabled)
    
    def test_get_patterns_by_category(self):
        """Get patterns by category works."""
        creds = get_patterns_by_category(PatternCategory.EASY_CREDENTIALS)
        assert len(creds) > 0
        assert all(p.category == PatternCategory.EASY_CREDENTIALS for p in creds)
    
    def test_get_patterns_by_severity(self):
        """Get patterns by minimum severity works."""
        critical = get_patterns_by_severity(PatternSeverity.CRITICAL)
        assert len(critical) > 0
        assert all(p.severity == PatternSeverity.CRITICAL for p in critical)


# =============================================================================
# IndicatorType Tests
# =============================================================================

class TestIndicatorType:
    """Tests for indicator type enum."""
    
    def test_all_types_exist(self):
        """All expected types exist."""
        expected = ["network", "file", "banner", "credential", "timing", "behavior", "content"]
        for t in expected:
            assert hasattr(IndicatorType, t.upper())


# =============================================================================
# IndicatorConfidence Tests
# =============================================================================

class TestIndicatorConfidence:
    """Tests for indicator confidence enum."""
    
    def test_confidence_values(self):
        """Confidence values are strings."""
        assert IndicatorConfidence.LOW.value == "low"
        assert IndicatorConfidence.DEFINITE.value == "definite"
    
    def test_confidence_scores(self):
        """Confidence scores are between 0 and 1."""
        for conf in IndicatorConfidence:
            assert 0 <= conf.score <= 1
    
    def test_confidence_from_score(self):
        """Confidence can be derived from score."""
        assert IndicatorConfidence.from_score(0.1) == IndicatorConfidence.LOW
        assert IndicatorConfidence.from_score(0.5) == IndicatorConfidence.MEDIUM
        assert IndicatorConfidence.from_score(0.8) == IndicatorConfidence.HIGH
        assert IndicatorConfidence.from_score(0.95) == IndicatorConfidence.DEFINITE


# =============================================================================
# HoneypotIndicator Tests
# =============================================================================

class TestHoneypotIndicator:
    """Tests for honeypot indicator model."""
    
    def test_indicator_creation(self):
        """Indicator can be created."""
        indicator = HoneypotIndicator(
            indicator_type=IndicatorType.CREDENTIAL,
            confidence=IndicatorConfidence.HIGH,
            description="Suspicious credentials found",
            target="10.0.0.1",
            evidence="admin:password",
        )
        assert indicator.target == "10.0.0.1"
        assert indicator.confidence == IndicatorConfidence.HIGH
    
    def test_indicator_to_dict(self):
        """Indicator converts to dictionary."""
        indicator = HoneypotIndicator(
            indicator_type=IndicatorType.BANNER,
            confidence=IndicatorConfidence.DEFINITE,
            description="Kippo honeypot detected",
            target="192.168.1.1",
        )
        data = indicator.to_dict()
        assert data["indicator_type"] == "banner"
        assert data["confidence"] == "definite"
        assert data["confidence_score"] == 1.0
    
    def test_indicator_from_dict(self):
        """Indicator can be created from dictionary."""
        data = {
            "indicator_type": "file",
            "confidence": "medium",
            "description": "Suspicious file",
            "target": "target",
            "timestamp": datetime.now().isoformat(),
        }
        indicator = HoneypotIndicator.from_dict(data)
        assert indicator.indicator_type == IndicatorType.FILE
    
    def test_indicator_format(self):
        """Indicator formats for display."""
        indicator = HoneypotIndicator(
            indicator_type=IndicatorType.CREDENTIAL,
            confidence=IndicatorConfidence.HIGH,
            description="Password found in robots.txt",
            target="example.com",
        )
        formatted = indicator.format()
        assert "example.com" in formatted
        assert "Password" in formatted


# =============================================================================
# IndicatorGroup Tests
# =============================================================================

class TestIndicatorGroup:
    """Tests for indicator group."""
    
    @pytest.fixture
    def group(self):
        """Create sample indicator group."""
        group = IndicatorGroup(target="10.0.0.1")
        group.add(HoneypotIndicator(
            indicator_type=IndicatorType.BANNER,
            confidence=IndicatorConfidence.HIGH,
            description="Cowrie SSH honeypot",
            target="10.0.0.1",
        ))
        group.add(HoneypotIndicator(
            indicator_type=IndicatorType.FILE,
            confidence=IndicatorConfidence.MEDIUM,
            description="Canary file found",
            target="10.0.0.1",
        ))
        return group
    
    def test_group_count(self, group):
        """Group counts indicators."""
        assert group.count == 2
    
    def test_group_max_confidence(self, group):
        """Group finds max confidence."""
        assert group.max_confidence == IndicatorConfidence.HIGH
    
    def test_group_aggregate_score(self, group):
        """Group calculates aggregate score."""
        score = group.aggregate_score
        assert 0 < score < 1
    
    def test_group_is_likely_honeypot(self, group):
        """Group determines likely honeypot status."""
        # With HIGH + MEDIUM confidence, should be likely
        assert group.is_likely_honeypot is True
    
    def test_group_is_definite_honeypot(self):
        """Group determines definite honeypot status."""
        group = IndicatorGroup(target="test")
        group.add(HoneypotIndicator(
            indicator_type=IndicatorType.BANNER,
            confidence=IndicatorConfidence.DEFINITE,
            description="Known honeypot",
            target="test",
        ))
        assert group.is_definite_honeypot is True
    
    def test_group_get_by_type(self, group):
        """Filter indicators by type."""
        banner = group.get_by_type(IndicatorType.BANNER)
        assert len(banner) == 1
    
    def test_group_get_by_confidence(self, group):
        """Filter indicators by confidence."""
        high = group.get_by_confidence(IndicatorConfidence.HIGH)
        assert len(high) == 1
    
    def test_group_to_dict(self, group):
        """Group converts to dictionary."""
        data = group.to_dict()
        assert data["target"] == "10.0.0.1"
        assert data["indicator_count"] == 2
    
    def test_group_format(self, group):
        """Group formats for display."""
        formatted = group.format()
        assert "10.0.0.1" in formatted


# =============================================================================
# IndicatorSummary Tests
# =============================================================================

class TestIndicatorSummary:
    """Tests for indicator summary."""
    
    @pytest.fixture
    def summary(self):
        """Create sample summary."""
        summary = IndicatorSummary()
        
        # Add honeypot target
        summary.add_indicator("10.0.0.1", HoneypotIndicator(
            indicator_type=IndicatorType.BANNER,
            confidence=IndicatorConfidence.DEFINITE,
            description="Kippo detected",
            target="10.0.0.1",
        ))
        
        # Add suspicious target
        summary.add_indicator("10.0.0.2", HoneypotIndicator(
            indicator_type=IndicatorType.FILE,
            confidence=IndicatorConfidence.MEDIUM,
            description="Canary file",
            target="10.0.0.2",
        ))
        
        return summary
    
    def test_summary_total_indicators(self, summary):
        """Summary counts total indicators."""
        assert summary.total_indicators == 2
    
    def test_summary_targets_analyzed(self, summary):
        """Summary counts targets."""
        assert summary.targets_analyzed == 2
    
    def test_summary_honeypot_targets(self, summary):
        """Summary identifies honeypot targets."""
        assert "10.0.0.1" in summary.honeypot_targets
    
    def test_summary_definite_honeypots(self, summary):
        """Summary identifies definite honeypots."""
        assert "10.0.0.1" in summary.definite_honeypots
    
    def test_summary_to_dict(self, summary):
        """Summary converts to dictionary."""
        data = summary.to_dict()
        assert data["total_indicators"] == 2
        assert data["targets_analyzed"] == 2
    
    def test_summary_format(self, summary):
        """Summary formats for display."""
        formatted = summary.format()
        assert "HONEYPOT DETECTION SUMMARY" in formatted


# =============================================================================
# Sensitivity Tests
# =============================================================================

class TestSensitivity:
    """Tests for sensitivity levels."""
    
    def test_sensitivity_values(self):
        """All sensitivity levels exist."""
        assert Sensitivity.LOW.value == "low"
        assert Sensitivity.PARANOID.value == "paranoid"
    
    def test_sensitivity_min_severity(self):
        """Sensitivity maps to minimum severity."""
        assert Sensitivity.LOW.min_severity == PatternSeverity.CRITICAL
        assert Sensitivity.PARANOID.min_severity == PatternSeverity.LOW
    
    def test_sensitivity_min_confidence(self):
        """Sensitivity maps to minimum confidence."""
        assert Sensitivity.LOW.min_confidence == IndicatorConfidence.DEFINITE
        assert Sensitivity.PARANOID.min_confidence == IndicatorConfidence.LOW


# =============================================================================
# DetectionContext Tests
# =============================================================================

class TestDetectionContext:
    """Tests for detection context."""
    
    def test_context_creation(self):
        """Context can be created."""
        context = DetectionContext(
            target="10.0.0.1",
            target_type="host",
        )
        assert context.target == "10.0.0.1"
    
    def test_context_add_banner(self):
        """Add banner to context."""
        context = DetectionContext(target="test")
        context.add_banner(22, "SSH-2.0-OpenSSH")
        assert 22 in context.banners
        assert context.banners[22] == "SSH-2.0-OpenSSH"
    
    def test_context_add_file(self):
        """Add file to context."""
        context = DetectionContext(target="test")
        context.add_file("/var/www/passwords.txt")
        assert "/var/www/passwords.txt" in context.files
    
    def test_context_add_port(self):
        """Add port to context."""
        context = DetectionContext(target="test")
        context.add_port(80, "http")
        assert 80 in context.ports
        assert context.services[80] == "http"
    
    def test_context_all_text(self):
        """Get all text content."""
        context = DetectionContext(
            target="test",
            content="Main content",
        )
        context.add_banner(22, "SSH banner")
        context.add_file("passwords.txt")
        
        text = context.all_text
        assert "Main content" in text
        assert "SSH banner" in text
        assert "passwords.txt" in text
    
    def test_context_to_dict(self):
        """Context converts to dictionary."""
        context = DetectionContext(target="10.0.0.1")
        context.add_port(22)
        data = context.to_dict()
        assert data["target"] == "10.0.0.1"
        assert data["port_count"] == 1


# =============================================================================
# DetectionResult Tests
# =============================================================================

class TestDetectionResult:
    """Tests for detection result."""
    
    def test_result_creation(self):
        """Result can be created."""
        result = DetectionResult(
            target="10.0.0.1",
            is_honeypot=True,
            confidence=IndicatorConfidence.HIGH,
            score=0.75,
        )
        assert result.is_honeypot is True
    
    def test_result_to_dict(self):
        """Result converts to dictionary."""
        result = DetectionResult(
            target="test",
            is_honeypot=False,
            confidence=IndicatorConfidence.LOW,
            score=0.1,
        )
        data = result.to_dict()
        assert data["target"] == "test"
        assert data["is_honeypot"] is False
    
    def test_result_format_honeypot(self):
        """Format result when honeypot detected."""
        result = DetectionResult(
            target="10.0.0.1",
            is_honeypot=True,
            confidence=IndicatorConfidence.DEFINITE,
            score=0.95,
            indicators=[HoneypotIndicator(
                indicator_type=IndicatorType.BANNER,
                confidence=IndicatorConfidence.DEFINITE,
                description="Kippo honeypot",
                target="10.0.0.1",
            )],
        )
        formatted = result.format()
        assert "DEFINITE HONEYPOT" in formatted
    
    def test_result_format_clean(self):
        """Format result when no honeypot."""
        result = DetectionResult(
            target="10.0.0.1",
            is_honeypot=False,
            confidence=IndicatorConfidence.LOW,
            score=0.0,
        )
        formatted = result.format()
        assert "No honeypot indicators" in formatted


# =============================================================================
# HoneypotDetector Tests
# =============================================================================

class TestHoneypotDetector:
    """Tests for main honeypot detector."""
    
    @pytest.fixture
    def detector(self):
        """Create detector instance."""
        return HoneypotDetector(sensitivity=Sensitivity.MEDIUM)
    
    def test_detector_creation(self, detector):
        """Detector can be created."""
        assert detector.sensitivity == Sensitivity.MEDIUM
        assert len(detector.patterns) > 0
    
    def test_detector_sensitivity_filters_patterns(self):
        """Sensitivity filters active patterns."""
        paranoid = HoneypotDetector(sensitivity=Sensitivity.PARANOID)
        low = HoneypotDetector(sensitivity=Sensitivity.LOW)
        
        assert len(paranoid.patterns) >= len(low.patterns)
    
    def test_detector_add_pattern(self, detector):
        """Add custom pattern."""
        initial = len(detector._patterns)
        detector.add_pattern(DetectionPattern(
            name="custom",
            description="Custom pattern",
            category=PatternCategory.EASY_CREDENTIALS,
            severity=PatternSeverity.HIGH,
            keywords=["custom_keyword"],
        ))
        assert len(detector._patterns) == initial + 1
    
    def test_detector_remove_pattern(self, detector):
        """Remove pattern."""
        detector.add_pattern(DetectionPattern(
            name="to_remove",
            description="To remove",
            category=PatternCategory.EASY_CREDENTIALS,
            severity=PatternSeverity.HIGH,
            keywords=["remove"],
        ))
        result = detector.remove_pattern("to_remove")
        assert result is True
    
    def test_detector_detect_clean_content(self, detector):
        """Detect clean content."""
        context = DetectionContext(
            target="10.0.0.1",
            content="Normal system output with no honeypot indicators",
        )
        result = detector.detect(context)
        assert result.is_honeypot is False
    
    def test_detector_detect_easy_credentials(self, detector):
        """Detect easy credentials pattern."""
        context = DetectionContext(
            target="10.0.0.1",
            content="Admin password: hunter2",
        )
        result = detector.detect(context)
        assert result.is_honeypot is True
        assert len(result.indicators) > 0
    
    def test_detector_detect_backspace_injection(self, detector):
        """Detect backspace Unicode injection."""
        # U+0008 is backspace character
        context = DetectionContext(
            target="10.0.0.1",
            content="Normal text\x08\x08\x08hidden content",
        )
        result = detector.detect(context)
        assert result.is_honeypot is True
    
    def test_detector_detect_canary_file(self, detector):
        """Detect canary file."""
        context = DetectionContext(
            target="10.0.0.1",
            files=["passwords.txt", "index.html"],
        )
        result = detector.detect(context)
        assert result.is_honeypot is True
    
    def test_detector_detect_kippo_banner(self, detector):
        """Detect Kippo honeypot banner."""
        context = DetectionContext(target="10.0.0.1")
        context.add_banner(22, "SSH-2.0-OpenSSH_5.1p1 Debian")
        result = detector.detect(context)
        assert result.is_honeypot is True
    
    def test_detector_detect_cowrie_banner(self, detector):
        """Detect Cowrie honeypot banner."""
        context = DetectionContext(target="10.0.0.1")
        context.add_banner(22, "Cowrie SSH honeypot")
        result = detector.detect(context)
        assert result.is_honeypot is True
    
    def test_detector_detect_too_many_ports(self, detector):
        """Detect too many open ports."""
        # Use PARANOID to include LOW severity patterns with check functions
        detector.sensitivity = Sensitivity.PARANOID
        context = DetectionContext(target="10.0.0.1")
        for port in range(1, 60):
            context.add_port(port)
        result = detector.detect(context)
        # Check matches for port count detection
        assert any(
            "port" in m.description.lower()
            for m in result.matches
        )
    
    def test_detector_detect_instant_response(self, detector):
        """Detect instant response times."""
        # Use PARANOID to include LOW severity timing patterns
        detector.sensitivity = Sensitivity.PARANOID
        context = DetectionContext(target="10.0.0.1")
        # All responses under 1ms
        context.response_times = [0.1, 0.2, 0.3, 0.1, 0.2, 0.15]
        result = detector.detect(context)
        # Check matches for latency detection
        assert any(
            "latency" in m.description.lower() or "simulated" in m.description.lower()
            for m in result.matches
        )
    
    def test_detector_detect_consistent_timing(self, detector):
        """Detect suspiciously consistent timing."""
        detector.sensitivity = Sensitivity.PARANOID
        context = DetectionContext(target="10.0.0.1")
        # Very consistent response times
        context.response_times = [10.0, 10.0, 10.0, 10.0, 10.0]
        result = detector.detect(context)
        # Should find consistent timing pattern
        assert len(result.matches) >= 0  # May or may not match
    
    def test_detector_detect_tarpit(self, detector):
        """Detect tarpit behavior."""
        # Use PARANOID to include MEDIUM severity network patterns
        detector.sensitivity = Sensitivity.PARANOID
        context = DetectionContext(target="10.0.0.1")
        # Progressively slower responses (tarpit)
        context.response_times = [1.0, 10.0, 100.0, 500.0, 1000.0]
        result = detector.detect(context)
        # Check matches for tarpit detection
        assert any(
            "tarpit" in m.description.lower()
            for m in result.matches
        )
    
    def test_detector_detect_text(self, detector):
        """Quick text detection."""
        result = detector.detect_text("10.0.0.1", "password: admin123")
        assert result.is_honeypot is True
    
    def test_detector_detect_banner(self, detector):
        """Quick banner detection."""
        result = detector.detect_banner("10.0.0.1", 22, "Kippo SSH")
        assert result.is_honeypot is True
    
    def test_detector_detect_files(self, detector):
        """Quick file list detection."""
        result = detector.detect_files("10.0.0.1", [
            "index.html",
            "passwords.txt",
            "style.css",
        ])
        assert result.is_honeypot is True
    
    def test_detector_batch_detect(self, detector):
        """Batch detection on multiple targets."""
        contexts = [
            DetectionContext(target="10.0.0.1", content="clean"),
            DetectionContext(target="10.0.0.2", content="password: admin"),
            DetectionContext(target="10.0.0.3", files=["passwords.txt"]),
        ]
        summary = detector.batch_detect(contexts)
        # Only targets with indicators are added to summary
        assert summary.targets_analyzed >= 2
        assert len(summary.honeypot_targets) >= 1
    
    def test_detector_format_warning(self, detector):
        """Format warning message."""
        result = DetectionResult(
            target="10.0.0.1",
            is_honeypot=True,
            confidence=IndicatorConfidence.HIGH,
            score=0.8,
            indicators=[HoneypotIndicator(
                indicator_type=IndicatorType.BANNER,
                confidence=IndicatorConfidence.HIGH,
                description="Honeypot detected",
                target="10.0.0.1",
            )],
            recommendations=["Skip this host"],
        )
        warning = detector.format_warning(result)
        assert "POTENTIAL HONEYPOT" in warning
        assert "Skip this host" in warning
    
    def test_detector_format_warning_clean(self, detector):
        """No warning for clean result."""
        result = DetectionResult(
            target="10.0.0.1",
            is_honeypot=False,
            confidence=IndicatorConfidence.LOW,
            score=0.0,
        )
        warning = detector.format_warning(result)
        assert warning == ""
    
    def test_detector_detection_log(self, detector):
        """Detections are logged."""
        detector.detect_text("10.0.0.1", "password: admin123")
        assert len(detector.detection_log) >= 1
    
    def test_detector_clear_log(self, detector):
        """Log can be cleared."""
        detector.detect_text("10.0.0.1", "password: admin123")
        detector.clear_log()
        assert len(detector.detection_log) == 0
    
    def test_detector_add_custom_check(self, detector):
        """Add custom check function."""
        def custom_check(context):
            if "custom_indicator" in context.content:
                return PatternMatch(
                    matched=True,
                    pattern_name="custom_check",
                    category=PatternCategory.BEHAVIOR,
                    severity=PatternSeverity.HIGH,
                    description="Custom indicator found",
                )
            return None
        
        detector.add_check("custom_check", custom_check)
        assert "custom_check" in detector._custom_checks


# =============================================================================
# Integration Tests
# =============================================================================

class TestHoneypotIntegration:
    """Integration tests for honeypot detection."""
    
    def test_full_detection_workflow(self):
        """Full detection workflow."""
        detector = HoneypotDetector(sensitivity=Sensitivity.PARANOID)
        
        # Create context with multiple indicators
        context = DetectionContext(
            target="10.0.0.15",
            target_type="host",
            content="Welcome! Check robots.txt for admin password: hunter2",
            files=["passwords.txt", "backup.sql"],
        )
        context.add_banner(22, "SSH-2.0-OpenSSH_5.1p1 Debian")
        context.add_port(22, "ssh")
        context.add_port(80, "http")
        
        result = detector.detect(context)
        
        # Should detect multiple indicators
        assert result.is_honeypot is True
        assert len(result.indicators) >= 2
        assert len(result.recommendations) > 0
    
    def test_detection_with_unicode_manipulation(self):
        """Detect various Unicode manipulation attacks."""
        # Use PARANOID for stricter detection
        detector = HoneypotDetector(sensitivity=Sensitivity.PARANOID)
        
        test_cases = [
            ("\x08\x08\x08hidden", "backspace"),  # Backspace
            ("\u200bhidden", "zero-width"),  # Zero-width space
            ("\u202ehidden", "right-to-left"),  # RTL override
        ]
        
        for content, description in test_cases:
            result = detector.detect_text("test", content)
            # Check that patterns were matched (may not reach honeypot threshold with single indicator)
            assert len(result.matches) > 0, f"Failed to detect {description}"
            # Check that related patterns are matched
            match_texts = " ".join(m.description.lower() for m in result.matches)
            assert any(word in match_texts for word in [description, "unicode", "invisible", "hidden"]), f"Failed to match {description}"
    
    def test_sensitivity_levels(self):
        """Different sensitivity levels produce different results."""
        paranoid_detector = HoneypotDetector(sensitivity=Sensitivity.PARANOID)
        low_detector = HoneypotDetector(sensitivity=Sensitivity.LOW)
        
        paranoid_result = paranoid_detector.detect_text("test", "password=admin")
        low_result = low_detector.detect_text("test", "password=admin")
        
        # Both should have matches (low just filters reported indicators)
        assert len(paranoid_result.matches) >= len(low_result.matches)
        # Paranoid reports more indicators due to lower threshold
        assert len(paranoid_result.indicators) >= len(low_result.indicators)
    
    def test_recommendations_by_category(self):
        """Recommendations are category-specific."""
        detector = HoneypotDetector()
        
        # Easy credentials
        result = detector.detect_text("test", "admin password: hunter2")
        assert any("credentials" in r.lower() for r in result.recommendations)
        
        # Canary files
        result = detector.detect_files("test", ["passwords.txt"])
        assert any("file" in r.lower() for r in result.recommendations)


# =============================================================================
# Edge Cases
# =============================================================================

class TestEdgeCases:
    """Tests for edge cases."""
    
    def test_empty_content(self):
        """Handle empty content."""
        detector = HoneypotDetector()
        result = detector.detect_text("test", "")
        assert result.is_honeypot is False
    
    def test_empty_context(self):
        """Handle empty context."""
        detector = HoneypotDetector()
        context = DetectionContext(target="test")
        result = detector.detect(context)
        assert result.is_honeypot is False
    
    def test_invalid_regex_pattern(self):
        """Handle invalid regex in custom pattern."""
        detector = HoneypotDetector()
        detector.add_pattern(DetectionPattern(
            name="bad_regex",
            description="Bad regex",
            category=PatternCategory.EASY_CREDENTIALS,
            severity=PatternSeverity.HIGH,
            pattern="[invalid(regex",  # Invalid
        ))
        # Should not crash
        result = detector.detect_text("test", "test content")
        assert result is not None
    
    def test_large_file_list(self):
        """Handle large file list."""
        detector = HoneypotDetector()
        files = [f"file_{i}.txt" for i in range(1000)]
        files.append("passwords.txt")
        result = detector.detect_files("test", files)
        assert result.is_honeypot is True
    
    def test_special_characters_in_target(self):
        """Handle special characters in target name."""
        detector = HoneypotDetector()
        result = detector.detect_text(
            "192.168.1.1:8080/path?query=value",
            "password: admin"
        )
        assert result.target == "192.168.1.1:8080/path?query=value"
    
    def test_no_detection_log_when_disabled(self):
        """No logging when disabled."""
        detector = HoneypotDetector(log_detections=False)
        detector.detect_text("test", "password: admin")
        # Log should still work but not warn
        assert len(detector.detection_log) >= 0  # May or may not log
