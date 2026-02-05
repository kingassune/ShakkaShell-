"""Tests for Tool-Aware Command Generation module.

Tests tool detection, registry, and fallback functionality.
"""

import pytest
from unittest.mock import AsyncMock, patch, MagicMock

from shakka.tools import (
    ToolDetector,
    DetectedTool,
    ToolStatus,
    ToolRegistry,
    ToolInfo,
    ToolCategory,
    FallbackManager,
    FallbackRule,
)


# =============================================================================
# ToolCategory Tests
# =============================================================================

class TestToolCategory:
    """Tests for tool category enum."""
    
    def test_all_categories_exist(self):
        """All expected categories exist."""
        expected = [
            "reconnaissance",
            "scanning",
            "enumeration",
            "exploitation",
            "post_exploitation",
            "password_cracking",
            "web_testing",
            "wireless",
            "forensics",
            "utility",
        ]
        for cat in expected:
            assert hasattr(ToolCategory, cat.upper())
    
    def test_category_values(self):
        """Category values are strings."""
        assert ToolCategory.SCANNING.value == "scanning"
        assert ToolCategory.EXPLOITATION.value == "exploitation"


# =============================================================================
# ToolInfo Tests
# =============================================================================

class TestToolInfo:
    """Tests for tool information model."""
    
    def test_tool_info_creation(self):
        """Tool info can be created."""
        tool = ToolInfo(
            name="nmap",
            description="Network scanner",
            category=ToolCategory.SCANNING,
            command="nmap",
        )
        assert tool.name == "nmap"
        assert tool.command == "nmap"
        assert tool.category == ToolCategory.SCANNING
    
    def test_tool_info_with_full_details(self):
        """Tool info with all fields."""
        tool = ToolInfo(
            name="sqlmap",
            description="SQL injection tool",
            category=ToolCategory.WEB_TESTING,
            command="sqlmap",
            version_arg="--version",
            install_apt="sqlmap",
            install_brew="sqlmap",
            install_pip="sqlmap",
            install_url="https://sqlmap.org",
            alternatives=["ghauri"],
            common_args=["-u", "--dbs"],
        )
        assert tool.install_apt == "sqlmap"
        assert "ghauri" in tool.alternatives
    
    def test_tool_info_to_dict(self):
        """Tool info converts to dictionary."""
        tool = ToolInfo(
            name="test",
            description="Test tool",
            category=ToolCategory.UTILITY,
            command="test",
        )
        data = tool.to_dict()
        assert data["name"] == "test"
        assert data["category"] == "utility"
    
    def test_tool_info_from_dict(self):
        """Tool info can be created from dictionary."""
        data = {
            "name": "from_dict",
            "description": "From dict tool",
            "category": "scanning",
            "command": "fromdict",
        }
        tool = ToolInfo.from_dict(data)
        assert tool.name == "from_dict"
        assert tool.category == ToolCategory.SCANNING
    
    def test_get_install_command_linux(self):
        """Get install command for Linux."""
        tool = ToolInfo(
            name="test",
            description="Test",
            category=ToolCategory.UTILITY,
            command="test",
            install_apt="test-package",
        )
        cmd = tool.get_install_command("linux")
        assert "apt-get install" in cmd
        assert "test-package" in cmd
    
    def test_get_install_command_darwin(self):
        """Get install command for macOS."""
        tool = ToolInfo(
            name="test",
            description="Test",
            category=ToolCategory.UTILITY,
            command="test",
            install_brew="test-brew",
        )
        cmd = tool.get_install_command("darwin")
        assert "brew install" in cmd
        assert "test-brew" in cmd
    
    def test_get_install_command_pip(self):
        """Get pip install command."""
        tool = ToolInfo(
            name="test",
            description="Test",
            category=ToolCategory.UTILITY,
            command="test",
            install_pip="test-pip",
        )
        cmd = tool.get_install_command("pip")
        assert "pip install" in cmd
        assert "test-pip" in cmd
    
    def test_get_install_command_none(self):
        """Returns None when no install method."""
        tool = ToolInfo(
            name="test",
            description="Test",
            category=ToolCategory.UTILITY,
            command="test",
        )
        cmd = tool.get_install_command("linux")
        assert cmd is None


# =============================================================================
# ToolRegistry Tests
# =============================================================================

class TestToolRegistry:
    """Tests for tool registry."""
    
    @pytest.fixture
    def registry(self):
        """Create registry instance."""
        return ToolRegistry()
    
    def test_registry_has_defaults(self, registry):
        """Registry has default tools."""
        assert registry.count > 0
        assert registry.get("nmap") is not None
    
    def test_registry_get(self, registry):
        """Get tool by name."""
        nmap = registry.get("nmap")
        assert nmap is not None
        assert nmap.name == "nmap"
    
    def test_registry_get_case_insensitive(self, registry):
        """Get is case insensitive."""
        assert registry.get("NMAP") is not None
        assert registry.get("Nmap") is not None
    
    def test_registry_get_unknown(self, registry):
        """Get unknown tool returns None."""
        assert registry.get("unknown_tool_xyz") is None
    
    def test_registry_register(self, registry):
        """Register custom tool."""
        custom = ToolInfo(
            name="custom_tool",
            description="Custom test tool",
            category=ToolCategory.UTILITY,
            command="custom",
        )
        registry.register(custom)
        assert registry.get("custom_tool") is not None
    
    def test_registry_unregister(self, registry):
        """Unregister a tool."""
        assert registry.get("nmap") is not None
        result = registry.unregister("nmap")
        assert result is True
        assert registry.get("nmap") is None
    
    def test_registry_unregister_unknown(self, registry):
        """Unregister unknown tool returns False."""
        result = registry.unregister("unknown_xyz")
        assert result is False
    
    def test_registry_get_all(self, registry):
        """Get all tools."""
        tools = registry.get_all()
        assert len(tools) > 0
        assert all(isinstance(t, ToolInfo) for t in tools)
    
    def test_registry_get_by_category(self, registry):
        """Get tools by category."""
        scanning = registry.get_by_category(ToolCategory.SCANNING)
        assert len(scanning) > 0
        assert all(t.category == ToolCategory.SCANNING for t in scanning)
    
    def test_registry_get_by_command(self, registry):
        """Get tool by command name."""
        tool = registry.get_by_command("nmap")
        assert tool is not None
        assert tool.name == "nmap"
    
    def test_registry_find_alternatives(self, registry):
        """Find alternatives for a tool."""
        alternatives = registry.find_alternatives("nmap")
        assert len(alternatives) > 0
    
    def test_registry_search(self, registry):
        """Search for tools."""
        results = registry.search("scan")
        assert len(results) > 0
    
    def test_registry_search_no_results(self, registry):
        """Search with no results."""
        results = registry.search("zzzznonexistent")
        assert len(results) == 0


# =============================================================================
# ToolStatus Tests
# =============================================================================

class TestToolStatus:
    """Tests for tool status enum."""
    
    def test_status_values(self):
        """All status values exist."""
        assert ToolStatus.AVAILABLE.value == "available"
        assert ToolStatus.NOT_FOUND.value == "not_found"
        assert ToolStatus.ERROR.value == "error"
        assert ToolStatus.UNKNOWN.value == "unknown"


# =============================================================================
# DetectedTool Tests
# =============================================================================

class TestDetectedTool:
    """Tests for detected tool model."""
    
    @pytest.fixture
    def sample_info(self):
        """Create sample tool info."""
        return ToolInfo(
            name="test_tool",
            description="Test tool",
            category=ToolCategory.UTILITY,
            command="test",
        )
    
    def test_detected_tool_creation(self, sample_info):
        """Detected tool can be created."""
        detected = DetectedTool(
            info=sample_info,
            status=ToolStatus.AVAILABLE,
            version="1.0.0",
            path="/usr/bin/test",
        )
        assert detected.info.name == "test_tool"
        assert detected.status == ToolStatus.AVAILABLE
        assert detected.version == "1.0.0"
    
    def test_detected_tool_to_dict(self, sample_info):
        """Detected tool converts to dictionary."""
        detected = DetectedTool(
            info=sample_info,
            status=ToolStatus.AVAILABLE,
            version="2.0",
        )
        data = detected.to_dict()
        assert data["name"] == "test_tool"
        assert data["status"] == "available"
        assert data["version"] == "2.0"
    
    def test_detected_tool_format_available(self, sample_info):
        """Format available tool."""
        detected = DetectedTool(
            info=sample_info,
            status=ToolStatus.AVAILABLE,
            version="1.0",
        )
        formatted = detected.format()
        assert "✓" in formatted
        assert "test_tool" in formatted
        assert "1.0" in formatted
    
    def test_detected_tool_format_not_found(self, sample_info):
        """Format not found tool."""
        detected = DetectedTool(
            info=sample_info,
            status=ToolStatus.NOT_FOUND,
        )
        formatted = detected.format()
        assert "✗" in formatted
        assert "not found" in formatted
    
    def test_detected_tool_format_error(self, sample_info):
        """Format error tool."""
        detected = DetectedTool(
            info=sample_info,
            status=ToolStatus.ERROR,
            error_message="failed to run",
        )
        formatted = detected.format()
        assert "⚠" in formatted


# =============================================================================
# ToolDetector Tests
# =============================================================================

class TestToolDetector:
    """Tests for tool detector."""
    
    @pytest.fixture
    def detector(self):
        """Create detector instance."""
        return ToolDetector()
    
    def test_detector_has_registry(self, detector):
        """Detector has a registry."""
        assert detector.registry is not None
        assert detector.registry.count > 0
    
    @pytest.mark.asyncio
    async def test_detect_available_tool(self, detector):
        """Detect an available tool (like ls or echo)."""
        # Create a minimal registry with a common tool
        registry = ToolRegistry()
        registry._tools.clear()
        registry.register(ToolInfo(
            name="echo",
            description="Echo text",
            category=ToolCategory.UTILITY,
            command="echo",
            version_arg="hello",  # echo just prints its args
        ))
        
        detector = ToolDetector(registry)
        result = await detector.detect("echo")
        
        assert result is not None
        assert result.status == ToolStatus.AVAILABLE
        assert result.path != ""
    
    @pytest.mark.asyncio
    async def test_detect_missing_tool(self, detector):
        """Detect a missing tool."""
        # Create registry with non-existent tool
        registry = ToolRegistry()
        registry._tools.clear()
        registry.register(ToolInfo(
            name="nonexistent_tool_xyz",
            description="Does not exist",
            category=ToolCategory.UTILITY,
            command="nonexistent_tool_xyz_12345",
        ))
        
        detector = ToolDetector(registry)
        result = await detector.detect("nonexistent_tool_xyz")
        
        assert result is not None
        assert result.status == ToolStatus.NOT_FOUND
    
    @pytest.mark.asyncio
    async def test_detect_unknown_tool(self, detector):
        """Detect tool not in registry."""
        result = await detector.detect("not_in_registry_xyz")
        assert result is None
    
    @pytest.mark.asyncio
    async def test_detect_all(self, detector):
        """Detect all tools."""
        # Use minimal registry for speed
        registry = ToolRegistry()
        registry._tools.clear()
        registry.register(ToolInfo(
            name="echo",
            description="Echo",
            category=ToolCategory.UTILITY,
            command="echo",
            version_arg="test",
        ))
        registry.register(ToolInfo(
            name="missing",
            description="Missing",
            category=ToolCategory.UTILITY,
            command="missing_xyz_123",
        ))
        
        detector = ToolDetector(registry)
        results = await detector.detect_all()
        
        assert len(results) == 2
    
    @pytest.mark.asyncio
    async def test_detect_all_cached(self, detector):
        """Detection results are cached."""
        registry = ToolRegistry()
        registry._tools.clear()
        registry.register(ToolInfo(
            name="echo",
            description="Echo",
            category=ToolCategory.UTILITY,
            command="echo",
            version_arg="test",
        ))
        
        detector = ToolDetector(registry)
        results1 = await detector.detect_all()
        results2 = await detector.detect_all()
        
        # Same results from cache
        assert len(results1) == len(results2)
    
    def test_get_cached(self, detector):
        """Get cached detection result."""
        # No cache initially
        result = detector.get("nmap")
        assert result is None
    
    def test_is_available(self, detector):
        """Check if tool is available."""
        # Before detection
        assert detector.is_available("nmap") is False
    
    @pytest.mark.asyncio
    async def test_available_tools_property(self):
        """Get available tools."""
        registry = ToolRegistry()
        registry._tools.clear()
        registry.register(ToolInfo(
            name="echo",
            description="Echo",
            category=ToolCategory.UTILITY,
            command="echo",
            version_arg="test",
        ))
        
        detector = ToolDetector(registry)
        await detector.detect_all()
        
        available = detector.available_tools
        assert len(available) >= 1
    
    @pytest.mark.asyncio
    async def test_missing_tools_property(self):
        """Get missing tools."""
        registry = ToolRegistry()
        registry._tools.clear()
        registry.register(ToolInfo(
            name="missing",
            description="Missing",
            category=ToolCategory.UTILITY,
            command="missing_xyz_123",
        ))
        
        detector = ToolDetector(registry)
        await detector.detect_all()
        
        missing = detector.missing_tools
        assert len(missing) >= 1
    
    @pytest.mark.asyncio
    async def test_get_by_category(self):
        """Get detected tools by category."""
        registry = ToolRegistry()
        registry._tools.clear()
        registry.register(ToolInfo(
            name="echo",
            description="Echo",
            category=ToolCategory.UTILITY,
            command="echo",
            version_arg="test",
        ))
        
        detector = ToolDetector(registry)
        await detector.detect_all()
        
        utility = detector.get_by_category(ToolCategory.UTILITY)
        assert len(utility) >= 1
    
    def test_suggest_installation(self, detector):
        """Get installation suggestion."""
        suggestion = detector.suggest_installation("nmap", "linux")
        assert suggestion is not None
        assert "apt" in suggestion
    
    def test_clear_cache(self, detector):
        """Clear detection cache."""
        detector._detected["test"] = MagicMock()
        detector.clear_cache()
        assert len(detector._detected) == 0
    
    @pytest.mark.asyncio
    async def test_format_report(self):
        """Format detection report."""
        registry = ToolRegistry()
        registry._tools.clear()
        registry.register(ToolInfo(
            name="echo",
            description="Echo",
            category=ToolCategory.UTILITY,
            command="echo",
            version_arg="test",
        ))
        
        detector = ToolDetector(registry)
        await detector.detect_all()
        
        report = detector.format_report()
        assert "Detected Tools" in report
        assert "available" in report or "✓" in report


# =============================================================================
# FallbackRule Tests
# =============================================================================

class TestFallbackRule:
    """Tests for fallback rule model."""
    
    def test_rule_creation(self):
        """Rule can be created."""
        rule = FallbackRule(
            source_tool="masscan",
            target_tool="nmap",
            description="Use nmap instead",
            pattern=r"masscan (.+)",
            replacement=r"nmap \1",
        )
        assert rule.source_tool == "masscan"
        assert rule.target_tool == "nmap"
    
    def test_rule_to_dict(self):
        """Rule converts to dictionary."""
        rule = FallbackRule(
            source_tool="a",
            target_tool="b",
            description="Test",
            pattern="a",
            replacement="b",
        )
        data = rule.to_dict()
        assert data["source_tool"] == "a"
        assert data["target_tool"] == "b"
    
    def test_rule_from_dict(self):
        """Rule can be created from dictionary."""
        data = {
            "source_tool": "x",
            "target_tool": "y",
            "description": "From dict",
            "pattern": "x",
            "replacement": "y",
        }
        rule = FallbackRule.from_dict(data)
        assert rule.source_tool == "x"
    
    def test_rule_apply_match(self):
        """Apply rule with matching pattern."""
        rule = FallbackRule(
            source_tool="test",
            target_tool="alt",
            description="Test",
            pattern=r"test (\S+)",
            replacement=r"alt \1",
        )
        result = rule.apply("test target")
        assert result == "alt target"
    
    def test_rule_apply_no_match(self):
        """Apply rule with non-matching pattern."""
        rule = FallbackRule(
            source_tool="test",
            target_tool="alt",
            description="Test",
            pattern=r"test (\S+)",
            replacement=r"alt \1",
        )
        result = rule.apply("other command")
        assert result is None


# =============================================================================
# FallbackManager Tests
# =============================================================================

class TestFallbackManager:
    """Tests for fallback manager."""
    
    @pytest.fixture
    def manager(self):
        """Create manager instance."""
        return FallbackManager()
    
    def test_manager_has_default_rules(self, manager):
        """Manager has default rules."""
        rules = manager.get_all_rules()
        assert len(rules) > 0
    
    def test_add_rule(self, manager):
        """Add custom rule."""
        initial_count = len(manager.get_all_rules())
        manager.add_rule(FallbackRule(
            source_tool="custom",
            target_tool="other",
            description="Custom rule",
            pattern="custom",
            replacement="other",
        ))
        assert len(manager.get_all_rules()) == initial_count + 1
    
    def test_remove_rule(self, manager):
        """Remove a rule."""
        # Add a rule first
        manager.add_rule(FallbackRule(
            source_tool="remove_me",
            target_tool="target",
            description="To remove",
            pattern="remove_me",
            replacement="target",
        ))
        
        result = manager.remove_rule("remove_me", "target")
        assert result is True
    
    def test_remove_rule_not_found(self, manager):
        """Remove non-existent rule."""
        result = manager.remove_rule("nonexistent", "also_nonexistent")
        assert result is False
    
    def test_set_available(self, manager):
        """Mark tool as available."""
        manager.set_available("nmap")
        assert manager.is_available("nmap") is True
    
    def test_set_unavailable(self, manager):
        """Mark tool as unavailable."""
        manager.set_available("test")
        manager.set_unavailable("test")
        assert manager.is_available("test") is False
    
    def test_get_fallback(self, manager):
        """Get fallback command."""
        manager.set_unavailable("masscan")
        manager.set_available("nmap")
        
        result = manager.get_fallback("masscan 10.0.0.1")
        
        assert result is not None
        new_cmd, old_tool, new_tool = result
        assert "nmap" in new_cmd
        assert old_tool == "masscan"
        assert new_tool == "nmap"
    
    def test_get_fallback_tool_available(self, manager):
        """No fallback when tool is available."""
        manager.set_available("nmap")
        
        result = manager.get_fallback("nmap -sV target")
        assert result is None
    
    def test_get_fallback_no_alternative(self, manager):
        """No fallback when no alternative available."""
        manager.set_unavailable("masscan")
        manager.set_unavailable("nmap")  # Alternative also unavailable
        
        result = manager.get_fallback("masscan 10.0.0.1")
        assert result is None
    
    def test_get_rules_for_tool(self, manager):
        """Get rules for specific tool."""
        rules = manager.get_rules_for_tool("masscan")
        assert len(rules) > 0
        assert all(r.source_tool == "masscan" for r in rules)
    
    def test_suggest_alternatives(self, manager):
        """Suggest alternatives for tool."""
        manager.set_available("nmap")
        manager.set_available("rustscan")
        
        alternatives = manager.suggest_alternatives("masscan")
        assert len(alternatives) > 0
    
    def test_format_suggestion(self, manager):
        """Format suggestion message."""
        message = manager.format_suggestion("nmap")
        assert "nmap" in message
        assert "not available" in message
    
    def test_clear(self, manager):
        """Clear availability info."""
        manager.set_available("test")
        manager.clear()
        assert manager.is_available("test") is False


# =============================================================================
# Integration Tests
# =============================================================================

class TestToolAwareIntegration:
    """Integration tests for tool-aware command generation."""
    
    @pytest.mark.asyncio
    async def test_full_detection_and_fallback_workflow(self):
        """Full workflow: detect tools and find fallbacks."""
        # Create registry with limited tools
        registry = ToolRegistry()
        registry._tools.clear()
        
        registry.register(ToolInfo(
            name="echo",
            description="Echo text",
            category=ToolCategory.UTILITY,
            command="echo",
            version_arg="test",
            alternatives=["printf"],
        ))
        
        registry.register(ToolInfo(
            name="missing_tool",
            description="Not installed",
            category=ToolCategory.UTILITY,
            command="missing_xyz_123",
            alternatives=["echo"],
        ))
        
        # Detect tools
        detector = ToolDetector(registry)
        await detector.detect_all()
        
        # Setup fallback manager
        manager = FallbackManager(registry)
        
        for tool in detector.available_tools:
            manager.set_available(tool.info.name)
        for tool in detector.missing_tools:
            manager.set_unavailable(tool.info.name)
        
        # Verify
        assert detector.is_available("echo") is True
        assert detector.is_available("missing_tool") is False
    
    @pytest.mark.asyncio
    async def test_version_parsing(self):
        """Version parsing works correctly."""
        detector = ToolDetector()
        
        # Test version parsing
        assert detector._parse_version("version 1.2.3") == "1.2.3"
        assert detector._parse_version("v2.0.0") == "2.0.0"
        assert detector._parse_version("tool 3.14") == "3.14"
    
    def test_gobuster_to_ffuf_fallback(self):
        """Gobuster to ffuf fallback works."""
        manager = FallbackManager()
        manager.set_unavailable("gobuster")
        manager.set_available("ffuf")
        
        result = manager.get_fallback(
            "gobuster dir -u http://target -w wordlist.txt"
        )
        
        assert result is not None
        new_cmd, old, new = result
        assert "ffuf" in new_cmd
        assert "FUZZ" in new_cmd
    
    def test_ffuf_to_gobuster_fallback(self):
        """Ffuf to gobuster fallback works."""
        manager = FallbackManager()
        manager.set_unavailable("ffuf")
        manager.set_available("gobuster")
        
        result = manager.get_fallback(
            "ffuf -u http://target/FUZZ -w wordlist.txt"
        )
        
        assert result is not None
        new_cmd, old, new = result
        assert "gobuster" in new_cmd
        assert "dir" in new_cmd


# =============================================================================
# Edge Cases
# =============================================================================

class TestEdgeCases:
    """Tests for edge cases and error handling."""
    
    def test_empty_command(self):
        """Handle empty command."""
        manager = FallbackManager()
        result = manager.get_fallback("")
        assert result is None
    
    def test_whitespace_command(self):
        """Handle whitespace command."""
        manager = FallbackManager()
        result = manager.get_fallback("   ")
        assert result is None
    
    def test_invalid_regex_in_rule(self):
        """Handle invalid regex in rule."""
        rule = FallbackRule(
            source_tool="test",
            target_tool="alt",
            description="Bad regex",
            pattern="[invalid(regex",  # Invalid regex
            replacement="alt",
        )
        result = rule.apply("test input")
        assert result is None  # Should not crash
    
    def test_registry_empty(self):
        """Handle empty registry."""
        registry = ToolRegistry()
        registry._tools.clear()
        
        assert registry.count == 0
        assert registry.get("anything") is None
        assert registry.get_all() == []
    
    def test_detector_with_empty_registry(self):
        """Detector with empty registry."""
        registry = ToolRegistry()
        registry._tools.clear()
        
        detector = ToolDetector(registry)
        assert len(detector.available_tools) == 0
