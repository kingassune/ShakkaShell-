"""Tool detection for installed security tools.

Provides automatic detection of installed tools with version information.
"""

import asyncio
import shutil
import re
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Optional

from .registry import ToolRegistry, ToolInfo, ToolCategory


class ToolStatus(str, Enum):
    """Status of a detected tool."""
    
    AVAILABLE = "available"     # Tool is installed and working
    NOT_FOUND = "not_found"     # Tool is not installed
    ERROR = "error"             # Tool found but error on execution
    UNKNOWN = "unknown"         # Status not yet checked


@dataclass
class DetectedTool:
    """A detected tool with version and status.
    
    Contains information about an installed tool.
    """
    
    info: ToolInfo
    status: ToolStatus = ToolStatus.UNKNOWN
    version: str = ""
    path: str = ""
    last_checked: str = field(default_factory=lambda: datetime.now().isoformat())
    error_message: str = ""
    
    def to_dict(self) -> dict:
        """Convert to dictionary."""
        return {
            "name": self.info.name,
            "status": self.status.value,
            "version": self.version,
            "path": self.path,
            "last_checked": self.last_checked,
            "error_message": self.error_message,
            "category": self.info.category.value,
        }
    
    def format(self) -> str:
        """Format for display.
        
        Returns:
            Formatted string.
        """
        status_icons = {
            ToolStatus.AVAILABLE: "✓",
            ToolStatus.NOT_FOUND: "✗",
            ToolStatus.ERROR: "⚠",
            ToolStatus.UNKNOWN: "?",
        }
        icon = status_icons.get(self.status, "?")
        
        if self.status == ToolStatus.AVAILABLE:
            version_str = f"({self.version})" if self.version else ""
            return f"  {icon} {self.info.name} {version_str}"
        elif self.status == ToolStatus.NOT_FOUND:
            return f"  {icon} {self.info.name} (not found)"
        else:
            return f"  {icon} {self.info.name} ({self.error_message or 'error'})"


class ToolDetector:
    """Detects installed security tools.
    
    Scans the system for installed tools and caches results.
    
    Example:
        detector = ToolDetector()
        await detector.detect_all()
        
        for tool in detector.available_tools:
            print(f"{tool.info.name}: {tool.version}")
    """
    
    def __init__(self, registry: Optional[ToolRegistry] = None):
        """Initialize the detector.
        
        Args:
            registry: Optional tool registry. Uses default if not provided.
        """
        self.registry = registry or ToolRegistry()
        self._detected: dict[str, DetectedTool] = {}
        self._detection_complete = False
    
    async def detect_all(self, force: bool = False) -> list[DetectedTool]:
        """Detect all registered tools.
        
        Args:
            force: Force re-detection even if cached.
            
        Returns:
            List of detected tool results.
        """
        if self._detection_complete and not force:
            return list(self._detected.values())
        
        tasks = []
        for tool in self.registry.get_all():
            tasks.append(self._detect_tool(tool))
        
        results = await asyncio.gather(*tasks)
        
        for result in results:
            self._detected[result.info.name.lower()] = result
        
        self._detection_complete = True
        return results
    
    async def detect(self, name: str) -> Optional[DetectedTool]:
        """Detect a specific tool.
        
        Args:
            name: Tool name to detect.
            
        Returns:
            Detection result or None if not in registry.
        """
        tool = self.registry.get(name)
        if not tool:
            return None
        
        result = await self._detect_tool(tool)
        self._detected[name.lower()] = result
        return result
    
    async def _detect_tool(self, tool: ToolInfo) -> DetectedTool:
        """Detect a single tool.
        
        Args:
            tool: Tool info to detect.
            
        Returns:
            Detection result.
        """
        # Check if tool exists in PATH
        path = shutil.which(tool.command)
        
        if not path:
            return DetectedTool(
                info=tool,
                status=ToolStatus.NOT_FOUND,
            )
        
        # Try to get version
        try:
            version = await self._get_version(tool, path)
            return DetectedTool(
                info=tool,
                status=ToolStatus.AVAILABLE,
                version=version,
                path=path,
            )
        except Exception as e:
            return DetectedTool(
                info=tool,
                status=ToolStatus.ERROR,
                path=path,
                error_message=str(e),
            )
    
    async def _get_version(self, tool: ToolInfo, path: str) -> str:
        """Get tool version.
        
        Args:
            tool: Tool info.
            path: Path to tool binary.
            
        Returns:
            Version string.
        """
        try:
            proc = await asyncio.create_subprocess_exec(
                path,
                tool.version_arg,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(),
                timeout=5.0,
            )
            
            output = stdout.decode() + stderr.decode()
            version = self._parse_version(output)
            return version
        except asyncio.TimeoutError:
            return "timeout"
        except Exception:
            return ""
    
    def _parse_version(self, output: str) -> str:
        """Parse version from command output.
        
        Args:
            output: Command output.
            
        Returns:
            Extracted version string.
        """
        # Common version patterns
        patterns = [
            r"v?(\d+\.\d+(?:\.\d+)?)",  # X.Y.Z or X.Y
            r"version\s+(\d+\.\d+(?:\.\d+)?)",
            r"(\d+\.\d+(?:\.\d+)?)\s*$",
        ]
        
        for pattern in patterns:
            match = re.search(pattern, output, re.IGNORECASE)
            if match:
                return match.group(1)
        
        # Return first line if no version found
        first_line = output.strip().split("\n")[0]
        return first_line[:50] if first_line else ""
    
    def get(self, name: str) -> Optional[DetectedTool]:
        """Get cached detection result.
        
        Args:
            name: Tool name.
            
        Returns:
            Cached result or None.
        """
        return self._detected.get(name.lower())
    
    def is_available(self, name: str) -> bool:
        """Check if a tool is available.
        
        Args:
            name: Tool name.
            
        Returns:
            True if tool is installed and working.
        """
        result = self._detected.get(name.lower())
        return result is not None and result.status == ToolStatus.AVAILABLE
    
    @property
    def available_tools(self) -> list[DetectedTool]:
        """Get all available tools.
        
        Returns:
            List of available detected tools.
        """
        return [
            t for t in self._detected.values()
            if t.status == ToolStatus.AVAILABLE
        ]
    
    @property
    def missing_tools(self) -> list[DetectedTool]:
        """Get all missing tools.
        
        Returns:
            List of tools that are not installed.
        """
        return [
            t for t in self._detected.values()
            if t.status == ToolStatus.NOT_FOUND
        ]
    
    def get_by_category(self, category: ToolCategory) -> list[DetectedTool]:
        """Get detected tools by category.
        
        Args:
            category: Tool category.
            
        Returns:
            List of detected tools in that category.
        """
        return [
            t for t in self._detected.values()
            if t.info.category == category
        ]
    
    def get_available_by_category(self, category: ToolCategory) -> list[DetectedTool]:
        """Get available tools by category.
        
        Args:
            category: Tool category.
            
        Returns:
            List of available tools in that category.
        """
        return [
            t for t in self._detected.values()
            if t.info.category == category and t.status == ToolStatus.AVAILABLE
        ]
    
    def suggest_installation(self, name: str, platform: str = "linux") -> Optional[str]:
        """Get installation suggestion for a missing tool.
        
        Args:
            name: Tool name.
            platform: Target platform.
            
        Returns:
            Installation command or None.
        """
        tool = self.registry.get(name)
        if not tool:
            return None
        
        return tool.get_install_command(platform)
    
    def find_alternative(self, name: str) -> Optional[DetectedTool]:
        """Find an available alternative for a missing tool.
        
        Args:
            name: Tool name that is missing.
            
        Returns:
            An available alternative or None.
        """
        tool = self.registry.get(name)
        if not tool:
            return None
        
        for alt_name in tool.alternatives:
            alt = self._detected.get(alt_name.lower())
            if alt and alt.status == ToolStatus.AVAILABLE:
                return alt
        
        return None
    
    def format_report(self) -> str:
        """Format detection results as a report.
        
        Returns:
            Formatted report string.
        """
        lines = ["Detected Tools:"]
        
        # Group by category
        categories: dict[ToolCategory, list[DetectedTool]] = {}
        for tool in self._detected.values():
            cat = tool.info.category
            if cat not in categories:
                categories[cat] = []
            categories[cat].append(tool)
        
        for category in ToolCategory:
            if category in categories:
                tools = categories[category]
                lines.append(f"\n  {category.value.replace('_', ' ').title()}:")
                for tool in sorted(tools, key=lambda t: t.info.name):
                    lines.append(tool.format())
        
        # Summary
        available = len(self.available_tools)
        total = len(self._detected)
        lines.append(f"\n  {available}/{total} tools available")
        
        return "\n".join(lines)
    
    def clear_cache(self) -> None:
        """Clear detection cache."""
        self._detected.clear()
        self._detection_complete = False
