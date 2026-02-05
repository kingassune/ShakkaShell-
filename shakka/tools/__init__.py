"""Tool-Aware Command Generation for ShakkaShell.

This module provides detection of installed security tools and generates
commands using only available software with fallback alternatives.
"""

from .detector import ToolDetector, DetectedTool, ToolStatus
from .registry import ToolRegistry, ToolInfo, ToolCategory
from .fallback import FallbackManager, FallbackRule

__all__ = [
    # Detector
    "ToolDetector",
    "DetectedTool",
    "ToolStatus",
    # Registry
    "ToolRegistry",
    "ToolInfo",
    "ToolCategory",
    # Fallback
    "FallbackManager",
    "FallbackRule",
]
