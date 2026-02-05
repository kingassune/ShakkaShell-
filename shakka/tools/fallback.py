"""Fallback management for unavailable tools.

Provides automatic command translation to alternative tools.
"""

from dataclasses import dataclass, field
from typing import Callable, Optional
import re

from .registry import ToolRegistry, ToolInfo


@dataclass
class FallbackRule:
    """A rule for translating commands between tools.
    
    Defines how to convert a command from one tool to an alternative.
    """
    
    source_tool: str           # Original tool name
    target_tool: str           # Fallback tool name
    description: str           # Description of the fallback
    pattern: str               # Regex pattern to match source command
    replacement: str           # Replacement pattern for target
    priority: int = 0          # Higher priority rules are tried first
    
    def to_dict(self) -> dict:
        """Convert to dictionary."""
        return {
            "source_tool": self.source_tool,
            "target_tool": self.target_tool,
            "description": self.description,
            "pattern": self.pattern,
            "replacement": self.replacement,
            "priority": self.priority,
        }
    
    @classmethod
    def from_dict(cls, data: dict) -> "FallbackRule":
        """Create from dictionary."""
        return cls(
            source_tool=data.get("source_tool", ""),
            target_tool=data.get("target_tool", ""),
            description=data.get("description", ""),
            pattern=data.get("pattern", ""),
            replacement=data.get("replacement", ""),
            priority=data.get("priority", 0),
        )
    
    def apply(self, command: str) -> Optional[str]:
        """Apply the fallback rule to a command.
        
        Args:
            command: Original command.
            
        Returns:
            Transformed command or None if pattern doesn't match.
        """
        try:
            if re.search(self.pattern, command):
                return re.sub(self.pattern, self.replacement, command)
        except re.error:
            pass
        return None


class FallbackManager:
    """Manages fallback alternatives for unavailable tools.
    
    Provides automatic command translation when preferred tools are missing.
    
    Example:
        manager = FallbackManager()
        
        # Register available tools
        manager.set_available("nmap")
        manager.set_unavailable("masscan")
        
        # Get fallback command
        alt = manager.get_fallback("masscan -p- 10.0.0.1")
        # Returns: ("nmap -p- 10.0.0.1", "masscan", "nmap")
    """
    
    def __init__(self, registry: Optional[ToolRegistry] = None):
        """Initialize the fallback manager.
        
        Args:
            registry: Optional tool registry.
        """
        self.registry = registry or ToolRegistry()
        self._available: set[str] = set()
        self._unavailable: set[str] = set()
        self._rules: list[FallbackRule] = []
        self._register_default_rules()
    
    def _register_default_rules(self) -> None:
        """Register default fallback rules."""
        # Masscan to nmap
        self.add_rule(FallbackRule(
            source_tool="masscan",
            target_tool="nmap",
            description="Use nmap instead of masscan for port scanning",
            pattern=r"masscan\s+(.+)",
            replacement=r"nmap \1",
            priority=10,
        ))
        
        # Rustscan to nmap
        self.add_rule(FallbackRule(
            source_tool="rustscan",
            target_tool="nmap",
            description="Use nmap instead of rustscan",
            pattern=r"rustscan\s+-a\s+(\S+)",
            replacement=r"nmap -p- \1",
            priority=10,
        ))
        
        # Gobuster to ffuf
        self.add_rule(FallbackRule(
            source_tool="gobuster",
            target_tool="ffuf",
            description="Use ffuf instead of gobuster for directory brute forcing",
            pattern=r"gobuster\s+dir\s+-u\s+(\S+)\s+-w\s+(\S+)",
            replacement=r"ffuf -u \1/FUZZ -w \2",
            priority=10,
        ))
        
        # Ffuf to gobuster
        self.add_rule(FallbackRule(
            source_tool="ffuf",
            target_tool="gobuster",
            description="Use gobuster instead of ffuf",
            pattern=r"ffuf\s+-u\s+(\S+)/FUZZ\s+-w\s+(\S+)",
            replacement=r"gobuster dir -u \1 -w \2",
            priority=10,
        ))
        
        # Feroxbuster to gobuster
        self.add_rule(FallbackRule(
            source_tool="feroxbuster",
            target_tool="gobuster",
            description="Use gobuster instead of feroxbuster",
            pattern=r"feroxbuster\s+-u\s+(\S+)\s+-w\s+(\S+)",
            replacement=r"gobuster dir -u \1 -w \2",
            priority=10,
        ))
        
        # Hashcat to john
        self.add_rule(FallbackRule(
            source_tool="hashcat",
            target_tool="john",
            description="Use john instead of hashcat for password cracking",
            pattern=r"hashcat\s+-m\s+\d+\s+(\S+)\s+(\S+)",
            replacement=r"john --wordlist=\2 \1",
            priority=10,
        ))
        
        # John to hashcat
        self.add_rule(FallbackRule(
            source_tool="john",
            target_tool="hashcat",
            description="Use hashcat instead of john",
            pattern=r"john\s+--wordlist=(\S+)\s+(\S+)",
            replacement=r"hashcat -a 0 \2 \1",
            priority=10,
        ))
        
        # Nuclei to nmap scripts
        self.add_rule(FallbackRule(
            source_tool="nuclei",
            target_tool="nmap",
            description="Use nmap vulnerability scripts instead of nuclei",
            pattern=r"nuclei\s+-u\s+(\S+)",
            replacement=r"nmap --script=vuln \1",
            priority=10,
        ))
        
        # Amass to subfinder
        self.add_rule(FallbackRule(
            source_tool="amass",
            target_tool="subfinder",
            description="Use subfinder instead of amass",
            pattern=r"amass\s+enum\s+-d\s+(\S+)",
            replacement=r"subfinder -d \1",
            priority=10,
        ))
        
        # Subfinder to amass
        self.add_rule(FallbackRule(
            source_tool="subfinder",
            target_tool="amass",
            description="Use amass instead of subfinder",
            pattern=r"subfinder\s+-d\s+(\S+)",
            replacement=r"amass enum -passive -d \1",
            priority=10,
        ))
        
        # Curl to wget
        self.add_rule(FallbackRule(
            source_tool="curl",
            target_tool="wget",
            description="Use wget instead of curl",
            pattern=r"curl\s+(-o\s+\S+\s+)?(\S+)",
            replacement=r"wget \2",
            priority=5,
        ))
        
        # Wget to curl
        self.add_rule(FallbackRule(
            source_tool="wget",
            target_tool="curl",
            description="Use curl instead of wget",
            pattern=r"wget\s+(-O\s+\S+\s+)?(\S+)",
            replacement=r"curl -O \2",
            priority=5,
        ))
        
        # Netcat variants
        self.add_rule(FallbackRule(
            source_tool="netcat",
            target_tool="ncat",
            description="Use ncat instead of nc",
            pattern=r"\bnc\b(.+)",
            replacement=r"ncat\1",
            priority=10,
        ))
    
    def add_rule(self, rule: FallbackRule) -> None:
        """Add a fallback rule.
        
        Args:
            rule: Fallback rule to add.
        """
        self._rules.append(rule)
        # Keep sorted by priority (highest first)
        self._rules.sort(key=lambda r: r.priority, reverse=True)
    
    def remove_rule(self, source_tool: str, target_tool: str) -> bool:
        """Remove a fallback rule.
        
        Args:
            source_tool: Source tool name.
            target_tool: Target tool name.
            
        Returns:
            True if removed, False if not found.
        """
        for i, rule in enumerate(self._rules):
            if rule.source_tool == source_tool and rule.target_tool == target_tool:
                del self._rules[i]
                return True
        return False
    
    def set_available(self, tool: str) -> None:
        """Mark a tool as available.
        
        Args:
            tool: Tool name.
        """
        tool = tool.lower()
        self._available.add(tool)
        self._unavailable.discard(tool)
    
    def set_unavailable(self, tool: str) -> None:
        """Mark a tool as unavailable.
        
        Args:
            tool: Tool name.
        """
        tool = tool.lower()
        self._unavailable.add(tool)
        self._available.discard(tool)
    
    def is_available(self, tool: str) -> bool:
        """Check if a tool is available.
        
        Args:
            tool: Tool name.
            
        Returns:
            True if marked as available.
        """
        return tool.lower() in self._available
    
    def get_fallback(
        self,
        command: str,
    ) -> Optional[tuple[str, str, str]]:
        """Get a fallback command for an unavailable tool.
        
        Args:
            command: Original command string.
            
        Returns:
            Tuple of (new_command, original_tool, fallback_tool) or None.
        """
        # Detect which tool the command uses
        original_tool = self._detect_tool(command)
        if not original_tool:
            return None
        
        # Check if tool is available - if so, no fallback needed
        if self.is_available(original_tool):
            return None
        
        # Find applicable fallback rules
        for rule in self._rules:
            if rule.source_tool.lower() != original_tool.lower():
                continue
            
            # Check if target tool is available
            if not self.is_available(rule.target_tool):
                continue
            
            # Apply the rule
            new_command = rule.apply(command)
            if new_command:
                return (new_command, original_tool, rule.target_tool)
        
        return None
    
    def _detect_tool(self, command: str) -> Optional[str]:
        """Detect which tool a command uses.
        
        Args:
            command: Command string.
            
        Returns:
            Tool name or None.
        """
        # Get first word of command
        parts = command.strip().split()
        if not parts:
            return None
        
        cmd = parts[0]
        
        # Check if it matches any registered tool
        tool = self.registry.get_by_command(cmd)
        if tool:
            return tool.name
        
        # Fall back to command name
        return cmd
    
    def get_all_rules(self) -> list[FallbackRule]:
        """Get all fallback rules.
        
        Returns:
            List of all rules.
        """
        return list(self._rules)
    
    def get_rules_for_tool(self, tool: str) -> list[FallbackRule]:
        """Get fallback rules for a specific tool.
        
        Args:
            tool: Tool name.
            
        Returns:
            List of rules where tool is the source.
        """
        tool = tool.lower()
        return [r for r in self._rules if r.source_tool.lower() == tool]
    
    def suggest_alternatives(self, tool: str) -> list[str]:
        """Suggest available alternatives for a tool.
        
        Args:
            tool: Tool name.
            
        Returns:
            List of available alternative tool names.
        """
        tool_info = self.registry.get(tool)
        if not tool_info:
            return []
        
        alternatives = []
        for alt_name in tool_info.alternatives:
            if self.is_available(alt_name):
                alternatives.append(alt_name)
        
        return alternatives
    
    def format_suggestion(self, tool: str) -> str:
        """Format a suggestion message for a missing tool.
        
        Args:
            tool: Missing tool name.
            
        Returns:
            Formatted suggestion message.
        """
        lines = [f"Tool '{tool}' is not available."]
        
        # Suggest alternatives
        alternatives = self.suggest_alternatives(tool)
        if alternatives:
            lines.append(f"Available alternatives: {', '.join(alternatives)}")
        
        # Suggest installation
        tool_info = self.registry.get(tool)
        if tool_info:
            install_cmd = tool_info.get_install_command()
            if install_cmd:
                lines.append(f"Install with: {install_cmd}")
            elif tool_info.install_url:
                lines.append(f"Manual install: {tool_info.install_url}")
        
        return "\n".join(lines)
    
    def clear(self) -> None:
        """Clear all availability information."""
        self._available.clear()
        self._unavailable.clear()
