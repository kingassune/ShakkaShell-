"""MCP tool definitions and registry.

Defines the tools exposed by ShakkaShell's MCP server.
"""

from dataclasses import dataclass, field
from typing import Any, Callable, Coroutine, Optional


@dataclass
class MCPToolParameter:
    """Definition of a tool parameter."""
    
    name: str
    type: str
    description: str
    required: bool = False
    default: Any = None
    enum: Optional[list[str]] = None
    pattern: Optional[str] = None


@dataclass
class MCPTool:
    """Definition of an MCP tool.
    
    Attributes:
        name: Unique tool name (e.g., "shakka_execute")
        description: Human-readable description of what the tool does
        parameters: List of parameter definitions
        handler: Async function to execute when tool is called
    """
    
    name: str
    description: str
    parameters: list[MCPToolParameter] = field(default_factory=list)
    handler: Optional[Callable[..., Coroutine[Any, Any, dict]]] = None
    
    def to_schema(self) -> dict:
        """Convert tool to MCP-compatible JSON schema format.
        
        Returns:
            Dictionary with tool name, description, and input schema.
        """
        properties = {}
        required = []
        
        for param in self.parameters:
            prop = {
                "type": param.type,
                "description": param.description,
            }
            if param.default is not None:
                prop["default"] = param.default
            if param.enum:
                prop["enum"] = param.enum
            if param.pattern:
                prop["pattern"] = param.pattern
            
            properties[param.name] = prop
            
            if param.required:
                required.append(param.name)
        
        return {
            "name": self.name,
            "description": self.description,
            "inputSchema": {
                "type": "object",
                "properties": properties,
                "required": required,
            },
        }


class MCPToolRegistry:
    """Registry of available MCP tools.
    
    Example:
        registry = MCPToolRegistry()
        registry.register(shakka_execute_tool)
        tools = registry.list_tools()
    """
    
    def __init__(self):
        """Initialize an empty tool registry."""
        self._tools: dict[str, MCPTool] = {}
    
    def register(self, tool: MCPTool) -> None:
        """Register a tool with the registry.
        
        Args:
            tool: MCPTool instance to register.
            
        Raises:
            ValueError: If a tool with the same name is already registered.
        """
        if tool.name in self._tools:
            raise ValueError(f"Tool '{tool.name}' is already registered")
        self._tools[tool.name] = tool
    
    def get(self, name: str) -> Optional[MCPTool]:
        """Get a tool by name.
        
        Args:
            name: Tool name to look up.
            
        Returns:
            MCPTool if found, None otherwise.
        """
        return self._tools.get(name)
    
    def list_tools(self) -> list[MCPTool]:
        """List all registered tools.
        
        Returns:
            List of all registered MCPTool instances.
        """
        return list(self._tools.values())
    
    def list_tool_schemas(self) -> list[dict]:
        """Get JSON schemas for all tools.
        
        Returns:
            List of tool schemas in MCP format.
        """
        return [tool.to_schema() for tool in self._tools.values()]
    
    def has_tool(self, name: str) -> bool:
        """Check if a tool is registered.
        
        Args:
            name: Tool name to check.
            
        Returns:
            True if tool exists, False otherwise.
        """
        return name in self._tools


def create_default_tools() -> MCPToolRegistry:
    """Create registry with default ShakkaShell tools.
    
    Returns:
        MCPToolRegistry with shakka_execute, shakka_scan, and shakka_exploit tools.
    """
    registry = MCPToolRegistry()
    
    # shakka_execute tool
    execute_tool = MCPTool(
        name="shakka_execute",
        description="Convert natural language to security command and optionally execute it",
        parameters=[
            MCPToolParameter(
                name="prompt",
                type="string",
                description="Natural language security task description",
                required=True,
            ),
            MCPToolParameter(
                name="execute",
                type="boolean",
                description="Whether to execute the generated command",
                required=False,
                default=False,
            ),
            MCPToolParameter(
                name="explain",
                type="boolean",
                description="Include detailed explanation of the command",
                required=False,
                default=False,
            ),
        ],
    )
    registry.register(execute_tool)
    
    # shakka_scan tool
    scan_tool = MCPTool(
        name="shakka_scan",
        description="Quick network or host scan",
        parameters=[
            MCPToolParameter(
                name="target",
                type="string",
                description="Target IP, hostname, or CIDR range to scan",
                required=True,
            ),
            MCPToolParameter(
                name="scan_type",
                type="string",
                description="Type of scan to perform",
                required=False,
                default="quick",
                enum=["quick", "full", "vuln"],
            ),
        ],
    )
    registry.register(scan_tool)
    
    # shakka_exploit tool
    exploit_tool = MCPTool(
        name="shakka_exploit",
        description="Lookup or generate exploit for a CVE identifier",
        parameters=[
            MCPToolParameter(
                name="cve",
                type="string",
                description="CVE identifier (e.g., CVE-2024-1234)",
                required=True,
                pattern=r"^CVE-\d{4}-\d+$",
            ),
        ],
    )
    registry.register(exploit_tool)
    
    return registry
