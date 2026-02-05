"""Tests for MCP server implementation."""

import json
import pytest
from io import StringIO

from shakka.mcp.server import (
    MCPServer,
    MCPServerConfig,
    MCPServerInfo,
    MCPCapabilities,
    MCP_PROTOCOL_VERSION,
    PARSE_ERROR,
    INVALID_REQUEST,
    METHOD_NOT_FOUND,
    INVALID_PARAMS,
    INTERNAL_ERROR,
    MethodNotFoundError,
    InvalidParamsError,
)
from shakka.mcp.tools import (
    MCPTool,
    MCPToolParameter,
    MCPToolRegistry,
    create_default_tools,
)


class TestMCPToolParameter:
    """Tests for MCPToolParameter dataclass."""
    
    def test_basic_parameter(self):
        """Test creating a basic parameter."""
        param = MCPToolParameter(
            name="target",
            type="string",
            description="Target host",
            required=True,
        )
        
        assert param.name == "target"
        assert param.type == "string"
        assert param.required is True
        assert param.default is None
    
    def test_parameter_with_enum(self):
        """Test parameter with enum constraint."""
        param = MCPToolParameter(
            name="scan_type",
            type="string",
            description="Scan type",
            enum=["quick", "full", "vuln"],
        )
        
        assert param.enum == ["quick", "full", "vuln"]
    
    def test_parameter_with_pattern(self):
        """Test parameter with regex pattern."""
        param = MCPToolParameter(
            name="cve",
            type="string",
            description="CVE ID",
            pattern=r"^CVE-\d{4}-\d+$",
        )
        
        assert param.pattern == r"^CVE-\d{4}-\d+$"


class TestMCPTool:
    """Tests for MCPTool dataclass."""
    
    def test_basic_tool(self):
        """Test creating a basic tool."""
        tool = MCPTool(
            name="test_tool",
            description="A test tool",
        )
        
        assert tool.name == "test_tool"
        assert tool.description == "A test tool"
        assert tool.parameters == []
        assert tool.handler is None
    
    def test_tool_with_parameters(self):
        """Test tool with parameters."""
        tool = MCPTool(
            name="scan",
            description="Scan target",
            parameters=[
                MCPToolParameter(
                    name="target",
                    type="string",
                    description="Target",
                    required=True,
                ),
            ],
        )
        
        assert len(tool.parameters) == 1
        assert tool.parameters[0].name == "target"
    
    def test_to_schema(self):
        """Test converting tool to JSON schema."""
        tool = MCPTool(
            name="shakka_scan",
            description="Quick scan",
            parameters=[
                MCPToolParameter(
                    name="target",
                    type="string",
                    description="Target IP",
                    required=True,
                ),
                MCPToolParameter(
                    name="scan_type",
                    type="string",
                    description="Scan type",
                    default="quick",
                    enum=["quick", "full"],
                ),
            ],
        )
        
        schema = tool.to_schema()
        
        assert schema["name"] == "shakka_scan"
        assert schema["description"] == "Quick scan"
        assert schema["inputSchema"]["type"] == "object"
        assert "target" in schema["inputSchema"]["properties"]
        assert "scan_type" in schema["inputSchema"]["properties"]
        assert schema["inputSchema"]["required"] == ["target"]
        assert schema["inputSchema"]["properties"]["scan_type"]["enum"] == ["quick", "full"]
        assert schema["inputSchema"]["properties"]["scan_type"]["default"] == "quick"


class TestMCPToolRegistry:
    """Tests for MCPToolRegistry."""
    
    def test_empty_registry(self):
        """Test empty registry."""
        registry = MCPToolRegistry()
        
        assert registry.list_tools() == []
        assert registry.list_tool_schemas() == []
    
    def test_register_tool(self):
        """Test registering a tool."""
        registry = MCPToolRegistry()
        tool = MCPTool(name="test", description="Test tool")
        
        registry.register(tool)
        
        assert registry.has_tool("test")
        assert registry.get("test") == tool
    
    def test_register_duplicate_fails(self):
        """Test registering duplicate tool fails."""
        registry = MCPToolRegistry()
        tool = MCPTool(name="test", description="Test tool")
        
        registry.register(tool)
        
        with pytest.raises(ValueError, match="already registered"):
            registry.register(tool)
    
    def test_get_nonexistent_tool(self):
        """Test getting non-existent tool returns None."""
        registry = MCPToolRegistry()
        
        assert registry.get("nonexistent") is None
    
    def test_list_tools(self):
        """Test listing all tools."""
        registry = MCPToolRegistry()
        tool1 = MCPTool(name="tool1", description="Tool 1")
        tool2 = MCPTool(name="tool2", description="Tool 2")
        
        registry.register(tool1)
        registry.register(tool2)
        
        tools = registry.list_tools()
        
        assert len(tools) == 2
        assert tool1 in tools
        assert tool2 in tools
    
    def test_list_tool_schemas(self):
        """Test listing tool schemas."""
        registry = MCPToolRegistry()
        tool = MCPTool(name="test", description="Test")
        registry.register(tool)
        
        schemas = registry.list_tool_schemas()
        
        assert len(schemas) == 1
        assert schemas[0]["name"] == "test"


class TestCreateDefaultTools:
    """Tests for create_default_tools function."""
    
    def test_creates_registry(self):
        """Test creates a registry with default tools."""
        registry = create_default_tools()
        
        assert isinstance(registry, MCPToolRegistry)
    
    def test_has_shakka_execute(self):
        """Test registry has shakka_execute tool."""
        registry = create_default_tools()
        
        tool = registry.get("shakka_execute")
        assert tool is not None
        assert tool.description == "Convert natural language to security command and optionally execute it"
    
    def test_has_shakka_scan(self):
        """Test registry has shakka_scan tool."""
        registry = create_default_tools()
        
        tool = registry.get("shakka_scan")
        assert tool is not None
        assert tool.description == "Quick network or host scan"
    
    def test_has_shakka_exploit(self):
        """Test registry has shakka_exploit tool."""
        registry = create_default_tools()
        
        tool = registry.get("shakka_exploit")
        assert tool is not None
        assert tool.description == "Lookup or generate exploit for a CVE identifier"
    
    def test_shakka_execute_parameters(self):
        """Test shakka_execute has correct parameters."""
        registry = create_default_tools()
        tool = registry.get("shakka_execute")
        
        param_names = [p.name for p in tool.parameters]
        assert "prompt" in param_names
        assert "execute" in param_names
        assert "explain" in param_names
        
        prompt_param = next(p for p in tool.parameters if p.name == "prompt")
        assert prompt_param.required is True
    
    def test_shakka_scan_parameters(self):
        """Test shakka_scan has correct parameters."""
        registry = create_default_tools()
        tool = registry.get("shakka_scan")
        
        param_names = [p.name for p in tool.parameters]
        assert "target" in param_names
        assert "scan_type" in param_names
        
        scan_type = next(p for p in tool.parameters if p.name == "scan_type")
        assert scan_type.enum == ["quick", "full", "vuln"]
    
    def test_shakka_exploit_parameters(self):
        """Test shakka_exploit has correct parameters."""
        registry = create_default_tools()
        tool = registry.get("shakka_exploit")
        
        cve_param = tool.parameters[0]
        assert cve_param.name == "cve"
        assert cve_param.required is True
        assert cve_param.pattern == r"^CVE-\d{4}-\d+$"


class TestMCPServerConfig:
    """Tests for MCP server configuration."""
    
    def test_default_config(self):
        """Test default configuration values."""
        config = MCPServerConfig()
        
        assert config.server_info.name == "shakkashell"
        assert config.server_info.version == "2.0.0"
        assert config.capabilities.tools is True
        assert config.capabilities.prompts is False
    
    def test_custom_server_info(self):
        """Test custom server info."""
        info = MCPServerInfo(name="custom", version="1.0.0")
        config = MCPServerConfig(server_info=info)
        
        assert config.server_info.name == "custom"
        assert config.server_info.version == "1.0.0"


class TestMCPServer:
    """Tests for MCPServer class."""
    
    @pytest.fixture
    def server(self):
        """Create a default MCP server."""
        return MCPServer()
    
    def test_server_initialization(self, server):
        """Test server initializes correctly."""
        assert server.config is not None
        assert server.tool_registry is not None
        assert server._running is False
        assert server._initialized is False
    
    def test_server_with_custom_config(self):
        """Test server with custom configuration."""
        config = MCPServerConfig(
            server_info=MCPServerInfo(name="test", version="0.1.0")
        )
        server = MCPServer(config=config)
        
        assert server.config.server_info.name == "test"
    
    def test_server_with_custom_registry(self):
        """Test server with custom tool registry."""
        registry = MCPToolRegistry()
        registry.register(MCPTool(name="custom", description="Custom tool"))
        
        server = MCPServer(tool_registry=registry)
        
        assert server.tool_registry.has_tool("custom")


class TestMCPServerMessageHandling:
    """Tests for MCP server message handling."""
    
    @pytest.fixture
    def server(self):
        """Create an MCP server."""
        return MCPServer()
    
    @pytest.mark.asyncio
    async def test_handle_parse_error(self, server):
        """Test handling invalid JSON."""
        response = await server._handle_message("not valid json")
        
        assert response["jsonrpc"] == "2.0"
        assert response["error"]["code"] == PARSE_ERROR
        assert "Parse error" in response["error"]["message"]
    
    @pytest.mark.asyncio
    async def test_handle_invalid_request_not_object(self, server):
        """Test handling non-object request."""
        response = await server._handle_message('"string"')
        
        assert response["error"]["code"] == INVALID_REQUEST
    
    @pytest.mark.asyncio
    async def test_handle_invalid_jsonrpc_version(self, server):
        """Test handling wrong JSON-RPC version."""
        request = json.dumps({"jsonrpc": "1.0", "method": "test", "id": 1})
        response = await server._handle_message(request)
        
        assert response["error"]["code"] == INVALID_REQUEST
        assert "Invalid JSON-RPC version" in response["error"]["message"]
    
    @pytest.mark.asyncio
    async def test_handle_missing_method(self, server):
        """Test handling missing method."""
        request = json.dumps({"jsonrpc": "2.0", "id": 1})
        response = await server._handle_message(request)
        
        assert response["error"]["code"] == INVALID_REQUEST
    
    @pytest.mark.asyncio
    async def test_handle_unknown_method(self, server):
        """Test handling unknown method."""
        request = json.dumps({"jsonrpc": "2.0", "method": "unknown", "id": 1})
        response = await server._handle_message(request)
        
        assert response["error"]["code"] == METHOD_NOT_FOUND
    
    @pytest.mark.asyncio
    async def test_handle_initialize(self, server):
        """Test handling initialize request."""
        request = json.dumps({
            "jsonrpc": "2.0",
            "method": "initialize",
            "params": {"protocolVersion": MCP_PROTOCOL_VERSION},
            "id": 1,
        })
        
        response = await server._handle_message(request)
        
        assert response["jsonrpc"] == "2.0"
        assert response["id"] == 1
        assert "result" in response
        assert response["result"]["protocolVersion"] == MCP_PROTOCOL_VERSION
        assert response["result"]["serverInfo"]["name"] == "shakkashell"
        assert server._initialized is True
    
    @pytest.mark.asyncio
    async def test_handle_initialized_notification(self, server):
        """Test handling initialized notification (no response expected)."""
        request = json.dumps({
            "jsonrpc": "2.0",
            "method": "initialized",
            "params": {},
        })
        
        response = await server._handle_message(request)
        
        # Notifications don't get responses
        assert response is None
    
    @pytest.mark.asyncio
    async def test_handle_tools_list(self, server):
        """Test handling tools/list request."""
        request = json.dumps({
            "jsonrpc": "2.0",
            "method": "tools/list",
            "params": {},
            "id": 1,
        })
        
        response = await server._handle_message(request)
        
        assert response["id"] == 1
        assert "result" in response
        assert "tools" in response["result"]
        
        tool_names = [t["name"] for t in response["result"]["tools"]]
        assert "shakka_execute" in tool_names
        assert "shakka_scan" in tool_names
        assert "shakka_exploit" in tool_names
    
    @pytest.mark.asyncio
    async def test_handle_tools_call_missing_name(self, server):
        """Test tools/call without tool name."""
        request = json.dumps({
            "jsonrpc": "2.0",
            "method": "tools/call",
            "params": {},
            "id": 1,
        })
        
        response = await server._handle_message(request)
        
        assert response["error"]["code"] == INVALID_PARAMS
        assert "name is required" in response["error"]["message"]
    
    @pytest.mark.asyncio
    async def test_handle_tools_call_unknown_tool(self, server):
        """Test tools/call with unknown tool."""
        request = json.dumps({
            "jsonrpc": "2.0",
            "method": "tools/call",
            "params": {"name": "unknown_tool"},
            "id": 1,
        })
        
        response = await server._handle_message(request)
        
        assert response["error"]["code"] == INVALID_PARAMS
        assert "Unknown tool" in response["error"]["message"]
    
    @pytest.mark.asyncio
    async def test_handle_tools_call_missing_required_param(self, server):
        """Test tools/call missing required parameter."""
        request = json.dumps({
            "jsonrpc": "2.0",
            "method": "tools/call",
            "params": {
                "name": "shakka_execute",
                "arguments": {},  # Missing required 'prompt'
            },
            "id": 1,
        })
        
        response = await server._handle_message(request)
        
        assert response["error"]["code"] == INVALID_PARAMS
        assert "prompt" in response["error"]["message"]
    
    @pytest.mark.asyncio
    async def test_handle_tools_call_stub_response(self, server):
        """Test tools/call returns stub response when handler not implemented."""
        request = json.dumps({
            "jsonrpc": "2.0",
            "method": "tools/call",
            "params": {
                "name": "shakka_execute",
                "arguments": {"prompt": "scan ports"},
            },
            "id": 1,
        })
        
        response = await server._handle_message(request)
        
        assert response["id"] == 1
        assert "result" in response
        assert "content" in response["result"]
        assert len(response["result"]["content"]) == 1
        assert response["result"]["content"][0]["type"] == "text"
    
    @pytest.mark.asyncio
    async def test_handle_shutdown(self, server):
        """Test shutdown request stops server."""
        server._running = True
        
        request = json.dumps({
            "jsonrpc": "2.0",
            "method": "shutdown",
            "params": {},
            "id": 1,
        })
        
        await server._handle_message(request)
        
        assert server._running is False
    
    def test_stop(self, server):
        """Test stop method."""
        server._running = True
        server.stop()
        assert server._running is False


class TestMCPServerResponses:
    """Tests for MCP server response creation."""
    
    @pytest.fixture
    def server(self):
        """Create an MCP server."""
        return MCPServer()
    
    def test_create_success_response(self, server):
        """Test creating success response."""
        response = server._create_success_response(1, {"data": "test"})
        
        assert response["jsonrpc"] == "2.0"
        assert response["id"] == 1
        assert response["result"] == {"data": "test"}
        assert "error" not in response
    
    def test_create_error_response(self, server):
        """Test creating error response."""
        response = server._create_error_response(1, -32600, "test error")
        
        assert response["jsonrpc"] == "2.0"
        assert response["id"] == 1
        assert response["error"]["code"] == -32600
        assert response["error"]["message"] == "test error"
        assert "result" not in response
    
    def test_create_error_response_null_id(self, server):
        """Test creating error response with null id."""
        response = server._create_error_response(None, PARSE_ERROR, "parse error")
        
        assert response["id"] is None


class TestMCPExceptions:
    """Tests for MCP exception classes."""
    
    def test_method_not_found_error(self):
        """Test MethodNotFoundError."""
        error = MethodNotFoundError("test method")
        assert str(error) == "test method"
    
    def test_invalid_params_error(self):
        """Test InvalidParamsError."""
        error = InvalidParamsError("invalid param")
        assert str(error) == "invalid param"
