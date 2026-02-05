"""Tests for MCP HTTP transport implementation."""

import asyncio
import json
import threading
import time
import pytest
from io import BytesIO
from unittest.mock import AsyncMock, MagicMock, patch
from http.client import HTTPConnection

from shakka.mcp.transport import (
    HTTPTransportConfig,
    MCPHTTPHandler,
    MCPHTTPTransport,
    AsyncMCPHTTPTransport,
    create_http_transport,
    create_async_http_transport,
)
from shakka.mcp.server import MCPServer


# =============================================================================
# HTTPTransportConfig Tests
# =============================================================================

class TestHTTPTransportConfig:
    """Tests for HTTPTransportConfig dataclass."""
    
    def test_default_config(self):
        """Test default configuration values."""
        config = HTTPTransportConfig()
        
        assert config.host == "127.0.0.1"
        assert config.port == 3000
        assert config.cors_enabled is True
        assert config.cors_origins == ["*"]
        assert config.auth_enabled is False
        assert config.auth_token is None
        assert config.request_timeout == 30.0
        assert config.max_request_size == 1024 * 1024
        assert config.enable_sse is True
    
    def test_custom_config(self):
        """Test custom configuration."""
        config = HTTPTransportConfig(
            host="0.0.0.0",
            port=8080,
            cors_enabled=False,
            cors_origins=["https://example.com"],
            auth_enabled=True,
            auth_token="secret123",
            request_timeout=60.0,
            max_request_size=512 * 1024,
            enable_sse=False,
        )
        
        assert config.host == "0.0.0.0"
        assert config.port == 8080
        assert config.cors_enabled is False
        assert config.cors_origins == ["https://example.com"]
        assert config.auth_enabled is True
        assert config.auth_token == "secret123"
        assert config.request_timeout == 60.0
        assert config.max_request_size == 512 * 1024
        assert config.enable_sse is False
    
    def test_to_dict(self):
        """Test converting config to dictionary."""
        config = HTTPTransportConfig(host="localhost", port=5000)
        result = config.to_dict()
        
        assert result["host"] == "localhost"
        assert result["port"] == 5000
        assert "cors_enabled" in result
        assert "enable_sse" in result


# =============================================================================
# MCPHTTPHandler Tests
# =============================================================================

class TestMCPHTTPHandler:
    """Tests for MCPHTTPHandler class."""
    
    def test_handler_class_attributes(self):
        """Test handler class has required attributes."""
        assert hasattr(MCPHTTPHandler, "message_handler")
        assert hasattr(MCPHTTPHandler, "config")
        assert hasattr(MCPHTTPHandler, "sse_clients")
    
    def test_check_auth_disabled(self):
        """Test authentication check when disabled."""
        handler = MagicMock(spec=MCPHTTPHandler)
        handler.config = HTTPTransportConfig(auth_enabled=False)
        handler.headers = {}
        
        # Call the method
        result = MCPHTTPHandler._check_auth(handler)
        assert result is True
    
    def test_check_auth_valid_token(self):
        """Test authentication with valid token."""
        handler = MagicMock(spec=MCPHTTPHandler)
        handler.config = HTTPTransportConfig(auth_enabled=True, auth_token="secret123")
        handler.headers = MagicMock()
        handler.headers.get.return_value = "Bearer secret123"
        
        result = MCPHTTPHandler._check_auth(handler)
        assert result is True
    
    def test_check_auth_invalid_token(self):
        """Test authentication with invalid token."""
        handler = MagicMock(spec=MCPHTTPHandler)
        handler.config = HTTPTransportConfig(auth_enabled=True, auth_token="secret123")
        handler.headers = MagicMock()
        handler.headers.get.return_value = "Bearer wrongtoken"
        
        result = MCPHTTPHandler._check_auth(handler)
        assert result is False
    
    def test_check_auth_no_bearer(self):
        """Test authentication without Bearer prefix."""
        handler = MagicMock(spec=MCPHTTPHandler)
        handler.config = HTTPTransportConfig(auth_enabled=True, auth_token="secret123")
        handler.headers = MagicMock()
        handler.headers.get.return_value = "secret123"
        
        result = MCPHTTPHandler._check_auth(handler)
        assert result is False


# =============================================================================
# MCPHTTPTransport Tests
# =============================================================================

class TestMCPHTTPTransport:
    """Tests for MCPHTTPTransport class."""
    
    def test_init_with_defaults(self):
        """Test initialization with default config."""
        server = MagicMock()
        transport = MCPHTTPTransport(server)
        
        assert transport.mcp_server == server
        assert transport.config.host == "127.0.0.1"
        assert transport.config.port == 3000
        assert transport.running is False
    
    def test_init_with_custom_config(self):
        """Test initialization with custom config."""
        server = MagicMock()
        config = HTTPTransportConfig(host="0.0.0.0", port=8080)
        transport = MCPHTTPTransport(server, config)
        
        assert transport.config.host == "0.0.0.0"
        assert transport.config.port == 8080
    
    def test_address_property(self):
        """Test address property returns correct URL."""
        server = MagicMock()
        config = HTTPTransportConfig(host="localhost", port=3001)
        transport = MCPHTTPTransport(server, config)
        
        assert transport.address == "http://localhost:3001"
    
    def test_running_property_before_start(self):
        """Test running property is False before start."""
        server = MagicMock()
        transport = MCPHTTPTransport(server)
        
        assert transport.running is False
    
    def test_stop_without_start(self):
        """Test stopping without starting doesn't error."""
        server = MagicMock()
        transport = MCPHTTPTransport(server)
        
        # Should not raise
        transport.stop()
        assert transport.running is False


class TestMCPHTTPTransportIntegration:
    """Integration tests for MCPHTTPTransport."""
    
    @pytest.fixture
    def mcp_server(self):
        """Create a mock MCP server."""
        server = MagicMock()
        server._handle_message = AsyncMock(return_value={
            "jsonrpc": "2.0",
            "id": 1,
            "result": {"capabilities": {}},
        })
        return server
    
    def test_start_non_blocking(self, mcp_server):
        """Test starting server in non-blocking mode."""
        config = HTTPTransportConfig(port=3002)
        transport = MCPHTTPTransport(mcp_server, config)
        
        try:
            transport.start(blocking=False)
            time.sleep(0.5)  # Give server time to start
            
            assert transport.running is True
            
            # Try to connect
            conn = HTTPConnection("127.0.0.1", 3002, timeout=5)
            conn.request("GET", "/health")
            response = conn.getresponse()
            
            assert response.status == 200
            data = json.loads(response.read().decode())
            assert data["status"] == "ok"
            
            conn.close()
            
        finally:
            transport.stop()
    
    def test_health_endpoint(self, mcp_server):
        """Test /health endpoint."""
        config = HTTPTransportConfig(port=3003)
        transport = MCPHTTPTransport(mcp_server, config)
        
        try:
            transport.start(blocking=False)
            time.sleep(0.5)
            
            conn = HTTPConnection("127.0.0.1", 3003, timeout=5)
            conn.request("GET", "/health")
            response = conn.getresponse()
            
            assert response.status == 200
            data = json.loads(response.read().decode())
            assert data == {"status": "ok"}
            
            conn.close()
            
        finally:
            transport.stop()
    
    def test_info_endpoint(self, mcp_server):
        """Test /info endpoint."""
        config = HTTPTransportConfig(port=3004)
        transport = MCPHTTPTransport(mcp_server, config)
        
        try:
            transport.start(blocking=False)
            time.sleep(0.5)
            
            conn = HTTPConnection("127.0.0.1", 3004, timeout=5)
            conn.request("GET", "/info")
            response = conn.getresponse()
            
            assert response.status == 200
            data = json.loads(response.read().decode())
            assert data["name"] == "shakkashell"
            assert data["protocol"] == "mcp"
            assert data["transport"] == "http"
            
            conn.close()
            
        finally:
            transport.stop()
    
    def test_jsonrpc_post(self, mcp_server):
        """Test JSON-RPC POST request."""
        config = HTTPTransportConfig(port=3005)
        transport = MCPHTTPTransport(mcp_server, config)
        
        try:
            transport.start(blocking=False)
            time.sleep(0.5)
            
            conn = HTTPConnection("127.0.0.1", 3005, timeout=5)
            
            request_body = json.dumps({
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {},
            })
            
            conn.request(
                "POST",
                "/",
                body=request_body,
                headers={"Content-Type": "application/json"},
            )
            response = conn.getresponse()
            
            assert response.status == 200
            data = json.loads(response.read().decode())
            assert data["jsonrpc"] == "2.0"
            assert data["id"] == 1
            assert "result" in data
            
            conn.close()
            
        finally:
            transport.stop()
    
    def test_cors_preflight(self, mcp_server):
        """Test CORS preflight OPTIONS request."""
        config = HTTPTransportConfig(port=3006, cors_enabled=True)
        transport = MCPHTTPTransport(mcp_server, config)
        
        try:
            transport.start(blocking=False)
            time.sleep(0.5)
            
            conn = HTTPConnection("127.0.0.1", 3006, timeout=5)
            conn.request("OPTIONS", "/")
            response = conn.getresponse()
            
            assert response.status == 204
            assert response.getheader("Access-Control-Allow-Origin") is not None
            
            conn.close()
            
        finally:
            transport.stop()
    
    def test_404_for_unknown_path(self, mcp_server):
        """Test 404 for unknown GET paths."""
        config = HTTPTransportConfig(port=3007, enable_sse=False)
        transport = MCPHTTPTransport(mcp_server, config)
        
        try:
            transport.start(blocking=False)
            time.sleep(0.5)
            
            conn = HTTPConnection("127.0.0.1", 3007, timeout=5)
            conn.request("GET", "/unknown")
            response = conn.getresponse()
            
            assert response.status == 404
            conn.close()
            
        finally:
            transport.stop()


# =============================================================================
# AsyncMCPHTTPTransport Tests
# =============================================================================

class TestAsyncMCPHTTPTransport:
    """Tests for AsyncMCPHTTPTransport class."""
    
    def test_init_with_defaults(self):
        """Test initialization with default config."""
        server = MagicMock()
        transport = AsyncMCPHTTPTransport(server)
        
        assert transport.mcp_server == server
        assert transport.config.host == "127.0.0.1"
        assert transport.config.port == 3000
        assert transport.running is False
    
    def test_init_with_custom_config(self):
        """Test initialization with custom config."""
        server = MagicMock()
        config = HTTPTransportConfig(host="0.0.0.0", port=9000)
        transport = AsyncMCPHTTPTransport(server, config)
        
        assert transport.config.host == "0.0.0.0"
        assert transport.config.port == 9000
    
    def test_address_property(self):
        """Test address property returns correct URL."""
        server = MagicMock()
        config = HTTPTransportConfig(host="localhost", port=9001)
        transport = AsyncMCPHTTPTransport(server, config)
        
        assert transport.address == "http://localhost:9001"


@pytest.mark.asyncio
class TestAsyncMCPHTTPTransportIntegration:
    """Async integration tests for AsyncMCPHTTPTransport."""
    
    @pytest.fixture
    def mcp_server(self):
        """Create a mock MCP server."""
        server = MagicMock()
        server._handle_message = AsyncMock(return_value={
            "jsonrpc": "2.0",
            "id": 1,
            "result": {"capabilities": {}},
        })
        return server
    
    async def test_start_background(self, mcp_server):
        """Test starting server in background."""
        config = HTTPTransportConfig(port=9010)
        transport = AsyncMCPHTTPTransport(mcp_server, config)
        
        try:
            await transport.start_background()
            assert transport.running is True
        finally:
            await transport.stop()
            assert transport.running is False
    
    async def test_stop(self, mcp_server):
        """Test stopping server."""
        config = HTTPTransportConfig(port=9011)
        transport = AsyncMCPHTTPTransport(mcp_server, config)
        
        await transport.start_background()
        assert transport.running is True
        
        await transport.stop()
        assert transport.running is False
        assert transport._server is None
    
    async def test_health_endpoint(self, mcp_server):
        """Test /health endpoint via async transport."""
        config = HTTPTransportConfig(port=9012)
        transport = AsyncMCPHTTPTransport(mcp_server, config)
        
        try:
            await transport.start_background()
            await asyncio.sleep(0.3)
            
            reader, writer = await asyncio.open_connection("127.0.0.1", 9012)
            
            request = (
                "GET /health HTTP/1.1\r\n"
                "Host: localhost\r\n"
                "\r\n"
            )
            writer.write(request.encode())
            await writer.drain()
            
            response = await asyncio.wait_for(reader.read(1024), timeout=5)
            response_str = response.decode()
            
            assert "200 OK" in response_str
            assert '"status": "ok"' in response_str
            
            writer.close()
            await writer.wait_closed()
            
        finally:
            await transport.stop()
    
    async def test_info_endpoint(self, mcp_server):
        """Test /info endpoint via async transport."""
        config = HTTPTransportConfig(port=9013)
        transport = AsyncMCPHTTPTransport(mcp_server, config)
        
        try:
            await transport.start_background()
            await asyncio.sleep(0.3)
            
            reader, writer = await asyncio.open_connection("127.0.0.1", 9013)
            
            request = (
                "GET /info HTTP/1.1\r\n"
                "Host: localhost\r\n"
                "\r\n"
            )
            writer.write(request.encode())
            await writer.drain()
            
            response = await asyncio.wait_for(reader.read(1024), timeout=5)
            response_str = response.decode()
            
            assert "200 OK" in response_str
            assert "shakkashell" in response_str
            assert "http-async" in response_str
            
            writer.close()
            await writer.wait_closed()
            
        finally:
            await transport.stop()
    
    async def test_jsonrpc_post(self, mcp_server):
        """Test JSON-RPC POST request."""
        config = HTTPTransportConfig(port=9014)
        transport = AsyncMCPHTTPTransport(mcp_server, config)
        
        try:
            await transport.start_background()
            await asyncio.sleep(0.3)
            
            reader, writer = await asyncio.open_connection("127.0.0.1", 9014)
            
            body = json.dumps({
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {},
            })
            
            request = (
                f"POST / HTTP/1.1\r\n"
                f"Host: localhost\r\n"
                f"Content-Type: application/json\r\n"
                f"Content-Length: {len(body)}\r\n"
                f"\r\n"
                f"{body}"
            )
            writer.write(request.encode())
            await writer.drain()
            
            response = await asyncio.wait_for(reader.read(2048), timeout=5)
            response_str = response.decode()
            
            assert "200 OK" in response_str
            assert '"jsonrpc"' in response_str
            
            writer.close()
            await writer.wait_closed()
            
        finally:
            await transport.stop()
    
    async def test_404_for_unknown_path(self, mcp_server):
        """Test 404 for unknown GET paths."""
        config = HTTPTransportConfig(port=9015, enable_sse=False)
        transport = AsyncMCPHTTPTransport(mcp_server, config)
        
        try:
            await transport.start_background()
            await asyncio.sleep(0.3)
            
            reader, writer = await asyncio.open_connection("127.0.0.1", 9015)
            
            request = (
                "GET /unknown HTTP/1.1\r\n"
                "Host: localhost\r\n"
                "\r\n"
            )
            writer.write(request.encode())
            await writer.drain()
            
            response = await asyncio.wait_for(reader.read(1024), timeout=5)
            response_str = response.decode()
            
            assert "404" in response_str
            
            writer.close()
            await writer.wait_closed()
            
        finally:
            await transport.stop()
    
    async def test_auth_rejection(self, mcp_server):
        """Test authentication rejection without token."""
        config = HTTPTransportConfig(
            port=9016,
            auth_enabled=True,
            auth_token="secret123",
        )
        transport = AsyncMCPHTTPTransport(mcp_server, config)
        
        try:
            await transport.start_background()
            await asyncio.sleep(0.3)
            
            reader, writer = await asyncio.open_connection("127.0.0.1", 9016)
            
            body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "test"})
            
            request = (
                f"POST / HTTP/1.1\r\n"
                f"Host: localhost\r\n"
                f"Content-Type: application/json\r\n"
                f"Content-Length: {len(body)}\r\n"
                f"\r\n"
                f"{body}"
            )
            writer.write(request.encode())
            await writer.drain()
            
            response = await asyncio.wait_for(reader.read(1024), timeout=5)
            response_str = response.decode()
            
            assert "401" in response_str
            
            writer.close()
            await writer.wait_closed()
            
        finally:
            await transport.stop()
    
    async def test_auth_accepted_with_token(self, mcp_server):
        """Test authentication accepted with valid token."""
        config = HTTPTransportConfig(
            port=9017,
            auth_enabled=True,
            auth_token="secret123",
        )
        transport = AsyncMCPHTTPTransport(mcp_server, config)
        
        try:
            await transport.start_background()
            await asyncio.sleep(0.3)
            
            reader, writer = await asyncio.open_connection("127.0.0.1", 9017)
            
            body = json.dumps({
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {},
            })
            
            request = (
                f"POST / HTTP/1.1\r\n"
                f"Host: localhost\r\n"
                f"Content-Type: application/json\r\n"
                f"Authorization: Bearer secret123\r\n"
                f"Content-Length: {len(body)}\r\n"
                f"\r\n"
                f"{body}"
            )
            writer.write(request.encode())
            await writer.drain()
            
            response = await asyncio.wait_for(reader.read(2048), timeout=5)
            response_str = response.decode()
            
            assert "200 OK" in response_str
            
            writer.close()
            await writer.wait_closed()
            
        finally:
            await transport.stop()
    
    async def test_cors_preflight(self, mcp_server):
        """Test CORS preflight OPTIONS request."""
        config = HTTPTransportConfig(port=9018, cors_enabled=True)
        transport = AsyncMCPHTTPTransport(mcp_server, config)
        
        try:
            await transport.start_background()
            await asyncio.sleep(0.3)
            
            reader, writer = await asyncio.open_connection("127.0.0.1", 9018)
            
            request = (
                "OPTIONS / HTTP/1.1\r\n"
                "Host: localhost\r\n"
                "\r\n"
            )
            writer.write(request.encode())
            await writer.drain()
            
            response = await asyncio.wait_for(reader.read(1024), timeout=5)
            response_str = response.decode()
            
            assert "204" in response_str
            assert "Access-Control-Allow-Origin" in response_str
            
            writer.close()
            await writer.wait_closed()
            
        finally:
            await transport.stop()
    
    async def test_broadcast_sse_no_clients(self, mcp_server):
        """Test SSE broadcast with no clients doesn't error."""
        config = HTTPTransportConfig(port=9019)
        transport = AsyncMCPHTTPTransport(mcp_server, config)
        
        try:
            await transport.start_background()
            # Should not raise
            await transport.broadcast_sse("test", {"data": "value"})
        finally:
            await transport.stop()


# =============================================================================
# Factory Function Tests
# =============================================================================

class TestFactoryFunctions:
    """Tests for factory functions."""
    
    def test_create_http_transport(self):
        """Test create_http_transport factory."""
        server = MagicMock()
        transport = create_http_transport(server, host="localhost", port=4000)
        
        assert isinstance(transport, MCPHTTPTransport)
        assert transport.config.host == "localhost"
        assert transport.config.port == 4000
    
    def test_create_http_transport_with_kwargs(self):
        """Test create_http_transport with additional kwargs."""
        server = MagicMock()
        transport = create_http_transport(
            server,
            host="0.0.0.0",
            port=5000,
            cors_enabled=False,
            auth_enabled=True,
            auth_token="token123",
        )
        
        assert transport.config.host == "0.0.0.0"
        assert transport.config.port == 5000
        assert transport.config.cors_enabled is False
        assert transport.config.auth_enabled is True
        assert transport.config.auth_token == "token123"
    
    def test_create_async_http_transport(self):
        """Test create_async_http_transport factory."""
        server = MagicMock()
        transport = create_async_http_transport(server, host="localhost", port=4001)
        
        assert isinstance(transport, AsyncMCPHTTPTransport)
        assert transport.config.host == "localhost"
        assert transport.config.port == 4001
    
    def test_create_async_http_transport_with_kwargs(self):
        """Test create_async_http_transport with additional kwargs."""
        server = MagicMock()
        transport = create_async_http_transport(
            server,
            host="0.0.0.0",
            port=5001,
            enable_sse=False,
            request_timeout=60.0,
        )
        
        assert transport.config.host == "0.0.0.0"
        assert transport.config.port == 5001
        assert transport.config.enable_sse is False
        assert transport.config.request_timeout == 60.0


# =============================================================================
# Edge Case Tests
# =============================================================================

class TestEdgeCases:
    """Tests for edge cases and error handling."""
    
    def test_config_immutable_defaults(self):
        """Test that default lists are not shared between instances."""
        config1 = HTTPTransportConfig()
        config2 = HTTPTransportConfig()
        
        config1.cors_origins.append("https://test.com")
        
        # config2 should not be affected
        assert "https://test.com" not in config2.cors_origins
    
    def test_transport_server_reference(self):
        """Test transport maintains server reference."""
        server = MagicMock()
        transport = MCPHTTPTransport(server)
        
        assert transport.mcp_server is server
    
    def test_multiple_transports_same_server(self):
        """Test multiple transports can use same server."""
        server = MagicMock()
        
        transport1 = MCPHTTPTransport(server, HTTPTransportConfig(port=7000))
        transport2 = MCPHTTPTransport(server, HTTPTransportConfig(port=7001))
        
        assert transport1.mcp_server is transport2.mcp_server
        assert transport1.config.port != transport2.config.port


@pytest.mark.asyncio
class TestAsyncEdgeCases:
    """Async edge case tests."""
    
    async def test_double_stop(self):
        """Test stopping twice doesn't error."""
        server = MagicMock()
        server._handle_message = AsyncMock()
        transport = AsyncMCPHTTPTransport(server, HTTPTransportConfig(port=9030))
        
        await transport.start_background()
        await transport.stop()
        await transport.stop()  # Should not raise
    
    async def test_stop_clears_sse_clients(self):
        """Test stop clears SSE client list."""
        server = MagicMock()
        server._handle_message = AsyncMock()
        transport = AsyncMCPHTTPTransport(server, HTTPTransportConfig(port=9031))
        
        await transport.start_background()
        
        # Manually add a mock client
        mock_writer = MagicMock()
        mock_writer.close = MagicMock()
        mock_writer.wait_closed = AsyncMock()
        transport._sse_clients.add(mock_writer)
        
        await transport.stop()
        
        assert len(transport._sse_clients) == 0


# =============================================================================
# Import Tests
# =============================================================================

class TestImports:
    """Test module imports."""
    
    def test_transport_module_imports(self):
        """Test all transport classes are importable."""
        from shakka.mcp.transport import (
            HTTPTransportConfig,
            MCPHTTPHandler,
            MCPHTTPTransport,
            AsyncMCPHTTPTransport,
            create_http_transport,
            create_async_http_transport,
        )
        
        assert HTTPTransportConfig is not None
        assert MCPHTTPHandler is not None
        assert MCPHTTPTransport is not None
        assert AsyncMCPHTTPTransport is not None
    
    def test_main_package_imports(self):
        """Test transport is importable from main mcp package."""
        from shakka.mcp import (
            HTTPTransportConfig,
            MCPHTTPTransport,
            AsyncMCPHTTPTransport,
            create_http_transport,
            create_async_http_transport,
        )
        
        assert HTTPTransportConfig is not None
        assert MCPHTTPTransport is not None
        assert AsyncMCPHTTPTransport is not None
