# FastMCP v2.10 Reference Guide

> **Document Purpose**: This document captures key learnings about FastMCP v2.10 implementation details discovered during the OAuth server migration. Use this as a reference for future version updates.

## Table of Contents

1. [Context Structure Changes](#context-structure-changes)
2. [Middleware System](#middleware-system)
3. [Custom Routes](#custom-routes)
4. [Server Initialization](#server-initialization)
5. [Error Handling](#error-handling)
6. [Common Patterns](#common-patterns)
7. [Migration Notes](#migration-notes)

---

## Context Structure Changes

### Key Finding: Message Parameter Access

**FastMCP v2.10 changed how middleware accesses message parameters.**

#### ❌ Old Pattern (Pre-v2.10)
```python
# This DOES NOT work in v2.10
tool_name = context.message.params.get("name", "unknown")
arguments = context.message.params.get("arguments", {})
uri = context.message.params.get("uri", "unknown")
```

#### ✅ New Pattern (v2.10+)
```python
# Tool execution context
tool_name = getattr(context.message, 'name', "unknown")
arguments = getattr(context.message, 'arguments', {})

# Resource access context  
uri = getattr(context.message, 'uri', "unknown")
```

### Context Object Structure

```python
class MiddlewareContext:
    message: object          # The MCP message object
    method: str             # MCP method name (e.g., "tools/call")
    source: str             # "client" or "server"
    type: str               # "request" or "notification"
    timestamp: datetime     # When request was received
    fastmcp_context: object # FastMCP Context object (if available)
```

### Safe Attribute Access Pattern

```python
def safe_get_message_attr(context: MiddlewareContext, attr: str, default=None):
    """Safely get attribute from context message"""
    return getattr(context.message, attr, default)

# Usage
tool_name = safe_get_message_attr(context, 'name', "unknown")
arguments = safe_get_message_attr(context, 'arguments', {})
```

---

## Middleware System

### Middleware Class Structure

```python
from fastmcp.server.middleware import Middleware, MiddlewareContext
from mcp.types import ErrorData
from mcp import McpError

class CustomMiddleware(Middleware):
    def __init__(self, *args, **kwargs):
        super().__init__()
        # Custom initialization
    
    # Available hooks (implement only what you need)
    async def on_message(self, context: MiddlewareContext, call_next):
        """Called for ALL MCP messages"""
        pass
    
    async def on_request(self, context: MiddlewareContext, call_next):
        """Called for requests that expect responses"""
        pass
    
    async def on_notification(self, context: MiddlewareContext, call_next):
        """Called for fire-and-forget notifications"""
        pass
    
    async def on_list_tools(self, context: MiddlewareContext, call_next):
        """Called when listing tools"""
        pass
    
    async def on_call_tool(self, context: MiddlewareContext, call_next):
        """Called when executing tools"""
        pass
    
    async def on_list_resources(self, context: MiddlewareContext, call_next):
        """Called when listing resources"""
        pass
    
    async def on_read_resource(self, context: MiddlewareContext, call_next):
        """Called when reading resources"""
        pass
    
    async def on_list_prompts(self, context: MiddlewareContext, call_next):
        """Called when listing prompts"""
        pass
    
    async def on_get_prompt(self, context: MiddlewareContext, call_next):
        """Called when getting prompts"""
        pass
```

### Hook Execution Order

**Multiple hooks are called for the same request in this order:**

1. `on_message` (for ALL messages)
2. `on_request` OR `on_notification` (based on message type)
3. Operation-specific hook (e.g., `on_call_tool`)

### Common Middleware Patterns

#### 1. Authentication Middleware
```python
async def on_call_tool(self, context: MiddlewareContext, call_next):
    # Get authentication info
    user_info = self.get_current_user()
    
    if not user_info:
        raise McpError(ErrorData(code=-32000, message="Authentication required"))
    
    # Continue to next middleware/handler
    return await call_next(context)
```

#### 2. RBAC Filtering Middleware
```python
async def on_list_tools(self, context: MiddlewareContext, call_next):
    user_info = self.get_current_user()
    user_role = user_info.get('role', 'viewer')
    
    # Get all tools
    result = await call_next(context)
    
    # Filter based on permissions
    if isinstance(result, list):
        filtered = [tool for tool in result if self.can_access(tool.name, user_role)]
        return filtered
    
    return result
```

#### 3. Error Handling Pattern
```python
async def on_call_tool(self, context: MiddlewareContext, call_next):
    tool_name = "unknown"  # Initialize early!
    try:
        tool_name = getattr(context.message, 'name', "unknown")
        
        result = await call_next(context)
        return result
        
    except McpError:
        # Re-raise MCP errors as-is
        raise
    except Exception as e:
        # Log and convert to MCP error
        logger.error(f"Tool '{tool_name}' failed: {e}")
        raise McpError(ErrorData(code=-32000, message=f"Tool execution error: {str(e)}"))
```

### Middleware Registration

```python
# Single middleware
mcp.add_middleware(CustomMiddleware())

# Multiple middleware (execution order matters)
mcp.add_middleware(AuthMiddleware())     # Runs first
mcp.add_middleware(LoggingMiddleware())  # Runs second
mcp.add_middleware(TimingMiddleware())   # Runs third
```

---

## Custom Routes

### Route Registration Pattern

```python
@mcp.custom_route("/path", methods=["GET", "POST", "OPTIONS"])
async def custom_endpoint(request: Request) -> Response:
    """Custom route handler"""
    
    # Handle CORS preflight
    if request.method == "OPTIONS":
        return Response(
            status_code=200,
            headers={
                "Access-Control-Allow-Origin": "*",
                "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
                "Access-Control-Allow-Headers": "Content-Type, Authorization"
            }
        )
    
    # Handle actual request
    try:
        # Route logic here
        return JSONResponse({"status": "success"})
    except Exception as e:
        return JSONResponse({"error": str(e)}, status_code=500)
```

### Query Parameters and Form Data

```python
# Query parameters
client_id = request.query_params.get('client_id')
redirect_uri = request.query_params.get('redirect_uri')

# Form data (async)
form_data = await request.form()
grant_type = form_data.get("grant_type")

# JSON body (async)
json_data = await request.json()

# Headers
auth_header = request.headers.get("authorization", "")
user_agent = request.headers.get("user-agent", "")
```

### Response Types

```python
# JSON Response
return JSONResponse({"key": "value"})

# HTML Response
return Response(html_content, media_type="text/html")

# Redirect Response
return RedirectResponse(url)

# Custom headers
response = JSONResponse(data)
response.headers["Custom-Header"] = "value"
return response
```

---

## Server Initialization

### Basic Server Setup

```python
from fastmcp import FastMCP

# Create server
mcp = FastMCP(
    name="Server Name",
    instructions="Server description"
)

# Register tools
@mcp.tool
def my_tool(param: str) -> str:
    return f"Result: {param}"

# Register custom routes
@mcp.custom_route("/api/endpoint")
async def custom_route(request: Request):
    return JSONResponse({"message": "success"})

# Add middleware
mcp.add_middleware(CustomMiddleware())

# Create ASGI app
app = mcp.http_app()
```

### With HTTP Middleware (Starlette)

```python
from starlette.middleware.sessions import SessionMiddleware
from starlette.middleware.base import BaseHTTPMiddleware

# Create HTTP app first
app = mcp.http_app()

# Add Starlette middleware
app.add_middleware(
    SessionMiddleware,
    secret_key="your-secret-key",
    max_age=7200
)

# Custom HTTP middleware
class CustomHTTPMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        # Pre-processing
        response = await call_next(request)
        # Post-processing
        return response

app.add_middleware(CustomHTTPMiddleware)
```

---

## Error Handling

### MCP Error Types

```python
from mcp.types import ErrorData
from mcp import McpError

# Standard MCP error
raise McpError(ErrorData(
    code=-32000,  # Application error code
    message="Error description"
))

# With additional data
raise McpError(ErrorData(
    code=-32000,
    message="Validation failed",
    data={"field": "value"}
))
```

### Error Code Conventions

- `-32000`: Generic application error
- `-32001`: Authentication required
- `-32002`: Authorization failed
- `-32003`: Resource not found
- `-32004`: Invalid parameters

### Exception Handling in Middleware

```python
async def on_call_tool(self, context: MiddlewareContext, call_next):
    try:
        return await call_next(context)
    except McpError:
        # Re-raise MCP errors unchanged
        raise
    except ValueError as e:
        # Convert to MCP error
        raise McpError(ErrorData(code=-32004, message=f"Invalid parameter: {e}"))
    except Exception as e:
        # Generic error handling
        logger.error(f"Unexpected error: {e}")
        raise McpError(ErrorData(code=-32000, message="Internal server error"))
```

---

## Common Patterns

### 1. Safe Attribute Access

```python
def safe_get(obj, attr, default=None):
    """Safely get attribute with fallback"""
    return getattr(obj, attr, default)

# Usage in middleware
tool_name = safe_get(context.message, 'name', "unknown")
```

### 2. Variable Initialization

```python
# Always initialize variables that might be used in exception handlers
async def on_call_tool(self, context: MiddlewareContext, call_next):
    tool_name = "unknown"  # Initialize early!
    try:
        tool_name = getattr(context.message, 'name', "unknown")
        # ... rest of logic
    except Exception as e:
        # tool_name is guaranteed to be defined
        logger.error(f"Error in tool '{tool_name}': {e}")
```

### 3. Async Context Management

```python
# HTTP client in middleware
async def middleware_method(self, context, call_next):
    async with httpx.AsyncClient() as client:
        response = await client.get("https://api.example.com")
        # Process response
    
    return await call_next(context)
```

### 4. Session Access

```python
# Check if session is available
try:
    if hasattr(request, 'session'):
        request.session['key'] = 'value'
except Exception as e:
    logger.debug(f"Session not available: {e}")
```

---

## Migration Notes

### Breaking Changes in v2.10

1. **Context Structure**: Direct parameter access changed
2. **Middleware Hooks**: Some hook signatures may have changed
3. **Error Handling**: More strict error type requirements

### Compatibility Strategies

#### 1. Version Detection
```python
def get_tool_name_from_context(context):
    """Get tool name with version compatibility"""
    # Try v2.10+ format first
    if hasattr(context.message, 'name'):
        return getattr(context.message, 'name', "unknown")
    
    # Fallback to older format
    if hasattr(context.message, 'params'):
        return context.message.params.get('name', "unknown")
    
    return "unknown"
```

#### 2. Graceful Degradation
```python
async def safe_middleware_call(self, context: MiddlewareContext, call_next):
    """Middleware with fallback patterns"""
    try:
        # Try v2.10 pattern
        tool_name = getattr(context.message, 'name', None)
        if tool_name is None:
            # Fallback to older pattern
            tool_name = context.message.params.get('name', 'unknown')
    except AttributeError:
        tool_name = "unknown"
    
    # Continue with logic...
```

### Testing Compatibility

```python
def test_context_access():
    """Test different context access patterns"""
    # Mock context for testing
    class MockContext:
        def __init__(self, name, args):
            self.message = type('Message', (), {
                'name': name,
                'arguments': args
            })()
    
    context = MockContext("test_tool", {"param": "value"})
    
    # Test access patterns
    assert getattr(context.message, 'name') == "test_tool"
    assert getattr(context.message, 'arguments') == {"param": "value"}
```

---

## Troubleshooting

### Common Issues

1. **AttributeError on context.message.params**
   - **Cause**: Using pre-v2.10 context access pattern
   - **Solution**: Use `getattr(context.message, 'attribute', default)`

2. **UnboundLocalError in exception handling**
   - **Cause**: Variable not initialized before try block
   - **Solution**: Initialize variables early: `tool_name = "unknown"`

3. **Middleware not executing**
   - **Cause**: Wrong hook method name or registration order
   - **Solution**: Check hook spelling and middleware registration

4. **Custom routes not working**
   - **Cause**: Missing HTTP app creation or middleware conflicts
   - **Solution**: Ensure `app = mcp.http_app()` is called

### Debug Patterns

```python
# Debug middleware execution
async def on_call_tool(self, context: MiddlewareContext, call_next):
    logger.debug(f"Middleware called: {context.method}")
    logger.debug(f"Message type: {type(context.message)}")
    logger.debug(f"Message attrs: {dir(context.message)}")
    
    try:
        result = await call_next(context)
        logger.debug(f"Middleware completed successfully")
        return result
    except Exception as e:
        logger.error(f"Middleware error: {e}")
        raise
```

---

## Future Proofing

### Strategies for Version Updates

1. **Abstraction Layer**: Create helper functions for common operations
2. **Version Detection**: Check for attribute existence before access
3. **Comprehensive Testing**: Test all middleware hooks and custom routes
4. **Documentation**: Keep this document updated with each version change

### Recommended Abstractions

```python
class FastMCPCompatibility:
    """Compatibility layer for FastMCP versions"""
    
    @staticmethod
    def get_tool_name(context: MiddlewareContext) -> str:
        """Get tool name with version compatibility"""
        return getattr(context.message, 'name', "unknown")
    
    @staticmethod
    def get_tool_arguments(context: MiddlewareContext) -> dict:
        """Get tool arguments with version compatibility"""
        return getattr(context.message, 'arguments', {})
    
    @staticmethod
    def get_resource_uri(context: MiddlewareContext) -> str:
        """Get resource URI with version compatibility"""
        return getattr(context.message, 'uri', "unknown")
```

---

## Version History

- **v2.10**: Current implementation with direct message attribute access
- **Pre-v2.10**: Used `context.message.params` for parameter access

---

*Last Updated: January 6, 2025*  
*FastMCP Version: 2.10*  
*Migration Context: Okta MCP OAuth Server*
