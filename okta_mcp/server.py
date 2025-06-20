"""Main MCP server implementation for Okta."""
import os
import logging
from typing import List
from fastmcp import FastMCP, Context
from fastmcp.client.sampling import RequestContext, SamplingMessage, SamplingParams

logger = logging.getLogger("okta_mcp")

async def sampling_handler(
    messages: List[SamplingMessage],
    params: SamplingParams,
    ctx: RequestContext,
) -> str:
    """Handle sampling requests using configured AI model."""
    
    try:
        from okta_mcp.utils.model_provider import get_model
        
        model = get_model()
        system_instruction = params.systemPrompt or "You are a helpful assistant"
        
        payload = [{"role": "system", "content": system_instruction}]
        for m in messages:
            if m.content.type == "text":
                payload.append({"role": "user", "content": m.content.text})
        
        response = model.chat.completions.create(
            messages=payload,
            model="gpt-4o-mini",
            max_tokens=getattr(params, 'maxTokens', 150)
        )
        
        return response.choices[0].message.content
        
    except Exception as e:
        logger.error(f"Sampling error: {e}")
        return f"AI processing failed: {str(e)}"

def create_server():
    """Create and configure the MCP server."""
    try:
        # Create server with sampling handler
        mcp = FastMCP("Okta MCP Server")
        
        # Register sampling handler (try different methods)
        if hasattr(mcp, 'set_sampling_handler'):
            mcp.set_sampling_handler(sampling_handler)
        else:
            mcp.sampling_handler = sampling_handler
        
        # Rest of your existing setup...
        from okta_mcp.utils.okta_client import create_okta_client, OktaMcpClient
        
        logger.info("Initializing Okta client")
        okta_client = create_okta_client(
            org_url=os.getenv("OKTA_CLIENT_ORGURL"),
            api_token=os.getenv("OKTA_API_TOKEN")
        )
        
        from okta_mcp.utils.request_manager import RequestManager
        concurrent_limit = int(os.getenv("OKTA_CONCURRENT_LIMIT", "15"))
        request_manager = RequestManager(concurrent_limit)
        
        okta_mcp_client = OktaMcpClient(okta_client, request_manager=request_manager)
        
        from okta_mcp.tools.tool_registry import ToolRegistry
        registry = ToolRegistry()
        
        logger.info("Initializing tool registry")
        registry.initialize_server(mcp)
        
        logger.info("Registering tools")
        registry.register_all_tools(mcp, okta_mcp_client)
        
        mcp.request_manager = request_manager
        
        logger.info("MCP server created successfully with sampling handler")
        return mcp
    
    except Exception as e:
        logger.error(f"Error creating MCP server: {e}")
        raise

# Keep your existing run functions unchanged
def run_with_stdio(server):
    """Run the server with STDIO transport."""
    logger.info("Starting server with STDIO transport")
    server.run()

def run_with_sse(server, host="0.0.0.0", port=3000, reload=False):
    """Run the server with SSE transport (deprecated)."""
    logger.warning("SSE transport is deprecated, use --http instead")
    logger.info(f"Starting server with SSE transport on {host}:{port}")
    
    app = server.sse_app()
    
    import uvicorn
    uvicorn.run(app, host=host, port=port, reload=reload)

def run_with_http(server, host="0.0.0.0", port=3000):
    """Run the server with HTTP transport."""
    logger.info("Starting server with HTTP transport")
    
    try:
        server.run(transport="streamable-http", host=host, port=port)
    except TypeError:
        logger.warning("FastMCP doesn't accept host/port, using defaults")
        server.run(transport="streamable-http")

if __name__ == "__main__":
    server = create_server()
    run_with_stdio(server)