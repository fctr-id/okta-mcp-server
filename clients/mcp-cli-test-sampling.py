"""Custom FastMCP client with sampling support using model provider and pydantic-ai Agent."""

import sys
import os
import asyncio

# Add the parent directory to Python path so we can import okta_mcp
project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, project_root)

print(f"Added to Python path: {project_root}")

from fastmcp import Client
from okta_mcp.utils.model_provider import get_model
from pydantic_ai import Agent

class SamplingAgent:
    """Agent-based sampling handler using model provider."""
    
    def __init__(self):
        self.model = get_model()
        print(f"🤖 Model type: {type(self.model)}")
        print(f"✅ SamplingAgent initialized with pydantic-ai model")
    
    async def handle_sampling(self, messages, params, context):
        """Handle sampling requests using pydantic-ai Agent - THE CORRECT WAY."""
        
        print(f"📋 Agent sampling request received:")
        print(f"  Messages: {len(messages)}")
        print(f"  System prompt: {params.systemPrompt[:100] if params.systemPrompt else 'None'}...")
        
        try:
            # Extract the user message content
            user_content = ""
            for msg in messages:
                if msg.content.type == "text":
                    user_content += msg.content.text + " "
            
            user_content = user_content.strip()
            print(f"🔤 User content: {user_content}")
            
            # Create an agent with the specific system prompt from the request
            system_prompt = params.systemPrompt or "You are a helpful assistant."
            
            print(f"🤖 Creating Agent with pydantic-ai model...")
            
            # THIS IS THE CORRECT WAY - Use Agent, not direct model calls
            agent = Agent(
                model=self.model,
                system_prompt=system_prompt,
                retries=2
            )
            
            print(f"🎯 Running agent.run() with user content...")
            
            # Use the agent to run the request
            result = await agent.run(user_content)
            
            # Extract the response from RunResult
            response_text = result.output if hasattr(result, 'output') else str(result)
            print(f"✅ Agent Response: {response_text}")
            
            return response_text
            
        except Exception as e:
            print(f"❌ Agent sampling error: {e}")
            import traceback
            traceback.print_exc()
            return f"Agent Error: {str(e)}"

async def test_client():
    """Test the client with agent-based sampling support."""
    
    print("🧪 Testing model provider...")
    try:
        model = get_model()
        print(f"✅ Model provider working: {type(model)}")
    except Exception as e:
        print(f"❌ Model provider failed: {e}")
        return
    
    # Create the sampling agent
    try:
        sampling_agent = SamplingAgent()
        print("✅ Sampling agent created successfully")
    except Exception as e:
        print(f"❌ Failed to create sampling agent: {e}")
        return
    
    # Connect to your running server with agent-based sampling
    async with Client("http://localhost:3000/sse", sampling_handler=sampling_agent.handle_sampling) as client:
        print("🔗 Connected to server with agent-based sampling")
        
        # List available tools
        tools = await client.list_tools()
        
        # Handle tools response
        tool_names = []
        if hasattr(tools, 'tools'):
            tool_names = [t.name for t in tools.tools]
        elif isinstance(tools, dict) and 'tools' in tools:
            tool_names = [t.get('name', 'unnamed') for t in tools['tools']]
        
        print(f"📋 Available tools: {tool_names}")
        
        # Test the agent-powered sampling
        print("\n🧪 Testing list_okta_users with agent-based natural language processing...")
        
        try:
            result = await client.call_tool("list_okta_users", {
                "query": "Find users whose first name starts with Dan"
            })
            
            print(f"📊 Result: {result}")
        except Exception as e:
            print(f"❌ Tool call error: {e}")

if __name__ == "__main__":
    asyncio.run(test_client())