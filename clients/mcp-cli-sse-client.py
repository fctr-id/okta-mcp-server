"""
Advanced MCP Client with LLM Agent integration
Connects to an Okta MCP server and uses PydanticAI to process queries.
Shows detailed message exchange between LLM and MCP server.
"""

import os
import json
import asyncio
import logging
from typing import Dict, Any, Optional, List
from enum import Enum
from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt
from rich.table import Table
from rich.syntax import Syntax
from dotenv import load_dotenv
from pydantic_ai import Agent
from pydantic_ai.models.gemini import GeminiModel
from pydantic_ai.models.openai import OpenAIModel
from pydantic_ai.providers.google_vertex import GoogleVertexProvider
from pydantic_ai.providers.openai import OpenAIProvider
from pydantic_ai.mcp import MCPServerHTTP
from openai import AsyncAzureOpenAI

# Load environment variables at startup
load_dotenv()

# Configure rich console for pretty output
console = Console()

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("mcp_agent_client")

# Determine if we're in debug mode
DEBUG_MODE = logger.getEffectiveLevel() <= logging.DEBUG

# Server connection parameters for SSE
SERVER_URL = "http://localhost:3000/sse"

class AIProvider(str, Enum):
    VERTEX_AI = "vertex_ai"
    OPENAI = "openai"
    AZURE_OPENAI = "azure_openai"
    OPENAI_COMPATIBLE = "openai_compatible"

class ModelConfig:
    @staticmethod
    def get_reasoning_model():
        """Get the reasoning model based on configured provider"""
        provider = os.getenv('AI_PROVIDER', 'vertex_ai').lower()
        
        if provider == AIProvider.VERTEX_AI:
            service_account = os.getenv('GOOGLE_APPLICATION_CREDENTIALS') or os.getenv('VERTEX_AI_SERVICE_ACCOUNT_FILE')
            project_id = os.getenv('VERTEX_AI_PROJECT')
            region = os.getenv('VERTEX_AI_LOCATION', 'us-central1')
            
            reasoning_model_name = os.getenv('VERTEX_AI_REASONING_MODEL', 'gemini-1.5-pro')
            
            vertex_provider = GoogleVertexProvider(
                service_account_file=service_account,
                project_id=project_id,
                region=region
            )
            
            return GeminiModel(
                reasoning_model_name,
                provider=vertex_provider
            )
        
        elif provider == AIProvider.OPENAI_COMPATIBLE:
            openai_compat_provider = OpenAIProvider(
                base_url=os.getenv('OPENAI_COMPATIBLE_BASE_URL'),
                api_key=os.getenv('OPENAI_COMPATIBLE_TOKEN')
            )
            
            reasoning_model_name = os.getenv('OPENAI_COMPATIBLE_REASONING_MODEL')
            
            return OpenAIModel(
                model_name=reasoning_model_name,
                provider=openai_compat_provider
            )
            
        elif provider == AIProvider.OPENAI:
            # Create OpenAI provider
            openai_provider = OpenAIProvider(
                api_key=os.getenv('OPENAI_API_KEY')
            )
            
            return OpenAIModel(
                model_name=os.getenv('OPENAI_REASONING_MODEL', 'gpt-4'),
                provider=openai_provider
            )
            
        elif provider == AIProvider.AZURE_OPENAI:
            # Create Azure OpenAI client
            azure_client = AsyncAzureOpenAI(
                azure_endpoint=os.getenv('AZURE_OPENAI_ENDPOINT'),
                api_version=os.getenv('AZURE_OPENAI_VERSION', '2024-07-01-preview'),
                api_key=os.getenv('AZURE_OPENAI_KEY')
            )
            
            # Create OpenAI provider with the Azure client
            azure_provider = OpenAIProvider(openai_client=azure_client)
            
            return OpenAIModel(
                model_name=os.getenv('AZURE_OPENAI_REASONING_DEPLOYMENT', 'gpt-4'),
                provider=azure_provider
            )
        
        # Default fallback to OpenAI if provider not recognized
        return OpenAIModel(
            model_name='gpt-4',
            provider=OpenAIProvider(api_key=os.getenv('OPENAI_API_KEY'))
        )

def format_json(obj: Any) -> str:
    """Format an object as JSON for display."""
    try:
        if hasattr(obj, 'model_dump'):
            obj = obj.model_dump()
        elif hasattr(obj, 'dict'):
            obj = obj.dict()
            
        # Format with nice indentation and handle newlines
        json_str = json.dumps(obj, indent=2, default=str)
        json_str = json_str.replace('\\n', '\n')
        return json_str
    except Exception:
        return str(obj)

def format_messages(messages: List[Any]) -> str:
    """Format message history for better readability."""
    formatted = []
    
    for i, msg in enumerate(messages, 1):
        try:
            if hasattr(msg, 'kind'):
                if msg.kind == 'request':
                    formatted.append(f"[bold yellow]===== REQUEST #{i} =====[/]")
                    
                    for part in msg.parts:
                        part_kind = getattr(part, 'part_kind', 'unknown')
                        
                        if part_kind == 'system-prompt':
                            formatted.append(f"[cyan]SYSTEM PROMPT:[/]")
                            formatted.append(f"{part.content}")
                        elif part_kind == 'user-prompt':
                            formatted.append(f"[green]USER PROMPT:[/]")
                            formatted.append(f"{part.content}")
                        else:
                            formatted.append(f"[blue]{part_kind.upper()}:[/]")
                            formatted.append(f"{getattr(part, 'content', str(part))}")
                
                elif msg.kind == 'response':
                    formatted.append(f"[bold cyan]===== RESPONSE #{i} =====[/]")
                    formatted.append(f"[dim]Model: {getattr(msg, 'model_name', 'unknown')}[/]")
                    
                    for part in msg.parts:
                        part_kind = getattr(part, 'part_kind', 'unknown')
                        
                        if part_kind == 'text':
                            formatted.append(f"[white]TEXT RESPONSE:[/]")
                            formatted.append(f"{part.content}")
                        
                        elif part_kind == 'tool-call':
                            formatted.append(f"[magenta]TOOL CALL: {part.tool_name}[/]")
                            
                            # Try to get arguments using different possible attributes
                            args = None
                            if hasattr(part, 'args'):
                                args = part.args
                            elif hasattr(part, 'arguments'):
                                args = part.arguments
                            
                            if args:
                                # Format tool arguments
                                args_str = format_json(args)
                                formatted.append(f"[yellow]ARGUMENTS:[/]")
                                formatted.append(f"{args_str}")
                            else:
                                formatted.append("[yellow]ARGUMENTS: None[/]")
                        
                        elif part_kind == 'tool-result':
                            formatted.append(f"[bright_green]TOOL RESULT:[/]")
                            
                            # Format tool result
                            content = getattr(part, 'content', None)
                            if content:
                                result_str = format_json(content)
                                formatted.append(f"{result_str}")
                            else:
                                formatted.append("No result content available")
                        
                        else:
                            formatted.append(f"[blue]{part_kind.upper()}:[/]")
                            content = getattr(part, 'content', str(part))
                            formatted.append(f"{content}")
            
            else:
                # For messages that don't have a 'kind' attribute
                formatted.append(f"[dim]Message #{i}: {str(msg)}[/]")
                
        except Exception as e:
            formatted.append(f"[red]Error formatting message #{i}: {e}[/]")
            formatted.append(f"[dim]{msg}[/]")
    
    return "\n".join(formatted)

class OktaMCPAgent:
    """Client that connects to Okta MCP server using PydanticAI's built-in MCP client."""
    
    def __init__(self):
        self.mcp_server = None
        self.agent = None
        self.model = None
    
    async def connect(self):
        """Connect to the MCP server and initialize the agent."""
        console.print("[bold]Connecting to Okta MCP server...[/]")
        
        try:
            # Create the MCP server connection using PydanticAI's MCPServerHTTP
            self.mcp_server = MCPServerHTTP(url=SERVER_URL)
            
            # Load the LLM model
            self.model = ModelConfig.get_reasoning_model()
            
            # Create the agent with the MCP server
            self.agent = Agent(
                model=self.model,
                mcp_servers=[self.mcp_server]
            )
            
            console.print(Panel.fit(
                "[bold green]Connected to Okta MCP Server[/]",
                title="Connection Status"
            ))
            
            return True
            
        except Exception as e:
            logger.error(f"Error connecting to MCP server: {e}")
            console.print(Panel(
                f"[bold red]Error connecting to MCP server:[/]\n{str(e)}",
                title="Connection Error",
                border_style="red"
            ))
            return False
    
    async def process_query(self, query: str):
        """Process a user query using the agent and show message exchange."""
        if not self.agent:
            raise ValueError("Agent not initialized")
        
        with console.status(f"[bold green]Processing query: {query}"):
            try:
                # Use the built-in MCP server runner context manager
                async with self.agent.run_mcp_servers():
                    result = await self.agent.run(query)
                    
                    # Only print all messages in debug mode
                    if DEBUG_MODE:
                        logger.debug("Full message exchange:")
                        console.print(result.all_messages())
                    else:
                        # In non-debug mode, just print a simple confirmation
                        console.print("[green]Query processed successfully[/]")
                
                return result.data
            except Exception as e:
                logger.error(f"Error processing query: {e}")
                return f"Error processing query: {str(e)}"
            
    async def inspect_tool_definitions(self):
        """Show what tool definitions the LLM actually sees."""
        try:
            console.print("[yellow]Inspecting tool definitions...[/]")
            
            # Access the MCP server directly instead
            if not self.mcp_server:
                raise ValueError("MCP Server not initialized")
                
            # Use the MCP server's list_tools method directly
            async with self.agent.run_mcp_servers():
                # The MCPServerHTTP class should have a list_tools method
                tools = await self.mcp_server.list_tools()
                
                # Print the exact tool definitions
                console.print(Panel(
                    format_json(tools),
                    title="Raw Tool Definitions Sent to LLM",
                    border_style="yellow"
                ))
                
                return tools
        except Exception as e:
            logger.error(f"Error inspecting tool definitions: {e}")
            return f"Error: {str(e)}"            

async def interactive_agent():
    """Run an interactive session with the agent."""
    # Create the client
    client = OktaMCPAgent()
    
    try:
        # Connect to the MCP server
        if not await client.connect():
            return
        
        # Never show tool definitions automatically - avoid unnecessary calls
        # Even in debug mode, user must explicitly request tools listing
        
        console.print("\n[bold cyan]Okta MCP Agent[/]")
        console.print("Type 'exit' to quit")
        console.print("Type 'tools' to show available tools")
        
        while True:
            try:
                query = Prompt.ask("\n[bold]Enter your query")
                
                # Handle special commands
                query_lower = query.lower()
                
                # Exit command
                if query_lower in ("exit", "quit"):
                    break
                
                # Tools inspection command
                if query_lower in ("tools", "tool", "?"):
                    await client.inspect_tool_definitions()
                    continue
                
                # Process normal query
                result = await client.process_query(query)
                
                # Display structured result if available
                if result:
                    formatted_result = format_json(result)
                    result_syntax = Syntax(
                        formatted_result, 
                        "json", 
                        theme="monokai",
                        line_numbers=True,
                        word_wrap=True
                    )
                    
                    console.print(Panel(
                        result_syntax,
                        title="Structured Result",
                        border_style="green"
                    ))
                
            except KeyboardInterrupt:
                console.print("\n[yellow]Command interrupted[/]")
                break
            except Exception as e:
                logger.error(f"Error in interactive loop: {e}")
                console.print(f"[bold red]Error: {e}[/]")
    
    finally:
        # No cleanup needed
        pass

if __name__ == "__main__":
    try:
        asyncio.run(interactive_agent())
    except KeyboardInterrupt:
        console.print("\n[italic]Client terminated by user[/]")
    except Exception as e:
        logger.error(f"Unhandled error: {e}")
        console.print(f"[bold red]Unhandled error: {e}[/]")
    finally:
        console.print("[bold green]Goodbye![/]")