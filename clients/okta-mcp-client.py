"""
Unified MCP Client for Okta MCP Server
Supports multiple transports 
"""

import os
import sys
import json
import asyncio
import logging
import argparse
from typing import Optional, Dict, Any, List
from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt
from dotenv import load_dotenv

from pydantic_ai import Agent
from pydantic_ai.mcp import MCPServerStdio, MCPServerStreamableHTTP

# Add the parent directory to sys.path to enable imports
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

# Import our custom modules
from okta_mcp.utils.model_provider import get_model
from okta_mcp.utils.logging import (
    configure_logging,
    setup_protocol_logging, 
    get_client_logger,
    LoggingMCPServerStdio
)

# Initialize Rich console
console = Console()

def load_env_vars():
    """Load all environment variables."""
    # load_dotenv() automatically merges .env into os.environ
    load_dotenv()
    return dict(os.environ)

class OktaMCPClient:
    """Unified MCP client with AI integration for Okta."""
    
    def __init__(self, transport_type: str = "stdio", server_url: Optional[str] = None, 
                 server_path: str = "./main.py", debug: bool = False):
        self.transport_type = transport_type
        self.server_url = server_url
        self.server_path = server_path
        self.debug = debug
        self.agent: Optional[Agent] = None
        self.mcp_server = None
        
        # Simplified logging setup
        log_level = getattr(logging, os.getenv('LOG_LEVEL', 'INFO').upper(), logging.INFO)
        
        configure_logging(console_level=logging.INFO, log_level=log_level, suppress_mcp_logs=True)
        self.protocol_logger, self.fs_logger = setup_protocol_logging(show_fs_logs=False, log_level=log_level)
        self.client_logger = get_client_logger("okta_mcp_client")
        
        # Get model from existing provider
        try:
            self.model = get_model()
            provider = os.getenv('AI_PROVIDER', 'openai').lower()
            console.print(f"[bold]Using AI provider: {provider}[/]")
        except Exception as e:
            raise Exception(f"Failed to initialize model: {e}")
        
        # System prompt for Okta
        self.system_prompt = """
        ## Role & Expertise
        You are an expert Okta AI assistant using Okta Python SDK tools. You understand Okta APIs, identities, groups, applications, policies, and factors in an enterprise setting.

        ## Core Objective
        Accurately answer Okta-related queries by using the provided tools to fetch data and strictly adhere to the output formats defined below.
        
        ## Output Formatting

        1.  **Default:** **STRICTLY JSON.** Output ONLY valid JSON. No explanations, summaries, or extra text unless specified otherwise.
            ```json
            { "results": [...] }
            ```
        2.  **Exception - Auth Policy/Access Rules:** When asked about **application access requirements** (e.g., "Do I need MFA?", "VPN required?") or directly about **Authentication Policies/Rules**:
            *   Provide a **human-readable summary** explaining each relevant rule's conditions (network, group, risk, etc.) and outcomes (allow, deny, require factor).
            *   Do **NOT** output the raw policy/rule JSON for these summaries.
        3.  **Errors:** Use a JSON error format: `{ "error": "Description of error." }`. If you lack specific knowledge (like event codes), state that: `{ "error": "I do not have knowledge of specific Okta event codes." }`    
        
        ## Handling Specific Query Types

            1.  **Application Access Questions ("Can user X access app Y?", "What's needed for app Z?"):**
                *   **YOU MUST FOLLOW THESE STEPS and PROVIDE THE RESPONSE in MARKDOWN:**
                    *   list_okta_users_tool and make sure the user exists and is in ACTIVE state. If Not, stop here and report the issue
                    *   Application ID (prioritize ACTIVE apps unless specified) and list if the app is not ACTIVE and Stop.
                    *   Groups assigned to the application.
                    *   Authentication Policy applied to the application and list_okta_policy_rules
                    *   **For each Policy Rule:** Use the `get_okta_policy_rule` tool **on the rule itself** to get detailed conditions and required factors/factor names.
                    *   If a user is specified: fetch the user's groups and factors using `list_okta_groups_tool` and `list_okta_factors_tool`.
                *   **MUST Respond With:**
                    *   The human-readable summary of the applicable policy rules (as per Output Rule #2).
                    *   A statement listing the required group(s) for app access.
                    *   If user specified: Compare user's groups/factors to requirements and state if they *appear* to meet them based *only* on fetched data.
                *   **DO NOT** show the raw JSON for the user's groups or factors in the final output for these access questions. Structure the combined summary/group info/user assessment clearly (e.g., within a structured JSON response).    
                
            2. If asked anything question regarding logs or events or activity where you have to use the get_okta_event_logs tool, make sure you know what event codes to search. If you are unsure let the user know that they have to provide specific event codes to search for    

            ### Core Concepts ###
            
        NOTE: Make sure you use list_okta_ tools to first get okta unique entity ID and then use the get_okta tools with that ID to get additional information    
            
        1. User Access:
            - Users can access applications through direct assignment or group membership
            - DO NOT show application assignments when asked about users unless specifically asked about it
            - Users are identified by email or login
            - User status can be: STAGED, PROVISIONED (also known as pending user action), ACTIVE, PASSWORD_RESET, PASSWORD_EXPIRED, LOCKED_OUT, SUSPENDED , DEPROVISIONED
            - Always list users and groups of all statuses unless specifically asked for a particular status
        
        2. Applications:
            - Applications have a technical name and a user-friendly label
            - Applications can be active or inactive
            - Always prefer ACTIVE applications only unless specified
            - Applications can be assigned to users directly or to groups
            - Applications are assigned to Policies and policies can have multiple rules 
            - Each rule will have conditions and also the 2 factors that are required for the rule to be satisfied
        
        3. Groups:
            - Groups can be assigned to applications
            - Users can be members of multiple groups
        
        4. Authentication:
            - Users can have multiple authentication factors
            - Factors include: email, SMS, push, security questions, etc.
            - Factors can be active or inactive

            ##Key Columns to provide in output##
            - Always use the following columns when answering queries unless more or less are asked in the query
            - For user related query Users: email, login, first_name, last_name, status
            - groups: name
            - applications: label, status
            - factors: factor_type, provider, status
            - Access / Authentication policy: Try to understand the flow and provide a human readable summary for each rule. do NOT just dump the json result
        """
    
    async def connect(self) -> bool:
        """Establish connection to MCP server and initialize AI agent."""
        try:
            console.print("[bold]Connecting to Okta MCP server...[/]")
            
            # Load environment variables
            env_vars = load_env_vars()
            
            self.protocol_logger.info("Initializing server...")
            
            # Create MCP server with logging wrapper
            if self.transport_type == "stdio":
                self.protocol_logger.info(f"MCPServerStdio methods: {[m for m in dir(MCPServerStdio) if not m.startswith('_') and callable(getattr(MCPServerStdio, m))]}")
                
                self.mcp_server = LoggingMCPServerStdio(
                    "python",
                    [self.server_path],
                    env=env_vars,
                    protocol_logger=self.protocol_logger,
                    fs_logger=self.fs_logger
                )
                
            elif self.transport_type == "http":
                if not self.server_url:
                    raise Exception("Server URL required for HTTP transport")
                self.protocol_logger.info("Creating HTTP MCP server")
                
                # Simple logging wrapper for HTTP transport
                class LoggingHTTP(MCPServerStreamableHTTP):
                    def __init__(self, url, protocol_logger):
                        super().__init__(url)
                        self.protocol_logger = protocol_logger
                    
                    async def call_tool(self, name, parameters=None, **kwargs):
                        self.protocol_logger.info(f"Directly calling tool: {name}")
                        return await super().call_tool(name, parameters, **kwargs)
                
                self.mcp_server = LoggingHTTP(self.server_url, self.protocol_logger)
                    
            else:
                raise Exception(f"Unsupported transport type: {self.transport_type}")
            
            # Create agent with MCP server
            self.agent = Agent(
                model=self.model,
                system_prompt=self.system_prompt,
                mcp_servers=[self.mcp_server],
                retries=2
            )
            
            self.protocol_logger.info("Server started and connected successfully")
            
            console.print(Panel.fit(
                "[bold green]Ready to connect to Okta MCP Server[/]",
                title="Connection Status"
            ))
            
            return True
            
        except Exception as e:
            self.protocol_logger.error(f"Error setting up MCP client: {e}")
            console.print(f"[red]Failed to connect: {e}[/red]")
            raise Exception(f"Failed to connect: {e}")
    
    async def process_query(self, query: str) -> str:
        """Process a user query."""
        if not self.agent:
            raise ValueError("Agent not initialized")
        
        try:
            console.print("[bold green]Processing query...[/]")
            
            async with self.agent.run_mcp_servers():
                self.protocol_logger.info("MCP servers started for query")
                
                result = await self.agent.run(query)
                
                # Show debug info if enabled
                if self.debug:
                    console.print("[cyan]===== Full message exchange =====[/]")
                    console.print(result.all_messages())
                else:
                    console.print("[green]Query processed successfully[/]")
                
                return result.output
                
        except Exception as e:
            self.protocol_logger.error(f"Error processing query: {e}")
            console.print(f"[bold red]Query processing error: {e}[/]")
            return f"Error processing query: {str(e)}"
    
    async def interactive_shell(self):
        """Run interactive shell for continuous queries."""
        if not self.agent:
            raise Exception("Client not connected. Call connect() first.")
        
        console.print("\n[bold cyan]Okta MCP Client[/]")
        console.print("Type 'exit' to quit")
        console.print("Type 'tools' to show available tools")
        console.print("Type 'debug on' to enable debug mode")
        console.print("Type 'debug off' to disable debug mode")
        
        try:
            while True:
                try:
                    query = Prompt.ask("\n[bold yellow]Enter your query")
                    
                    if not query.strip():
                        continue
                    
                    query_lower = query.lower().strip()
                    
                    if query_lower in ["quit", "exit", "q"]:
                        break
                    elif query_lower == "debug on":
                        self.debug = True
                        console.print("[green]Debug mode enabled[/green]")
                        continue
                    elif query_lower == "debug off":
                        self.debug = False
                        console.print("[green]Debug mode disabled[/green]")
                        continue
                    elif query_lower in ["tools", "tool", "?"]:
                        await self._inspect_tools()
                        continue
                    
                    # Process normal query
                    result = await self.process_query(query)
                    
                    # Display result
                    if result:
                        try:
                            result_obj = json.loads(result)
                            formatted_result = json.dumps(result_obj, indent=2, ensure_ascii=False)
                        except json.JSONDecodeError:
                            formatted_result = result
                        
                        console.print(Panel(
                            formatted_result,
                            title="Result",
                            border_style="green"
                        ))
                
                except KeyboardInterrupt:
                    console.print("\n[yellow]Command interrupted[/]")
                    break
                except Exception as e:
                    self.protocol_logger.error(f"Error in interactive loop: {e}")
                    console.print(f"[bold red]Error: {e}[/]")
        
        except KeyboardInterrupt:
            console.print("\n[yellow]Interrupted by user[/yellow]")
        finally:
            self.protocol_logger.info("Client session ended")
    
    def _serialize_tool_definition(self, tool_def) -> Dict[str, Any]:
        """Convert ToolDefinition object to serializable dictionary."""
        try:
            # Handle different types of tool definitions
            if hasattr(tool_def, 'model_dump'):
                # Pydantic model
                return tool_def.model_dump()
            elif hasattr(tool_def, 'dict'):
                # Pydantic v1 model
                return tool_def.dict()
            elif hasattr(tool_def, '__dict__'):
                # Regular object with __dict__
                result = {}
                for key, value in tool_def.__dict__.items():
                    if not key.startswith('_'):
                        try:
                            # Try to serialize the value
                            json.dumps(value)
                            result[key] = value
                        except (TypeError, ValueError):
                            # If value is not serializable, convert to string
                            result[key] = str(value)
                return result
            else:
                # Fallback to string representation
                return {"name": str(tool_def), "description": "Unable to serialize tool definition"}
        except Exception as e:
            return {"name": "unknown", "error": f"Serialization failed: {str(e)}"}
    
    async def _inspect_tools(self) -> Optional[List[Dict[str, Any]]]:
        """Show available tools."""
        try:
            console.print("[yellow]Inspecting available tools...[/]")
            
            if not self.mcp_server:
                raise ValueError("MCP Server not initialized")
                
            async with self.agent.run_mcp_servers():
                tools = await self.mcp_server.list_tools()
                
                if tools:
                    # Convert ToolDefinition objects to serializable dictionaries
                    serialized_tools = []
                    for tool in tools:
                        serialized_tool = self._serialize_tool_definition(tool)
                        serialized_tools.append(serialized_tool)
                    
                    # Create a nice summary view
                    tool_summary = []
                    for tool in serialized_tools:
                        name = tool.get('name', 'Unknown')
                        description = tool.get('description', 'No description')
                        # Truncate long descriptions
                        if len(description) > 100:
                            description = description[:97] + "..."
                        
                        tool_summary.append({
                            "name": name,
                            "description": description
                        })
                    
                    console.print(Panel(
                        json.dumps(tool_summary, indent=2, ensure_ascii=False),
                        title=f"Available Tools ({len(tool_summary)} found)",
                        border_style="yellow"
                    ))
                    
                    if self.debug:
                        console.print("\n[cyan]Full tool definitions:[/]")
                        console.print(Panel(
                            json.dumps(serialized_tools, indent=2, ensure_ascii=False),
                            title="Detailed Tool Definitions",
                            border_style="cyan"
                        ))
                    
                    return serialized_tools
                else:
                    console.print(Panel(
                        "No tools found",
                        title="Tool Definitions",
                        border_style="red"
                    ))
                    return []
                    
        except Exception as e:
            console.print(f"[bold red]Error inspecting tools: {e}[/]")
            if self.debug:
                import traceback
                console.print(f"[red]Traceback: {traceback.format_exc()}[/]")
            return None

async def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(description="Okta MCP Client")
    parser.add_argument("--server", help="Path to server script for STDIO transport")
    parser.add_argument("--http", help="HTTP URL for streamable HTTP transport")
    parser.add_argument("--debug", action="store_true", help="Enable debug mode")
    parser.add_argument("--query", "-q", help="Run a single query and exit")
    
    args = parser.parse_args()
    
    # Determine transport
    if args.server:
        transport_type = "stdio"
        server_url = None
        server_path = args.server
    elif args.http:
        transport_type = "http" 
        server_url = args.http
        server_path = None
    else:
        console.print("[red]Error:[/red] No transport specified. Use --server or --http")
        return 1
    
    try:
        # Create and connect client
        client = OktaMCPClient(
            transport_type=transport_type,
            server_url=server_url,
            server_path=server_path,
            debug=args.debug
        )
        
        await client.connect()
        
        # Run query or interactive shell
        if args.query:
            console.print(f"[blue]Query:[/blue] {args.query}")
            result = await client.process_query(args.query)
            
            if result:
                try:
                    result_obj = json.loads(result)
                    formatted_result = json.dumps(result_obj, indent=2, ensure_ascii=False)
                except json.JSONDecodeError:
                    formatted_result = result
                
                console.print(Panel(
                    formatted_result,
                    title="Result",
                    border_style="green"
                ))
        else:
            await client.interactive_shell()
            
        return 0
        
    except Exception as e:
        console.print(f"[red]Error:[/red] {e}")
        return 1

if __name__ == "__main__":
    try:
        sys.exit(asyncio.run(main()))
    except KeyboardInterrupt:
        console.print("\n[yellow]Interrupted by user[/yellow]")
        sys.exit(0)
    except Exception as e:
        console.print(f"[red]Unexpected error: {e}[/red]")
        sys.exit(1)