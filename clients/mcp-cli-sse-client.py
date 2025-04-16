"""
Advanced MCP Client with LLM Agent integration
Connects to an Okta MCP server and uses PydanticAI to process queries.
Shows detailed message exchange between LLM and MCP server.
"""

import os, sys
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
from pydantic_ai.mcp import MCPServerHTTP

# Load environment variables at startup
load_dotenv()

# Configure rich console for pretty output
console = Console()

# Add the parent directory to sys.path to enable imports
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from okta_mcp.utils.model_provider import get_model


# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("mcp_agent_client")

# Determine if we're in debug mode
DEBUG_MODE = logger.getEffectiveLevel() <= logging.DEBUG

# Server connection parameters for SSE
SERVER_URL = "http://localhost:3000/sse"

system_prompt = """
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
            
        2. If asked anythin question regarding logs or evemts or activity where you have to use the get_okta_event_logs ttol, make sure you know what event codes to search. If you are unsure let the user know that they have to provide specific event codes to search for    

        ### Core Concepts ###
        
    NOTE: Make ssure you use list_okta_ tools to first get okta unique entity ID and then use the get_okta otools with that ID to get additonal information    
        
    1. User Access:
        - Users can access applications through direct assignment or group membership
        - DO NOT show application assignments when asked about users unless specifically asked about it
        - Users are identified by email or login
        - User status can be: STAGED, PROVISIONED (also known as pending user action), ACTIVE, PASSWORD_RESET, PASSWORD_EXPIRED, LOCKED_OUT, SUSPENDED , DEPROVISIONED
        - ALways list users and groups of all statuses unless specifically asked for a particular status
    
    2. Applications:
        - Applications have a technical name and a user-friendly label
        - Applications can be active or inactive
        - Always prefer ACTIVE applications only unless specified
        - Applications can be assigned to users directly or to groups
        - APplications are assigned to Policies and polciies can have multiple rules 
        - Each rule will have conditions and also the 2 factors that are required for the rule to be satisfied
    
    3. Groups:
        - Groups can be assigned to applications
        - Users can be members of multiple groups
    
    4. Authentication:
        - Users can have multiple authentication factors
        - Factors include: email, SMS, push, security questions, etc.
        - Factors can be active or inactive

        ##Key Columns to provide in output##
        - Always use the following columns when answering queries unless more more less are asked in the query
        - For user related query Users: email, login, first_name, last_name, status
        - groups: name
        - applications: label, status
        - factors: factor_type, provider, status
        - Access / Authentication policy: Try to understand the flow and provide a human readable summary for each rule. do NOT just dump the json result
        
"""

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
            
            # Load the LLM model using the centralized model_provider
            self.model = get_model()
            
            # Create the agent with the MCP server
            self.agent = Agent(
                model=self.model,
                system_prompt=system_prompt,
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
                
                return result.output
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
    console.print("[bold]AI Provider Selected:[/]", os.getenv('AI_PROVIDER', 'openai'))
    
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