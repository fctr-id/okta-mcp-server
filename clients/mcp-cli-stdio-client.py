"""
STDIO MCP Client for Okta MCP Server
Connects directly to an Okta MCP server via STDIO transport.
"""

import os
import sys
import json
import asyncio
import logging
from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt
from rich.syntax import Syntax
from dotenv import load_dotenv
from pydantic_ai import Agent
from pydantic_ai.models.gemini import GeminiModel
from pydantic_ai.models.openai import OpenAIModel
from pydantic_ai.providers.google_vertex import GoogleVertexProvider
from pydantic_ai.providers.openai import OpenAIProvider
from pydantic_ai.mcp import MCPServerStdio
from openai import AsyncAzureOpenAI

# Add the parent directory to sys.path to enable imports
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from okta_mcp.utils.model_provider import get_model
from okta_mcp.utils.mcp_logging_utils import (
    setup_protocol_logging, 
    get_client_logger,
    format_json_with_newlines,
    LoggingMCPServerStdio
)

# Load environment variables
load_dotenv()

# Configure console
console = Console()

# Setup loggers
protocol_logger, fs_logger = setup_protocol_logging()
client_logger = get_client_logger("mcp_stdio_client")

# Determine if we're in debug mode
DEBUG_MODE = os.getenv('DEBUG', 'false').lower() == 'true'

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

def load_env_vars():
    """Load all environment variables from .env file and current environment."""
    # Start with current environment variables
    all_vars = dict(os.environ)
    
    # Also explicitly read from .env file to ensure we get everything
    env_path = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '.env'))
    if os.path.exists(env_path):
        with open(env_path, 'r') as f:
            for line in f:
                line = line.strip()
                # Skip comments and empty lines
                if line and not line.startswith('#') and '=' in line:
                    key, value = line.split('=', 1)
                    all_vars[key.strip()] = value.strip()
    
    protocol_logger.info(f"Loaded {len(all_vars)} environment variables")
    return all_vars

# Server configuration
PYTHON_PATH = "../venv/Scripts/python"
SERVER_SCRIPT = "../main.py"

ENV_VARS = load_env_vars()

class OktaMCPStdioClient:
    """Client that connects to Okta MCP server using STDIO transport."""
    
    def __init__(self):
        self.model = get_model()
        self.agent = None
        self.mcp_server = None   
        
        # Log which model is being used
        provider = os.getenv('AI_PROVIDER', 'openai').lower()
        console.print(f"[bold]Using AI provider: {provider}[/]")    
    
    async def connect(self):
        """Connect to the MCP server using STDIO transport."""
        console.print("[bold]Connecting to Okta MCP server via STDIO...[/]")
        
        try:
            protocol_logger.info("Initializing server...")
            fs_logger.info("Initializing server...")
            
            # Capture MCP Server methods for introspection
            protocol_logger.info(f"MCPServerStdio methods: {[m for m in dir(MCPServerStdio) if not m.startswith('_') and callable(getattr(MCPServerStdio, m))]}")
            
            # Create the LoggingMCPServerStdio instance
            self.mcp_server = LoggingMCPServerStdio(
                PYTHON_PATH,
                [SERVER_SCRIPT],
                env=ENV_VARS,
                protocol_logger=protocol_logger,
                fs_logger=fs_logger
            )
            
            # Create the agent with the MCP server
            self.agent = Agent(
                model=self.model,
                system_prompt=system_prompt,
                mcp_servers=[self.mcp_server],
                retries=2
            )
            
            protocol_logger.info("Server started and connected successfully")
            fs_logger.info("Server started and connected successfully")
            
            console.print(Panel.fit(
                "[bold green]Ready to connect to Okta MCP Server via STDIO[/]",
                title="Connection Status"
            ))
            
            return True
            
        except Exception as e:
            protocol_logger.error(f"Error setting up MCP client: {e}")
            fs_logger.error(f"Error setting up MCP client: {e}")
            console.print(Panel(
                f"[bold red]Error setting up MCP client:[/]\n{str(e)}",
                title="Setup Error",
                border_style="red"
            ))
            return False
    
    async def test_connection(self):
        """Test the connection by making a simple request."""
        try:
            protocol_logger.info("Testing connection...")
            fs_logger.info("Testing connection...")
            
            async with self.agent.run_mcp_servers():
                # If we get here, the connection is working
                protocol_logger.info("Connection test successful")
                fs_logger.info("Connection test successful")
                return True
        except Exception as e:
            protocol_logger.error(f"Connection test failed: {e}")
            fs_logger.error(f"Connection test failed: {e}")
            return False
    
    async def process_query(self, query: str):
        """Process a user query using the agent with STDIO transport."""
        if not self.agent:
            raise ValueError("Agent not initialized")
        
        with console.status(f"[bold green]Processing query: {query}"):
            try:
                # Log that we're about to process a query
                protocol_logger.info(f"Processing query: {query}")
                fs_logger.info(f"Processing query: {query}")
                
                # Add direct console logging for visibility
                console.print(f"[dim]Starting query processing...[/]")
                
                # Run the query through the agent
                async with self.agent.run_mcp_servers():
                    # Log MCP servers are running
                    protocol_logger.info("MCP servers started for query")
                    fs_logger.info("MCP servers started for query")
                    
                    # Log the start of the agent run
                    protocol_logger.info("Starting agent.run(query)")
                    fs_logger.info("Starting agent.run(query)")
                    
                    # Execute the query
                    result = await self.agent.run(query)
                    
                    # Log the completion of the query
                    protocol_logger.info("Agent.run completed successfully")
                    fs_logger.info("Agent.run completed successfully")
                    
                    # Try to log all messages exchanged
                    try:
                        if hasattr(result, 'all_messages'):
                            messages = result.all_messages()
                            protocol_logger.info(f"Message exchange count: {len(messages)}")
                            fs_logger.info(f"Message exchange count: {len(messages)}")
                            
                            for i, msg in enumerate(messages):
                                # Convert to string in case it's not serializable
                                msg_str = str(msg)
                                try:
                                    if isinstance(msg, dict):
                                        msg_str = json.dumps(msg, default=str)
                                except:
                                    pass
                                
                                protocol_logger.info(f"Message {i}: {msg_str}")
                                fs_logger.info(f"Message {i}: {msg_str}")
                    except Exception as e:
                        protocol_logger.error(f"Error logging messages: {e}")
                        fs_logger.error(f"Error logging messages: {e}")
                    
                    # Always print detailed output in debug mode
                    if DEBUG_MODE:
                        console.print("[cyan]===== Full message exchange =====[/]")
                        console.print(result.all_messages())
                    else:
                        console.print("[green]Query processed successfully[/]")
                    
                    return result.data
                    
            except Exception as e:
                protocol_logger.error(f"Error processing query: {e}")
                fs_logger.error(f"Error processing query: {e}")
                console.print(f"[bold red]Query processing error: {e}[/]")
                return f"Error processing query: {str(e)}"

    async def inspect_tool_definitions(self):
        """Show what tool definitions the LLM actually sees."""
        try:
            console.print("[yellow]Inspecting tool definitions...[/]")
            protocol_logger.info("Inspecting tool definitions")
            fs_logger.info("Inspecting tool definitions")
            
            if not self.mcp_server:
                raise ValueError("MCP Server not initialized")
                
            async with self.agent.run_mcp_servers():
                tools = await self.mcp_server.list_tools()
                
                # Log the tools we found
                protocol_logger.info(f"Found {len(tools) if tools else 0} tools")
                fs_logger.info(f"Found {len(tools) if tools else 0} tools")
                
                console.print(Panel(
                    format_json_with_newlines(tools),
                    title="Tool Definitions",
                    border_style="yellow"
                ))
                
                return tools
        except Exception as e:
            protocol_logger.error(f"Error inspecting tool definitions: {e}")
            fs_logger.error(f"Error inspecting tool definitions: {e}")
            console.print(f"[bold red]Error inspecting tools: {e}[/]")
            return f"Error: {str(e)}"

async def interactive_client():
    """Run an interactive session with the STDIO client."""
    client = OktaMCPStdioClient()
    
    try:
        if not await client.connect():
            return
        
        # Test the connection to make sure it's working
        if not await client.test_connection():
            console.print("[bold yellow]Warning: Connection test failed. Functionality may be limited.[/]")
        
        console.print("\n[bold cyan]Okta MCP STDIO Client[/]")
        console.print("Type 'exit' to quit")
        console.print("Type 'tools' to show available tools")
        console.print("Type 'debug on' to enable debug mode")
        console.print("Type 'debug off' to disable debug mode")
        
        while True:
            try:
                query = Prompt.ask("\n[bold]Enter your query")
                
                # Handle special commands
                query_lower = query.lower().strip()
                
                # Exit command
                if query_lower in ("exit", "quit"):
                    break
                
                # Debug mode commands
                if query_lower == "debug on":
                    os.environ['DEBUG'] = 'true'
                    console.print("[green]Debug mode enabled[/]")
                    continue
                
                if query_lower == "debug off":
                    os.environ['DEBUG'] = 'false'
                    console.print("[green]Debug mode disabled[/]")
                    continue
                
                # Tools inspection command
                if query_lower in ("tools", "tool", "?"):
                    await client.inspect_tool_definitions()
                    continue
                
                # Process normal query
                result = await client.process_query(query)
                
                # Display structured result if available
                if result:
                    # Parse the result if it's a string, or use it directly if it's already an object
                    if isinstance(result, str):
                        try:
                            # Try to parse if it's a JSON string
                            result_obj = json.loads(result)
                        except json.JSONDecodeError:
                            # Not valid JSON, use as is
                            result_obj = result
                    else:
                        result_obj = result
                    
                    # Re-serialize the object with proper formatting and no escaping
                    if isinstance(result_obj, (dict, list)):
                        formatted_result = json.dumps(result_obj, indent=2, ensure_ascii=False)
                    else:
                        formatted_result = str(result_obj)
                    
                    result_syntax = Syntax(
                        formatted_result,
                        "json",
                        theme="github-dark",
                        line_numbers=True,
                        word_wrap=True
                    )
                    
                    console.print(Panel(
                        formatted_result,
                        title="Structured Result",
                        border_style="green"
                    ))
                
            except KeyboardInterrupt:
                console.print("\n[yellow]Command interrupted[/]")
                break
            except Exception as e:
                client_logger.error(f"Error in interactive loop: {e}")
                fs_logger.error(f"Error in interactive loop: {e}")
                console.print(f"[bold red]Error: {e}[/]")
    
    finally:
        protocol_logger.info("Client session ended")
        fs_logger.info("Client session ended")

if __name__ == "__main__":
    try:
        asyncio.run(interactive_client())
    except KeyboardInterrupt:
        console.print("\n[italic]Client terminated by user[/]")
        protocol_logger.info("Client terminated by keyboard interrupt")
        fs_logger.info("Client terminated by keyboard interrupt")
    except Exception as e:
        client_logger.error(f"Unhandled error: {e}")
        protocol_logger.error(f"Unhandled error: {e}")
        fs_logger.error(f"Unhandled error: {e}")
        console.print(f"[bold red]Unhandled error: {e}[/]")