"""
Streamable HTTP MCP Client for Okta MCP Server
Connects to an Okta MCP server via Streamable HTTP transport (modern, recommended).
"""
import os
import sys
import asyncio
import json
import re
from typing import Dict, Any, Optional, List
from enum import Enum
from datetime import datetime

from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt
from rich.syntax import Syntax
from rich.table import Table
from rich.text import Text
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich import print as rprint

from dotenv import load_dotenv
from pydantic_ai import Agent
from pydantic_ai.mcp import MCPServerStreamableHTTP
from pydantic_ai.models import Model

# Load environment variables
load_dotenv()

class AIProvider(Enum):
    OPENAI = "openai"
    ANTHROPIC = "anthropic"
    AZURE_OPENAI = "azure_openai"
    VERTEX_AI = "vertex_ai"
    OPENAI_COMPATIBLE = "openai_compatible"

def parse_json_from_response(response: str) -> tuple[str, bool]:
    """
    Parse JSON content from markdown code blocks or return cleaned response.
    Returns (cleaned_content, is_json_format)
    """
    if not response:
        return response, False
    
    # Try to extract JSON from markdown code blocks
    json_match = re.search(r'```json\s*\n(.*?)\n```', response, re.DOTALL | re.IGNORECASE)
    if json_match:
        json_content = json_match.group(1).strip()
        try:
            # Validate it's proper JSON
            parsed = json.loads(json_content)
            # Return pretty-formatted JSON
            return json.dumps(parsed, indent=2), True
        except json.JSONDecodeError:
            # If JSON is invalid, return the content without code blocks
            return json_content, False
    
    # Try to extract any code block content
    code_match = re.search(r'```.*?\n(.*?)\n```', response, re.DOTALL)
    if code_match:
        return code_match.group(1).strip(), False
    
    # Check if the response itself is valid JSON (without code blocks)
    try:
        parsed = json.loads(response.strip())
        return json.dumps(parsed, indent=2), True
    except json.JSONDecodeError:
        pass
    
    # No code blocks found, return original
    return response, False

class OktaMCPStreamableClient:
    """
    MCP Client for connecting to Okta MCP Server via Streamable HTTP transport.
    Uses PydanticAI Agent with LLM integration.
    """
    
    def __init__(self, server_url: str = None, debug: bool = False):
        self.console = Console()
        self.debug = debug
        self.server_url = server_url or "http://localhost:8000/mcp"
        self.model = self._get_model()
        self.agent = None
        self.mcp_server = None
        
        # System prompt for the agent
        self.system_prompt = """
        You are an expert Okta administrator assistant with access to Okta MCP tools.
        
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

    def _get_model(self) -> Model:
        """Get the configured AI model based on environment variables."""
        provider = os.getenv('AI_PROVIDER', 'openai').lower()
        
        try:
            if provider == AIProvider.OPENAI.value:
                api_key = os.getenv('OPENAI_API_KEY')
                if not api_key:
                    raise ValueError("OPENAI_API_KEY environment variable is required")
                model_name = os.getenv('OPENAI_MODEL', 'gpt-4o')
                return f"openai:{model_name}"
                
            elif provider == AIProvider.ANTHROPIC.value:
                api_key = os.getenv('ANTHROPIC_API_KEY')
                if not api_key:
                    raise ValueError("ANTHROPIC_API_KEY environment variable is required")
                model_name = os.getenv('ANTHROPIC_MODEL', 'claude-3-5-sonnet-20241022')
                return f"anthropic:{model_name}"
                
            elif provider == AIProvider.AZURE_OPENAI.value:
                endpoint = os.getenv('AZURE_OPENAI_ENDPOINT')
                api_key = os.getenv('AZURE_OPENAI_API_KEY')
                if not endpoint or not api_key:
                    raise ValueError("AZURE_OPENAI_ENDPOINT and AZURE_OPENAI_API_KEY are required")
                model_name = os.getenv('AZURE_OPENAI_DEPLOYMENT_NAME', 'gpt-4o')
                return f"azure:{model_name}"
                
            elif provider == AIProvider.VERTEX_AI.value:
                project = os.getenv('GOOGLE_CLOUD_PROJECT')
                if not project:
                    raise ValueError("GOOGLE_CLOUD_PROJECT environment variable is required")
                model_name = os.getenv('VERTEX_AI_MODEL', 'gemini-1.5-pro')
                return f"vertexai:{model_name}"
                
            elif provider == AIProvider.OPENAI_COMPATIBLE.value:
                base_url = os.getenv('OPENAI_COMPATIBLE_BASE_URL')
                api_key = os.getenv('OPENAI_COMPATIBLE_API_KEY', 'dummy')
                if not base_url:
                    raise ValueError("OPENAI_COMPATIBLE_BASE_URL environment variable is required")
                model_name = os.getenv('OPENAI_COMPATIBLE_MODEL', 'gpt-4o')
                return f"openai:{model_name}"
                
            else:
                raise ValueError(f"Unsupported AI provider: {provider}")
                
        except Exception as e:
            self.console.print(f"[red]Error configuring AI model: {e}[/red]")
            self.console.print("[yellow]Falling back to OpenAI GPT-4o[/yellow]")
            return "openai:gpt-4o"

    async def connect(self) -> bool:
        """Connect to the Okta MCP Server via Streamable HTTP."""
        try:
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                console=self.console,
            ) as progress:
                task = progress.add_task("Connecting to Okta MCP Server...", total=None)
                
                # Create MCP server connection
                self.mcp_server = MCPServerStreamableHTTP(self.server_url)
                
                # Create agent with MCP server
                self.agent = Agent(
                    model=self.model,
                    system_prompt=self.system_prompt,
                    mcp_servers=[self.mcp_server]
                )
                
                progress.update(task, description="Testing connection...")
                
                # Test the connection by getting server info
                async with self.agent.run_mcp_servers():
                    # Simple connectivity test
                    result = await self.agent.run("What is the current time?")
                    if self.debug:
                        self.console.print(f"[dim]Connection test result: {result.output}[/dim]")
                
                progress.update(task, description="Connected successfully!")
                
            return True
            
        except Exception as e:
            self.console.print(f"[red]Failed to connect to MCP server: {e}[/red]")
            if self.debug:
                import traceback
                self.console.print(f"[dim]{traceback.format_exc()}[/dim]")
            return False

    async def run_query(self, query: str) -> Optional[str]:
        """Execute a query against the Okta MCP server."""
        if not self.agent:
            self.console.print("[red]Not connected to MCP server. Run connect() first.[/red]")
            return None
            
        try:
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                console=self.console,
            ) as progress:
                task = progress.add_task("Processing query...", total=None)
                
                async with self.agent.run_mcp_servers():
                    result = await self.agent.run(query)
                    
                progress.update(task, description="Query completed!")
                
            # Parse JSON from the response if present
            cleaned_response, is_json = parse_json_from_response(result.output)
            return cleaned_response, is_json
            
        except Exception as e:
            self.console.print(f"[red]Error executing query: {e}[/red]")
            if self.debug:
                import traceback
                self.console.print(f"[dim]{traceback.format_exc()}[/dim]")
            return None, False

    def display_connection_status(self):
        """Display current connection status."""
        status_panel = Panel(
            f"[green]✓[/green] Connected to Okta MCP Server\n"
            f"[blue]Server URL:[/blue] {self.server_url}\n"
            f"[blue]Transport:[/blue] Streamable HTTP\n"
            f"[blue]AI Model:[/blue] {self.model}",
            title="Connection Status",
            border_style="green"
        )
        self.console.print(status_panel)

    def display_help(self):
        """Display help information."""
        help_text = """
[bold blue]Available Commands:[/bold blue]
• [green]help[/green] - Show this help message
• [green]status[/green] - Show connection status
• [green]debug on/off[/green] - Enable/disable debug mode
• [green]tools[/green] - List available Okta tools
• [green]exit[/green] - Exit the client

[bold blue]Example Queries:[/bold blue]
• "List the first 10 users in our Okta tenant"
• "Show me details for user john@company.com"
• "What groups is user jane@company.com in?"
• "List all applications assigned to the Engineering group"
• "Show me users who haven't logged in for 30 days"
• "Get system log events from the last hour"

[bold blue]Time-based Queries:[/bold blue]
• "Show me login events from yesterday"
• "List users created in the last week"
• "Find failed login attempts from the last 24 hours"

[bold blue]Response Format:[/bold blue]
• JSON responses are automatically parsed and syntax-highlighted
• Non-JSON responses are displayed as formatted text
• Use 'debug on' to see raw responses
        """
        
        help_panel = Panel(
            help_text,
            title="Okta MCP Streamable HTTP Client Help",
            border_style="blue"
        )
        self.console.print(help_panel)

    async def list_tools(self):
        """List available tools from the MCP server."""
        if not self.agent:
            self.console.print("[red]Not connected to MCP server.[/red]")
            return
            
        try:
            # Get tools info by querying the agent
            async with self.agent.run_mcp_servers():
                result = await self.agent.run(
                    "List all available Okta tools and briefly describe what each one does. "
                    "Format this as a clear table or list."
                )
                
            self.console.print("\n[bold blue]Available Okta MCP Tools:[/bold blue]")
            self.console.print(result.output)
            
        except Exception as e:
            self.console.print(f"[red]Error listing tools: {e}[/red]")

    def display_response(self, content: str, is_json: bool, duration: float):
        """Display response with appropriate formatting."""
        if is_json:
            # Display as syntax-highlighted JSON
            try:
                syntax = Syntax(
                    content, 
                    "json", 
                    theme="monokai", 
                    line_numbers=True,
                    word_wrap=True
                )
                
                result_panel = Panel(
                    syntax,
                    title=f"JSON Response (took {duration:.2f}s)",
                    border_style="green"
                )
                self.console.print(result_panel)
                
            except Exception as e:
                # Fallback to regular text if syntax highlighting fails
                result_panel = Panel(
                    content,
                    title=f"Response (took {duration:.2f}s)",
                    border_style="green"
                )
                self.console.print(result_panel)
        else:
            # Display as regular text with formatting
            result_panel = Panel(
                content,
                title=f"Response (took {duration:.2f}s)",
                border_style="green"
            )
            self.console.print(result_panel)

async def main():
    """Main CLI interface."""
    console = Console()
    
    # Display welcome message
    console.print(Panel(
        "[bold green]Okta MCP Streamable HTTP Client[/bold green]\n"
        "Modern transport using Streamable HTTP protocol\n"
        "Type 'help' for available commands",
        title="Welcome",
        border_style="green"
    ))
    
    # Get server URL (default to localhost)
    server_url = os.getenv('MCP_SERVER_URL', 'http://localhost:8000/mcp')
    debug_mode = os.getenv('DEBUG', 'false').lower() == 'true'
    
    # Initialize client
    client = OktaMCPStreamableClient(server_url=server_url, debug=debug_mode)
    
    # Connect to server
    console.print(f"\n[blue]Connecting to:[/blue] {server_url}")
    if not await client.connect():
        console.print("[red]Failed to connect to MCP server. Exiting.[/red]")
        return
    
    client.display_connection_status()
    
    # Main interaction loop
    try:
        while True:
            try:
                user_input = Prompt.ask(
                    "\n[bold cyan]Okta Query[/bold cyan]",
                    default=""
                ).strip()
                
                if not user_input:
                    continue
                    
                # Handle special commands
                if user_input.lower() == 'exit':
                    break
                elif user_input.lower() == 'help':
                    client.display_help()
                elif user_input.lower() == 'status':
                    client.display_connection_status()
                elif user_input.lower() == 'tools':
                    await client.list_tools()
                elif user_input.lower() == 'debug on':
                    client.debug = True
                    console.print("[green]Debug mode enabled[/green]")
                elif user_input.lower() == 'debug off':
                    client.debug = False
                    console.print("[green]Debug mode disabled[/green]")
                else:
                    # Execute query
                    start_time = datetime.now()
                    result = await client.run_query(user_input)
                    end_time = datetime.now()
                    
                    if result and result[0]:  # result is now a tuple (content, is_json)
                        content, is_json = result
                        duration = (end_time - start_time).total_seconds()
                        
                        # Show raw response in debug mode
                        if client.debug:
                            console.print(f"[dim]Raw response: {content}[/dim]")
                            console.print(f"[dim]Detected as JSON: {is_json}[/dim]")
                        
                        # Display formatted response
                        client.display_response(content, is_json, duration)
                    
            except (KeyboardInterrupt, EOFError):
                break
            except Exception as e:
                console.print(f"[red]Unexpected error: {e}[/red]")
                if client.debug:
                    import traceback
                    console.print(f"[dim]{traceback.format_exc()}[/dim]")
                    
    except KeyboardInterrupt:
        console.print("\n[yellow]Interrupted by user[/yellow]")
    
    console.print("\n[blue]Goodbye![/blue]")

if __name__ == "__main__":
    asyncio.run(main())