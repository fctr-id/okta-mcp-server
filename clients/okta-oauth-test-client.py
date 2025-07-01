"""
OAuth-Enabled MCP Client for Okta MCP Server Testing
Supports OAuth authentication flow and authorization testing
"""

import os
import sys
import json
import asyncio
import logging
import argparse
import webbrowser
from typing import Optional, Dict, Any, List
from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt, Confirm
from rich.table import Table
from rich.text import Text
from dotenv import load_dotenv
import httpx

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
    load_dotenv()
    return dict(os.environ)

class OAuthFlowHandler:
    """Handle OAuth 2.0 authorization flow for testing"""
    
    def __init__(self, client_id: str, org_url: str):
        self.client_id = client_id
        self.org_url = org_url
        self.access_token: Optional[str] = None
        self.user_info: Optional[Dict] = None
    
    def get_authorization_url(self, redirect_uri: str = "urn:ietf:wg:oauth:2.0:oob") -> str:
        """Generate OAuth authorization URL"""
        base_url = f"{self.org_url}/oauth2/default/v1/authorize"
        scopes = [
            "openid", "profile", "email",
            "okta.users.read", "okta.groups.read", "okta.apps.read",
            "okta.policies.read", "okta.logs.read", "okta.networkZones.read"
        ]
        
        params = {
            "client_id": self.client_id,
            "response_type": "code",
            "scope": " ".join(scopes),
            "redirect_uri": redirect_uri,
            "state": "test-oauth-flow"
        }
        
        query_string = "&".join([f"{k}={v}" for k, v in params.items()])
        return f"{base_url}?{query_string}"
    
    async def exchange_code_for_token(self, code: str, client_secret: str, 
                                     redirect_uri: str = "urn:ietf:wg:oauth:2.0:oob") -> bool:
        """Exchange authorization code for access token"""
        try:
            token_url = f"{self.org_url}/oauth2/default/v1/token"
            
            data = {
                "grant_type": "authorization_code",
                "client_id": self.client_id,
                "client_secret": client_secret,
                "code": code,
                "redirect_uri": redirect_uri
            }
            
            async with httpx.AsyncClient() as client:
                response = await client.post(token_url, data=data)
                response.raise_for_status()
                
                token_data = response.json()
                self.access_token = token_data.get("access_token")
                
                # Decode JWT to get user info (for testing, not verifying signature)
                if self.access_token:
                    import jwt
                    self.user_info = jwt.decode(
                        self.access_token, 
                        options={"verify_signature": False}
                    )
                
                console.print("[green]✅ OAuth token obtained successfully[/]")
                return True
                
        except Exception as e:
            console.print(f"[red]❌ Token exchange failed: {e}[/]")
            return False
    
    def get_bearer_token(self) -> Optional[str]:
        """Get Bearer token for Authorization header"""
        return f"Bearer {self.access_token}" if self.access_token else None

class OktaOAuthMCPClient:
    """OAuth-enabled MCP client for testing Okta authorization features"""
    
    def __init__(self, transport_type: str = "stdio", server_url: Optional[str] = None, 
                 server_path: str = "./okta_oauth_proxy.py", debug: bool = False,
                 test_oauth: bool = False):
        self.transport_type = transport_type
        self.server_url = server_url
        self.server_path = server_path
        self.debug = debug
        self.test_oauth = test_oauth
        self.agent: Optional[Agent] = None
        self.mcp_server = None
        self.oauth_handler: Optional[OAuthFlowHandler] = None
        
        # Simplified logging setup
        log_level = getattr(logging, os.getenv('LOG_LEVEL', 'INFO').upper(), logging.INFO)
        
        configure_logging(console_level=logging.INFO, log_level=log_level, suppress_mcp_logs=True)
        self.protocol_logger, self.fs_logger = setup_protocol_logging(show_fs_logs=False, log_level=log_level)
        self.client_logger = get_client_logger("okta_oauth_mcp_client")
        
        # Get model from existing provider
        try:
            self.model = get_model()
            provider = os.getenv('AI_PROVIDER', 'openai').lower()
            console.print(f"[bold]Using AI provider: {provider}[/]")
        except Exception as e:
            raise Exception(f"Failed to initialize model: {e}")
        
        # Enhanced system prompt for OAuth testing
        self.system_prompt = """
        ## Role & Expertise
        You are an expert Okta AI assistant with OAuth authorization testing capabilities. You understand Okta APIs, identities, groups, applications, policies, and authorization workflows.

        ## Core Objective
        Test and demonstrate OAuth-protected Okta operations while providing clear feedback about authorization success/failure.
        
        ## Output Formatting

        1. **Default:** Valid JSON format with clear structure
        2. **Authorization Testing:** Include authorization context in responses
        3. **Error Handling:** Provide detailed error information for authorization failures
        
        ## Authorization Testing Context
        When testing authorization:
        - Clearly indicate which user/role is making the request
        - Show what permissions were checked
        - Explain why access was granted or denied
        - Suggest alternative approaches for denied requests
        
        ## Enhanced Error Responses
        For authorization errors, provide:
        ```json
        {
          "error": "Authorization failed",
          "details": {
            "required_roles": ["admin"],
            "user_roles": ["user.read"],
            "required_scopes": ["okta.logs.read"],
            "user_scopes": ["okta.users.read"],
            "suggestion": "Contact administrator for elevated privileges"
          }
        }
        ```

        ## Testing Scenarios
        Support testing of:
        - Role-based access control
        - Scope-based permissions
        - Contextual authorization rules
        - Bulk operation limits
        - Time-based restrictions
        - Self-service vs admin operations
        """
    
    async def setup_oauth_flow(self) -> bool:
        """Setup OAuth authentication flow"""
        try:
            client_id = os.getenv("OKTA_OAUTH_CLIENT_ID")
            client_secret = os.getenv("OKTA_OAUTH_CLIENT_SECRET")
            org_url = os.getenv("OKTA_CLIENT_ORGURL")
            
            if not all([client_id, client_secret, org_url]):
                console.print("[red]❌ Missing OAuth configuration. Set OKTA_OAUTH_CLIENT_ID, OKTA_OAUTH_CLIENT_SECRET, and OKTA_CLIENT_ORGURL[/]")
                return False
            
            self.oauth_handler = OAuthFlowHandler(client_id, org_url)
            
            console.print(Panel.fit(
                "[bold yellow]OAuth Authentication Required[/]\n\n"
                "This client will test OAuth-protected endpoints.\n"
                "You'll be redirected to Okta for authentication.",
                title="OAuth Setup"
            ))
            
            if not Confirm.ask("Continue with OAuth flow?", default=True):
                return False
            
            # Get authorization URL
            auth_url = self.oauth_handler.get_authorization_url()
            
            console.print(f"\n[bold]Opening authorization URL:[/]\n{auth_url}")
            
            # Open browser
            if Confirm.ask("Open browser automatically?", default=True):
                webbrowser.open(auth_url)
            else:
                console.print(f"\nPlease visit: {auth_url}")
            
            # Get authorization code
            console.print("\n[yellow]After authorization, you'll receive an authorization code.[/]")
            auth_code = Prompt.ask("Enter the authorization code")
            
            # Exchange code for token
            success = await self.oauth_handler.exchange_code_for_token(auth_code, client_secret)
            
            if success and self.oauth_handler.user_info:
                # Display user info
                user_table = Table(title="Authenticated User Info")
                user_table.add_column("Property", style="cyan")
                user_table.add_column("Value", style="green")
                
                user_info = self.oauth_handler.user_info
                user_table.add_row("User ID", user_info.get("sub", "N/A"))
                user_table.add_row("Email", user_info.get("email", "N/A"))
                user_table.add_row("Name", user_info.get("name", "N/A"))
                user_table.add_row("Roles", ", ".join(user_info.get("roles", [])))
                user_table.add_row("Scopes", user_info.get("scope", "N/A"))
                
                console.print(user_table)
            
            return success
            
        except Exception as e:
            console.print(f"[red]❌ OAuth setup failed: {e}[/]")
            return False
    
    async def connect(self) -> bool:
        """Establish connection to OAuth-protected MCP server"""
        try:
            console.print("[bold]Connecting to OAuth-protected Okta MCP server...[/]")
            
            # Setup OAuth if required
            if self.test_oauth:
                oauth_success = await self.setup_oauth_flow()
                if not oauth_success:
                    return False
            
            # Load environment variables
            env_vars = load_env_vars()
            
            # Add OAuth token to environment if available
            if self.oauth_handler and self.oauth_handler.access_token:
                env_vars["OAUTH_ACCESS_TOKEN"] = self.oauth_handler.access_token
            
            self.protocol_logger.info("Initializing OAuth-protected server...")
            
            # Create MCP server with OAuth support
            if self.transport_type == "stdio":
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
                
                # HTTP transport with OAuth headers
                class OAuthHTTP(MCPServerStreamableHTTP):
                    def __init__(self, url, oauth_handler, protocol_logger):
                        super().__init__(url)
                        self.oauth_handler = oauth_handler
                        self.protocol_logger = protocol_logger
                    
                    async def call_tool(self, name, parameters=None, **kwargs):
                        self.protocol_logger.info(f"OAuth tool call: {name}")
                        
                        # Add Authorization header if we have a token
                        if self.oauth_handler and self.oauth_handler.access_token:
                            # This would need to be implemented in the HTTP transport
                            # For now, log that we would add the header
                            self.protocol_logger.info(f"Would add Authorization header: Bearer {self.oauth_handler.access_token[:20]}...")
                        
                        return await super().call_tool(name, parameters, **kwargs)
                
                self.mcp_server = OAuthHTTP(self.server_url, self.oauth_handler, self.protocol_logger)
                    
            else:
                raise Exception(f"Unsupported transport type: {self.transport_type}")
            
            # Create agent with OAuth-enabled MCP server
            self.agent = Agent(
                model=self.model,
                system_prompt=self.system_prompt,
                mcp_servers=[self.mcp_server],
                retries=2
            )
            
            self.protocol_logger.info("OAuth-protected server connected successfully")
            
            status_text = "OAuth-Protected" if self.test_oauth else "Standard"
            console.print(Panel.fit(
                f"[bold green]Ready to test {status_text} Okta MCP Server[/]",
                title="Connection Status"
            ))
            
            return True
            
        except Exception as e:
            self.protocol_logger.error(f"Error setting up OAuth MCP client: {e}")
            console.print(f"[red]Failed to connect: {e}[/red]")
            raise Exception(f"Failed to connect: {e}")
    
    async def run_authorization_tests(self):
        """Run a suite of authorization tests"""
        if not self.agent:
            raise ValueError("Agent not initialized")
        
        console.print(Panel.fit(
            "[bold yellow]Running Authorization Test Suite[/]",
            title="OAuth Testing"
        ))
        
        test_cases = [
            {
                "name": "Public Tool Access",
                "query": "What time is it?",
                "expected": "Should work - public tool",
                "test_type": "public"
            },
            {
                "name": "User Read Access",
                "query": "List the first 5 Okta users",
                "expected": "Should work if user has user.read role",
                "test_type": "user_read"
            },
            {
                "name": "Admin-Only Access",
                "query": "Get Okta event logs for today",
                "expected": "Should require admin role",
                "test_type": "admin_only"
            },
            {
                "name": "Bulk Operation Limit",
                "query": "List 100 Okta users",
                "expected": "Should be limited for non-admin users",
                "test_type": "bulk_limit"
            },
            {
                "name": "Self-Access Test",
                "query": "Get my own user information",
                "expected": "Should work for own data",
                "test_type": "self_access"
            }
        ]
        
        results = []
        
        for i, test_case in enumerate(test_cases, 1):
            console.print(f"\n[cyan]Test {i}/{len(test_cases)}: {test_case['name']}[/]")
            console.print(f"[dim]Query: {test_case['query']}[/]")
            console.print(f"[dim]Expected: {test_case['expected']}[/]")
            
            try:
                result = await self.process_query(test_case['query'])
                
                # Analyze result for authorization indicators
                success = "error" not in result.lower() and "access denied" not in result.lower()
                
                test_result = {
                    "test": test_case['name'],
                    "query": test_case['query'],
                    "success": success,
                    "result": result[:200] + "..." if len(result) > 200 else result,
                    "type": test_case['test_type']
                }
                
                results.append(test_result)
                
                # Display result
                status = "✅ PASS" if success else "❌ FAIL"
                console.print(f"[green]{status}[/] - Test completed")
                
                if self.debug:
                    console.print(Panel(result[:500], title="Response Preview", border_style="dim"))
                
            except Exception as e:
                console.print(f"[red]❌ ERROR: {e}[/]")
                results.append({
                    "test": test_case['name'],
                    "query": test_case['query'],
                    "success": False,
                    "result": f"Exception: {str(e)}",
                    "type": test_case['test_type']
                })
        
        # Display summary
        self._display_test_summary(results)
        
        return results
    
    def _display_test_summary(self, results: List[Dict]):
        """Display test results summary"""
        summary_table = Table(title="Authorization Test Results")
        summary_table.add_column("Test", style="cyan")
        summary_table.add_column("Type", style="blue")
        summary_table.add_column("Status", style="bold")
        summary_table.add_column("Result Preview", style="dim")
        
        for result in results:
            status = "✅ PASS" if result['success'] else "❌ FAIL"
            preview = result['result'][:50] + "..." if len(result['result']) > 50 else result['result']
            
            summary_table.add_row(
                result['test'],
                result['type'],
                status,
                preview
            )
        
        console.print(summary_table)
        
        # Statistics
        total_tests = len(results)
        passed_tests = sum(1 for r in results if r['success'])
        
        console.print(f"\n[bold]Test Summary: {passed_tests}/{total_tests} tests passed[/]")
    
    async def process_query(self, query: str) -> str:
        """Process a user query with OAuth context"""
        if not self.agent:
            raise ValueError("Agent not initialized")
        
        try:
            # Add OAuth context to query if available
            if self.oauth_handler and self.oauth_handler.user_info:
                user_context = f"[OAuth Context: User={self.oauth_handler.user_info.get('email', 'unknown')}, Roles={self.oauth_handler.user_info.get('roles', [])}] "
                contextual_query = user_context + query
            else:
                contextual_query = query
            
            console.print("[bold green]Processing OAuth-protected query...[/]")
            
            async with self.agent.run_mcp_servers():
                self.protocol_logger.info("OAuth MCP servers started for query")
                
                result = await self.agent.run(contextual_query)
                
                # Show debug info if enabled
                if self.debug:
                    console.print("[cyan]===== Full OAuth message exchange =====[/]")
                    console.print(result.all_messages())
                else:
                    console.print("[green]OAuth query processed successfully[/]")
                
                return result.output
                
        except Exception as e:
            self.protocol_logger.error(f"Error processing OAuth query: {e}")
            console.print(f"[bold red]OAuth query processing error: {e}[/]")
            return f"Error processing OAuth query: {str(e)}"
    
    async def interactive_shell(self):
        """Run interactive shell with OAuth testing capabilities"""
        if not self.agent:
            raise Exception("Client not connected. Call connect() first.")
        
        console.print("\n[bold cyan]Okta OAuth MCP Test Client[/]")
        console.print("Type 'exit' to quit")
        console.print("Type 'tools' to show available tools")
        console.print("Type 'oauth-info' to show OAuth status")
        console.print("Type 'test-auth' to run authorization tests")
        console.print("Type 'debug on/off' to toggle debug mode")
        
        if self.oauth_handler and self.oauth_handler.user_info:
            user_email = self.oauth_handler.user_info.get('email', 'unknown')
            user_roles = self.oauth_handler.user_info.get('roles', [])
            console.print(f"[green]Authenticated as: {user_email} (Roles: {', '.join(user_roles)})[/]")
        
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
                    elif query_lower == "oauth-info":
                        await self._show_oauth_info()
                        continue
                    elif query_lower == "test-auth":
                        await self.run_authorization_tests()
                        continue
                    
                    # Process normal query
                    result = await self.process_query(query)
                    
                    # Display result with OAuth context
                    if result:
                        try:
                            result_obj = json.loads(result)
                            formatted_result = json.dumps(result_obj, indent=2, ensure_ascii=False)
                        except json.JSONDecodeError:
                            formatted_result = result
                        
                        title = "OAuth-Protected Result" if self.test_oauth else "Result"
                        console.print(Panel(
                            formatted_result,
                            title=title,
                            border_style="green"
                        ))
                
                except KeyboardInterrupt:
                    console.print("\n[yellow]Command interrupted[/]")
                    break
                except Exception as e:
                    self.protocol_logger.error(f"Error in OAuth interactive loop: {e}")
                    console.print(f"[bold red]Error: {e}[/]")
        
        except KeyboardInterrupt:
            console.print("\n[yellow]Interrupted by user[/yellow]")
        finally:
            self.protocol_logger.info("OAuth client session ended")
    
    async def _show_oauth_info(self):
        """Display OAuth authentication status"""
        if not self.oauth_handler:
            console.print(Panel(
                "[red]OAuth not configured[/]",
                title="OAuth Status"
            ))
            return
        
        info_table = Table(title="OAuth Authentication Status")
        info_table.add_column("Property", style="cyan")
        info_table.add_column("Value", style="green")
        
        if self.oauth_handler.access_token:
            info_table.add_row("Status", "✅ Authenticated")
            info_table.add_row("Token Present", "Yes")
            
            if self.oauth_handler.user_info:
                user_info = self.oauth_handler.user_info
                info_table.add_row("User ID", user_info.get("sub", "N/A"))
                info_table.add_row("Email", user_info.get("email", "N/A"))
                info_table.add_row("Name", user_info.get("name", "N/A"))
                info_table.add_row("Issuer", user_info.get("iss", "N/A"))
                info_table.add_row("Audience", user_info.get("aud", "N/A"))
                info_table.add_row("Roles", ", ".join(user_info.get("roles", [])))
                info_table.add_row("Scopes", user_info.get("scope", "N/A"))
                
                # Token expiration
                import time
                exp = user_info.get("exp")
                if exp:
                    exp_time = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(exp))
                    info_table.add_row("Expires", exp_time)
        else:
            info_table.add_row("Status", "❌ Not authenticated")
            info_table.add_row("Token Present", "No")
        
        console.print(info_table)
    
    async def _inspect_tools(self):
        """Show available tools with OAuth context"""
        try:
            console.print("[yellow]Inspecting OAuth-protected tools...[/]")
            
            if not self.mcp_server:
                raise ValueError("MCP Server not initialized")
                
            async with self.agent.run_mcp_servers():
                tools = await self.mcp_server.list_tools()
                
                if tools:
                    # Convert tools to serializable format
                    serialized_tools = []
                    for tool in tools:
                        if hasattr(tool, 'model_dump'):
                            serialized_tool = tool.model_dump()
                        elif hasattr(tool, 'dict'):
                            serialized_tool = tool.dict()
                        else:
                            serialized_tool = {"name": str(tool), "description": "Unable to serialize"}
                        serialized_tools.append(serialized_tool)
                    
                    # Create summary view
                    tool_table = Table(title=f"OAuth-Protected Tools ({len(serialized_tools)} found)")
                    tool_table.add_column("Tool Name", style="cyan")
                    tool_table.add_column("Description", style="dim")
                    tool_table.add_column("Auth Required", style="yellow")
                    
                    for tool in serialized_tools:
                        name = tool.get('name', 'Unknown')
                        description = tool.get('description', 'No description')
                        
                        # Truncate long descriptions
                        if len(description) > 80:
                            description = description[:77] + "..."
                        
                        # Guess authorization requirement based on tool name
                        auth_required = "Yes" if not name.startswith(('get_current_time', 'parse_relative_time')) else "No"
                        
                        tool_table.add_row(name, description, auth_required)
                    
                    console.print(tool_table)
                    
                    if self.debug:
                        console.print("\n[cyan]Full tool definitions:[/]")
                        console.print(Panel(
                            json.dumps(serialized_tools, indent=2, ensure_ascii=False),
                            title="Detailed Tool Definitions",
                            border_style="cyan"
                        ))
                else:
                    console.print(Panel(
                        "No tools found",
                        title="OAuth Tool Definitions",
                        border_style="red"
                    ))
                    
        except Exception as e:
            console.print(f"[bold red]Error inspecting OAuth tools: {e}[/]")
            if self.debug:
                import traceback
                console.print(f"[red]Traceback: {traceback.format_exc()}[/]")

async def main():
    """Main entry point for OAuth test client"""
    parser = argparse.ArgumentParser(description="Okta OAuth MCP Test Client")
    parser.add_argument("--server", help="Path to OAuth proxy script for STDIO transport", 
                       default="./okta_oauth_proxy.py")
    parser.add_argument("--http", help="HTTP URL for OAuth-protected HTTP transport")
    parser.add_argument("--debug", action="store_true", help="Enable debug mode")
    parser.add_argument("--query", "-q", help="Run a single query and exit")
    parser.add_argument("--oauth", action="store_true", help="Enable OAuth authentication flow")
    parser.add_argument("--test-auth", action="store_true", help="Run authorization test suite")
    
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
        # Create and connect OAuth client
        client = OktaOAuthMCPClient(
            transport_type=transport_type,
            server_url=server_url,
            server_path=server_path,
            debug=args.debug,
            test_oauth=args.oauth
        )
        
        await client.connect()
        
        # Run authorization tests if requested
        if args.test_auth:
            await client.run_authorization_tests()
            return 0
        
        # Run query or interactive shell
        if args.query:
            console.print(f"[blue]OAuth Query:[/blue] {args.query}")
            result = await client.process_query(args.query)
            
            if result:
                try:
                    result_obj = json.loads(result)
                    formatted_result = json.dumps(result_obj, indent=2, ensure_ascii=False)
                except json.JSONDecodeError:
                    formatted_result = result
                
                title = "OAuth-Protected Result" if args.oauth else "Result"
                console.print(Panel(
                    formatted_result,
                    title=title,
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
