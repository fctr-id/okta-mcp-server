"""
OAuth Proxy Test Client for Okta MCP Server
Tests the OAuth proxy server (confidential client) architecture
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
from rich.progress import track
from dotenv import load_dotenv
import httpx
from datetime import datetime, timedelta

from pydantic_ai import Agent
from pydantic_ai.mcp import MCPServerStreamableHTTP

# Add the parent directory to sys.path to enable imports
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

# Import our custom modules
from okta_mcp.utils.model_provider import get_model
from okta_mcp.utils.logging import (
    configure_logging,
    setup_protocol_logging, 
    get_client_logger
)

# Initialize Rich console
console = Console()

def load_env_vars():
    """Load all environment variables."""
    load_dotenv()
    return dict(os.environ)

class OAuthProxyTester:
    """Test client for OAuth proxy server (confidential client architecture)"""
    
    def __init__(self, proxy_url: str = "http://localhost:3001", debug: bool = False):
        self.proxy_url = proxy_url
        self.debug = debug
        self.agent: Optional[Agent] = None
        self.mcp_server = None
        self.proxy_status = None
        
        # Setup logging
        log_level = getattr(logging, os.getenv('LOG_LEVEL', 'INFO').upper(), logging.INFO)
        configure_logging(console_level=logging.INFO, log_level=log_level, suppress_mcp_logs=True)
        self.protocol_logger, self.fs_logger = setup_protocol_logging(show_fs_logs=False, log_level=log_level)
        self.client_logger = get_client_logger("oauth_proxy_test_client")
        
        # Get model from existing provider
        try:
            self.model = get_model()
            provider = os.getenv('AI_PROVIDER', 'openai').lower()
            console.print(f"[bold]Using AI provider: {provider}[/]")
        except Exception as e:
            raise Exception(f"Failed to initialize model: {e}")
        
        # System prompt for proxy testing
        self.system_prompt = """
        ## Role & Expertise
        You are testing an OAuth-protected Okta MCP Server through a proxy server. The proxy handles OAuth authentication transparently.

        ## Core Objective
        Test MCP operations through the OAuth proxy server and validate that authentication/authorization works seamlessly.
        
        ## Test Context
        - The OAuth proxy server handles all authentication
        - You should be able to access Okta data without handling OAuth directly
        - Focus on testing various permission levels and data access patterns
        
        ## Output Formatting
        Provide clear, structured responses in JSON format when appropriate, with good error handling for authorization issues.
        """
    
    async def check_proxy_server(self) -> Dict[str, Any]:
        """Check if the OAuth proxy server is running and configured"""
        try:
            console.print(f"[yellow]Checking OAuth proxy server at {self.proxy_url}...[/]")
            
            async with httpx.AsyncClient(timeout=10.0) as client:
                # Check health endpoint
                try:
                    health_response = await client.get(f"{self.proxy_url}/health")
                    health_status = health_response.status_code == 200
                except:
                    health_status = False
                
                # Check OAuth status
                try:
                    oauth_response = await client.get(f"{self.proxy_url}/oauth/status")
                    oauth_data = oauth_response.json() if oauth_response.status_code == 200 else {}
                except:
                    oauth_data = {}
                
                # Check MCP capabilities
                try:
                    mcp_response = await client.get(f"{self.proxy_url}/mcp/capabilities")
                    mcp_data = mcp_response.json() if mcp_response.status_code == 200 else {}
                except:
                    mcp_data = {}
                
                self.proxy_status = {
                    "running": health_status,
                    "oauth_configured": bool(oauth_data),
                    "mcp_available": bool(mcp_data),
                    "oauth_status": oauth_data,
                    "mcp_capabilities": mcp_data,
                    "proxy_url": self.proxy_url
                }
                
                return self.proxy_status
                
        except Exception as e:
            console.print(f"[red]Error checking proxy server: {e}[/]")
            self.proxy_status = {
                "running": False,
                "error": str(e),
                "proxy_url": self.proxy_url
            }
            return self.proxy_status
    
    def display_proxy_status(self):
        """Display proxy server status"""
        if not self.proxy_status:
            console.print("[red]Proxy status not checked[/]")
            return
        
        # Create status table
        status_table = Table(title="OAuth Proxy Server Status")
        status_table.add_column("Component", style="cyan")
        status_table.add_column("Status", style="bold")
        status_table.add_column("Details", style="dim")
        
        # Server running status
        running_status = "🟢 Running" if self.proxy_status.get("running") else "🔴 Not Running"
        status_table.add_row("Proxy Server", running_status, self.proxy_url)
        
        # OAuth configuration
        oauth_status = "🟢 Configured" if self.proxy_status.get("oauth_configured") else "🟡 Not Configured"
        oauth_details = str(self.proxy_status.get("oauth_status", {}))[:50]
        status_table.add_row("OAuth Config", oauth_status, oauth_details)
        
        # MCP availability
        mcp_status = "🟢 Available" if self.proxy_status.get("mcp_available") else "🔴 Unavailable"
        mcp_details = str(len(self.proxy_status.get("mcp_capabilities", {}))) + " capabilities"
        status_table.add_row("MCP Backend", mcp_status, mcp_details)
        
        console.print(status_table)
        
        # Show error if any
        if "error" in self.proxy_status:
            console.print(Panel(
                f"[red]Error: {self.proxy_status['error']}[/]",
                title="Connection Error",
                border_style="red"
            ))
    
    async def initiate_oauth_flow(self) -> bool:
        """Initiate OAuth flow through the proxy server"""
        try:
            console.print("[yellow]Starting OAuth authentication through proxy...[/]")
            
            # Get OAuth authorization URL from proxy
            async with httpx.AsyncClient() as client:
                auth_response = await client.get(f"{self.proxy_url}/oauth/authorize")
                
                if auth_response.status_code == 302:
                    # Follow redirect to Okta
                    auth_url = auth_response.headers.get("Location")
                elif auth_response.status_code == 200:
                    # JSON response with auth URL
                    auth_data = auth_response.json()
                    auth_url = auth_data.get("authorization_url")
                else:
                    raise Exception(f"Unexpected response: {auth_response.status_code}")
                
                if not auth_url:
                    raise Exception("No authorization URL received from proxy")
                
                console.print(Panel(
                    f"[bold]OAuth Authentication Required[/]\n\n"
                    f"The proxy server will handle OAuth authentication.\n"
                    f"Please visit the following URL to authorize:\n\n"
                    f"[link={auth_url}]{auth_url}[/]\n\n"
                    f"After authorization, the proxy will handle the callback automatically.",
                    title="OAuth Flow",
                    border_style="yellow"
                ))
                
                if Confirm.ask("Open the authorization URL in your browser?"):
                    webbrowser.open(auth_url)
                
                # Wait for user to complete OAuth flow
                console.print("\n[yellow]Please complete the OAuth authorization in your browser...[/]")
                
                # Poll proxy server for OAuth completion
                max_attempts = 30  # 5 minutes max
                for attempt in range(max_attempts):
                    await asyncio.sleep(10)  # Wait 10 seconds between checks
                    
                    try:
                        status_response = await client.get(f"{self.proxy_url}/oauth/status")
                        if status_response.status_code == 200:
                            status_data = status_response.json()
                            if status_data.get("authenticated"):
                                console.print("[green]✅ OAuth authentication successful![/]")
                                return True
                    except:
                        pass
                    
                    console.print(f"[dim]Waiting for OAuth completion... ({attempt + 1}/{max_attempts})[/]")
                
                console.print("[red]❌ OAuth authentication timed out[/]")
                return False
                
        except Exception as e:
            console.print(f"[red]OAuth flow failed: {e}[/]")
            return False
    
    async def connect(self) -> bool:
        """Connect to the OAuth proxy server"""
        try:
            console.print("[bold]Connecting to OAuth proxy server...[/]")
            
            # Check proxy server status
            status = await self.check_proxy_server()
            self.display_proxy_status()
            
            if not status.get("running"):
                console.print("[red]❌ Proxy server is not running. Please start it first:[/]")
                console.print(f"[dim]python okta_oauth_proxy.py --transport http --port {self.proxy_url.split(':')[-1]}[/]")
                return False
            
            # Check if OAuth is required
            if not status.get("oauth_configured"):
                console.print("[yellow]⚠️  OAuth not configured on proxy server[/]")
                if Confirm.ask("Do you want to initiate OAuth flow?"):
                    oauth_success = await self.initiate_oauth_flow()
                    if not oauth_success:
                        return False
            
            # Create MCP client pointing to proxy
            console.print(f"[green]Connecting to MCP proxy at {self.proxy_url}[/]")
            
            self.mcp_server = MCPServerStreamableHTTP(self.proxy_url)
            
            # Create agent with proxy server
            self.agent = Agent(
                model=self.model,
                system_prompt=self.system_prompt,
                mcp_servers=[self.mcp_server],
                retries=2
            )
            
            console.print(Panel.fit(
                "[bold green]Connected to OAuth Proxy Server![/]\n\n"
                "All OAuth authentication is handled by the proxy.\n"
                "You can now test MCP operations transparently.",
                title="Connection Successful"
            ))
            
            return True
            
        except Exception as e:
            console.print(f"[red]Failed to connect to proxy: {e}[/]")
            return False
    
    async def run_proxy_tests(self) -> Dict[str, Any]:
        """Run comprehensive tests for the OAuth proxy architecture"""
        console.print("[bold cyan]Running OAuth Proxy Test Suite...[/]")
        
        test_results = {
            'connection_tests': {},
            'authentication_tests': {},
            'authorization_tests': {},
            'mcp_operation_tests': {},
            'overall_status': 'PENDING'
        }
        
        try:
            # Test 1: Connection and Proxy Status
            console.print("\n[yellow]1. Testing Proxy Connection...[/]")
            connection_tests = await self._test_proxy_connection()
            test_results['connection_tests'] = connection_tests
            
            # Test 2: OAuth Authentication
            console.print("\n[yellow]2. Testing OAuth Authentication...[/]")
            auth_tests = await self._test_oauth_authentication()
            test_results['authentication_tests'] = auth_tests
            
            # Test 3: Authorization Through Proxy
            console.print("\n[yellow]3. Testing Authorization Through Proxy...[/]")
            authz_tests = await self._test_proxy_authorization()
            test_results['authorization_tests'] = authz_tests
            
            # Test 4: MCP Operations
            console.print("\n[yellow]4. Testing MCP Operations...[/]")
            mcp_tests = await self._test_mcp_operations()
            test_results['mcp_operation_tests'] = mcp_tests
            
            # Calculate overall status
            all_tests = [connection_tests, auth_tests, authz_tests, mcp_tests]
            passed_tests = sum(1 for test in all_tests if test.get('status') == 'PASS')
            total_tests = len(all_tests)
            
            if passed_tests == total_tests:
                test_results['overall_status'] = 'PASS'
            elif passed_tests > 0:
                test_results['overall_status'] = 'PARTIAL'
            else:
                test_results['overall_status'] = 'FAIL'
            
            # Display results
            self._display_proxy_test_results(test_results)
            
            return test_results
            
        except Exception as e:
            console.print(f"[red]Proxy test suite failed: {e}[/]")
            test_results['overall_status'] = 'ERROR'
            test_results['error'] = str(e)
            return test_results
    
    async def _test_proxy_connection(self) -> Dict[str, Any]:
        """Test proxy server connection and status"""
        results = {'status': 'PENDING', 'tests': {}}
        
        try:
            # Test basic connectivity
            async with httpx.AsyncClient(timeout=5.0) as client:
                try:
                    response = await client.get(f"{self.proxy_url}/health")
                    results['tests']['health_check'] = {
                        'status': 'PASS' if response.status_code == 200 else 'FAIL',
                        'details': f"HTTP status: {response.status_code}"
                    }
                except Exception as e:
                    results['tests']['health_check'] = {
                        'status': 'FAIL',
                        'details': f"Connection failed: {str(e)}"
                    }
                
                # Test OAuth endpoints
                try:
                    oauth_response = await client.get(f"{self.proxy_url}/oauth/status")
                    results['tests']['oauth_endpoints'] = {
                        'status': 'PASS' if oauth_response.status_code in [200, 401] else 'FAIL',
                        'details': f"OAuth endpoint responsive: {oauth_response.status_code}"
                    }
                except Exception as e:
                    results['tests']['oauth_endpoints'] = {
                        'status': 'FAIL',
                        'details': f"OAuth endpoints failed: {str(e)}"
                    }
            
            # Overall status
            test_statuses = [test['status'] for test in results['tests'].values()]
            if all(status == 'PASS' for status in test_statuses):
                results['status'] = 'PASS'
            elif any(status == 'PASS' for status in test_statuses):
                results['status'] = 'PARTIAL'
            else:
                results['status'] = 'FAIL'
                
        except Exception as e:
            results['status'] = 'ERROR'
            results['error'] = str(e)
        
        return results
    
    async def _test_oauth_authentication(self) -> Dict[str, Any]:
        """Test OAuth authentication through proxy"""
        results = {'status': 'PENDING', 'tests': {}}
        
        try:
            async with httpx.AsyncClient() as client:
                # Test OAuth status endpoint
                try:
                    status_response = await client.get(f"{self.proxy_url}/oauth/status")
                    if status_response.status_code == 200:
                        status_data = status_response.json()
                        authenticated = status_data.get("authenticated", False)
                        results['tests']['oauth_status'] = {
                            'status': 'PASS' if authenticated else 'PARTIAL',
                            'details': f"Authentication status: {authenticated}"
                        }
                    else:
                        results['tests']['oauth_status'] = {
                            'status': 'FAIL',
                            'details': f"Status check failed: {status_response.status_code}"
                        }
                except Exception as e:
                    results['tests']['oauth_status'] = {
                        'status': 'FAIL',
                        'details': f"OAuth status failed: {str(e)}"
                    }
                
                # Test protected endpoint access
                try:
                    protected_response = await client.get(f"{self.proxy_url}/mcp/tools")
                    results['tests']['protected_access'] = {
                        'status': 'PASS' if protected_response.status_code == 200 else 'PARTIAL',
                        'details': f"Protected endpoint access: {protected_response.status_code}"
                    }
                except Exception as e:
                    results['tests']['protected_access'] = {
                        'status': 'FAIL',
                        'details': f"Protected access failed: {str(e)}"
                    }
            
            # Overall status
            test_statuses = [test['status'] for test in results['tests'].values()]
            if all(status == 'PASS' for status in test_statuses):
                results['status'] = 'PASS'
            elif any(status == 'PASS' for status in test_statuses):
                results['status'] = 'PARTIAL'
            else:
                results['status'] = 'FAIL'
                
        except Exception as e:
            results['status'] = 'ERROR'
            results['error'] = str(e)
        
        return results
    
    async def _test_proxy_authorization(self) -> Dict[str, Any]:
        """Test authorization policies through proxy"""
        results = {'status': 'PENDING', 'tests': {}}
        
        try:
            if not self.agent:
                raise ValueError("Agent not initialized")
            
            # Test basic authorized operation
            async with self.agent.run_mcp_servers():
                try:
                    result = await self.agent.run("What time is it?")
                    results['tests']['basic_operation'] = {
                        'status': 'PASS' if result else 'FAIL',
                        'details': f"Basic operation successful"
                    }
                except Exception as e:
                    results['tests']['basic_operation'] = {
                        'status': 'FAIL',
                        'details': f"Basic operation failed: {str(e)}"
                    }
                
                # Test Okta data access through proxy
                try:
                    result = await self.agent.run("List 3 Okta users")
                    success = result and "error" not in result.lower()
                    results['tests']['okta_data_access'] = {
                        'status': 'PASS' if success else 'FAIL',
                        'details': f"Okta data access through proxy: {'success' if success else 'failed'}"
                    }
                except Exception as e:
                    results['tests']['okta_data_access'] = {
                        'status': 'FAIL',
                        'details': f"Okta data access failed: {str(e)}"
                    }
            
            # Overall status
            test_statuses = [test['status'] for test in results['tests'].values()]
            if all(status == 'PASS' for status in test_statuses):
                results['status'] = 'PASS'
            elif any(status == 'PASS' for status in test_statuses):
                results['status'] = 'PARTIAL'
            else:
                results['status'] = 'FAIL'
                
        except Exception as e:
            results['status'] = 'ERROR'
            results['error'] = str(e)
        
        return results
    
    async def _test_mcp_operations(self) -> Dict[str, Any]:
        """Test various MCP operations through proxy"""
        results = {'status': 'PENDING', 'tests': {}}
        
        try:
            if not self.agent:
                raise ValueError("Agent not initialized")
            
            test_operations = [
                ("Tool List", "Show available tools"),
                ("User Query", "Get details for the first active user"),
                ("Group Query", "List 3 Okta groups"),
                ("App Query", "Show 2 Okta applications")
            ]
            
            async with self.agent.run_mcp_servers():
                for test_name, query in test_operations:
                    try:
                        result = await self.agent.run(query)
                        success = result and len(result) > 10  # Basic success check
                        
                        results['tests'][test_name.lower().replace(' ', '_')] = {
                            'status': 'PASS' if success else 'FAIL',
                            'details': f"Query: '{query}' - {'Success' if success else 'Failed'}"
                        }
                    except Exception as e:
                        results['tests'][test_name.lower().replace(' ', '_')] = {
                            'status': 'FAIL',
                            'details': f"Query failed: {str(e)}"
                        }
            
            # Overall status
            test_statuses = [test['status'] for test in results['tests'].values()]
            if all(status == 'PASS' for status in test_statuses):
                results['status'] = 'PASS'
            elif any(status == 'PASS' for status in test_statuses):
                results['status'] = 'PARTIAL'
            else:
                results['status'] = 'FAIL'
                
        except Exception as e:
            results['status'] = 'ERROR'
            results['error'] = str(e)
        
        return results
    
    def _display_proxy_test_results(self, results: Dict[str, Any]):
        """Display proxy test results"""
        console.print("\n" + "="*80)
        console.print("[bold cyan]OAUTH PROXY TEST RESULTS[/]")
        console.print("="*80)
        
        # Overall status
        status_color = {
            'PASS': 'green',
            'PARTIAL': 'yellow', 
            'FAIL': 'red',
            'ERROR': 'red',
            'PENDING': 'blue'
        }
        
        overall_status = results.get('overall_status', 'UNKNOWN')
        console.print(f"\n[bold]Overall Status: [{status_color.get(overall_status, 'white')}]{overall_status}[/][/]")
        
        # Detailed results table
        table = Table(title="OAuth Proxy Test Results")
        table.add_column("Test Category", style="cyan")
        table.add_column("Status", style="bold")
        table.add_column("Details", style="dim")
        
        for category, category_results in results.items():
            if category == 'overall_status':
                continue
                
            if isinstance(category_results, dict) and 'status' in category_results:
                status = category_results.get('status', 'UNKNOWN')
                color = status_color.get(status, 'white')
                
                # Count individual tests if available
                tests = category_results.get('tests', {})
                details = f"{len(tests)} tests" if tests else category_results.get('details', 'No details')
                
                table.add_row(
                    category.replace('_', ' ').title(),
                    f"[{color}]{status}[/]",
                    details
                )
        
        console.print(table)
        
        # Recommendations for proxy testing
        if overall_status != 'PASS':
            console.print("\n[bold yellow]Recommendations for Proxy Testing:[/]")
            console.print("• Ensure OAuth proxy server is running: python okta_oauth_proxy.py --transport http")
            console.print("• Verify OAuth configuration in proxy server")
            console.print("• Check that backend MCP server is accessible")
            console.print("• Complete OAuth authentication flow if required")
        else:
            console.print("\n[bold green]🎉 OAuth Proxy is working perfectly![/]")
            console.print("• All proxy operations successful")
            console.print("• OAuth authentication transparent to client")
            console.print("• Ready for production use with Claude Desktop")
    
    async def process_query(self, query: str) -> str:
        """Process a query through the OAuth proxy"""
        if not self.agent:
            raise ValueError("Agent not initialized")
        
        try:
            console.print("[bold green]Processing query through OAuth proxy...[/]")
            
            async with self.agent.run_mcp_servers():
                result = await self.agent.run(query)
                
                if self.debug:
                    console.print("[cyan]===== Proxy Message Exchange =====[/]")
                    console.print(result.all_messages())
                else:
                    console.print("[green]Query processed through proxy successfully[/]")
                
                return result.output
                
        except Exception as e:
            console.print(f"[bold red]Proxy query error: {e}[/]")
            return f"Error processing query through proxy: {str(e)}"
    
    async def interactive_shell(self):
        """Interactive shell for testing OAuth proxy"""
        if not self.agent:
            raise Exception("Client not connected. Call connect() first.")
        
        console.print("\n[bold cyan]OAuth Proxy Test Client[/]")
        console.print("Type 'exit' to quit")
        console.print("Type 'proxy-status' to check proxy server status")
        console.print("Type 'run-tests' to run comprehensive proxy tests")
        console.print("Type 'debug on/off' to toggle debug mode")
        
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
                    elif query_lower == "proxy-status":
                        await self.check_proxy_server()
                        self.display_proxy_status()
                        continue
                    elif query_lower == "run-tests":
                        await self.run_proxy_tests()
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
                            title="Proxy Result",
                            border_style="green"
                        ))
                
                except KeyboardInterrupt:
                    console.print("\n[yellow]Command interrupted[/]")
                    break
                except Exception as e:
                    console.print(f"[bold red]Error: {e}[/]")
        
        except KeyboardInterrupt:
            console.print("\n[yellow]Interrupted by user[/yellow]")
        finally:
            console.print("OAuth proxy test session ended")

async def main():
    """Main entry point for OAuth proxy test client"""
    parser = argparse.ArgumentParser(description="OAuth Proxy Test Client")
    parser.add_argument("--proxy-url", default="http://localhost:3001", 
                       help="OAuth proxy server URL (default: http://localhost:3001)")
    parser.add_argument("--debug", action="store_true", help="Enable debug mode")
    parser.add_argument("--query", "-q", help="Run a single query and exit")
    parser.add_argument("--test-proxy", action="store_true", help="Run proxy test suite and exit")
    parser.add_argument("--check-status", action="store_true", help="Check proxy status and exit")
    
    args = parser.parse_args()
    
    try:
        # Create proxy test client
        client = OAuthProxyTester(
            proxy_url=args.proxy_url,
            debug=args.debug
        )
        
        # Check proxy status if requested
        if args.check_status:
            await client.check_proxy_server()
            client.display_proxy_status()
            return 0
        
        # Connect to proxy
        if not await client.connect():
            console.print("[red]Failed to connect to OAuth proxy server[/]")
            return 1
        
        # Run proxy tests if requested
        if args.test_proxy:
            test_results = await client.run_proxy_tests()
            overall_status = test_results.get('overall_status', 'UNKNOWN')
            return 0 if overall_status == 'PASS' else 1
        
        # Run single query or interactive shell
        if args.query:
            console.print(f"[blue]Proxy Query:[/blue] {args.query}")
            result = await client.process_query(args.query)
            
            if result:
                try:
                    result_obj = json.loads(result)
                    formatted_result = json.dumps(result_obj, indent=2, ensure_ascii=False)
                except json.JSONDecodeError:
                    formatted_result = result
                
                console.print(Panel(
                    formatted_result,
                    title="Proxy Result",
                    border_style="green"
                ))
        else:
            await client.interactive_shell()
            
        return 0
        
    except Exception as e:
        console.print(f"[red]Error:[/red] {e}")
        if args.debug:
            import traceback
            console.print(f"[red]Traceback:[/red]\n{traceback.format_exc()}")
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
