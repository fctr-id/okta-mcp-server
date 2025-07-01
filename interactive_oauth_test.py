#!/usr/bin/env python3
"""
Interactive OAuth FastMCP Proxy Test Client
Includes browser automation for OAuth flow testing
"""

import asyncio
import webbrowser
import logging
import httpx
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.prompt import Confirm, Prompt
import json

console = Console()

class InteractiveOAuthTest:
    """Interactive test client with browser integration"""
    
    def __init__(self, proxy_url: str = "http://localhost:3001"):
        self.proxy_url = proxy_url
        self.session_cookies = {}
        
    async def test_full_oauth_flow(self):
        """Test the complete OAuth flow with browser interaction"""
        console.print("\n[bold blue]🌐 Testing Full OAuth Flow with Browser[/bold blue]")
        
        # Step 1: Check initial status
        console.print("1. Checking initial authentication status...")
        async with httpx.AsyncClient() as client:
            response = await client.get(f"{self.proxy_url}/oauth/status")
            if response.status_code == 200 and not response.json().get("authenticated"):
                console.print("[green]✅ Initial status: Unauthenticated (as expected)[/green]")
            else:
                console.print("[yellow]⚠️ User may already be authenticated[/yellow]")
        
        # Step 2: Get OAuth login URL
        console.print("2. Getting OAuth login URL...")
        async with httpx.AsyncClient(follow_redirects=False) as client:
            response = await client.get(f"{self.proxy_url}/oauth/login")
            
            if response.status_code == 302:
                auth_url = response.headers.get("location")
                session_cookie = response.cookies.get("oauth_session")
                
                console.print(f"[green]✅ OAuth URL generated[/green]")
                console.print(f"[dim]URL: {auth_url[:80]}...[/dim]")
                
                # Step 3: Open browser for user authentication
                if Confirm.ask("🌐 Open browser for OAuth authentication?"):
                    console.print("Opening browser... Complete the OAuth flow and return here.")
                    webbrowser.open(auth_url)
                    
                    # Wait for user to complete OAuth
                    input("\n📝 Press Enter after completing OAuth authentication in the browser...")
                    
                    # Step 4: Check authentication status
                    console.print("3. Checking authentication status after OAuth...")
                    
                    # Use the session cookie from the login redirect
                    cookies = {"oauth_session": session_cookie} if session_cookie else {}
                    
                    async with httpx.AsyncClient(cookies=cookies) as auth_client:
                        status_response = await auth_client.get(f"{self.proxy_url}/oauth/status")
                        
                        if status_response.status_code == 200:
                            status_data = status_response.json()
                            
                            if status_data.get("authenticated"):
                                console.print("[green]🎉 OAuth authentication successful![/green]")
                                
                                user_info = status_data.get("user_info", {})
                                table = Table(title="Authenticated User Info")
                                table.add_column("Field", style="cyan")
                                table.add_column("Value", style="magenta")
                                
                                for key, value in user_info.items():
                                    table.add_row(str(key), str(value))
                                
                                console.print(table)
                                
                                # Store cookies for further testing
                                self.session_cookies = cookies
                                
                                return True
                            else:
                                console.print("[red]❌ Authentication failed or incomplete[/red]")
                                console.print(f"Status: {status_data}")
                                return False
                        else:
                            console.print(f"[red]❌ Status check failed: {status_response.status_code}[/red]")
                            return False
                else:
                    console.print("[yellow]⚠️ Skipping browser test - manual authentication required[/yellow]")
                    console.print(f"Manual OAuth URL: {auth_url}")
                    return False
            else:
                console.print(f"[red]❌ OAuth login failed: {response.status_code}[/red]")
                return False
    
    async def test_authenticated_mcp_calls(self):
        """Test MCP endpoints with authentication"""
        if not self.session_cookies:
            console.print("[yellow]⚠️ No authentication cookies - skipping MCP tests[/yellow]")
            return False
            
        console.print("\n[bold blue]🔧 Testing Authenticated MCP Endpoints[/bold blue]")
        
        async with httpx.AsyncClient(cookies=self.session_cookies) as client:
            # Test 1: List tools
            console.print("1. Testing MCP tools list...")
            try:
                response = await client.get(f"{self.proxy_url}/mcp/tools")
                if response.status_code == 200:
                    data = response.json()
                    tools = data.get("tools", [])
                    console.print(f"[green]✅ Found {len(tools)} MCP tools[/green]")
                    
                    if tools:
                        table = Table(title="Available MCP Tools")
                        table.add_column("Tool Name", style="cyan")
                        table.add_column("Description", style="magenta")
                        
                        for tool in tools[:5]:  # Show first 5 tools
                            name = tool.get("name", "Unknown")
                            desc = tool.get("description", "No description")[:50] + "..."
                            table.add_row(name, desc)
                        
                        console.print(table)
                    
                    # Test 2: Try calling a tool if available
                    if tools and Confirm.ask("🔧 Try calling an MCP tool?"):
                        await self._test_tool_call(client, tools)
                    
                    return True
                else:
                    console.print(f"[red]❌ Tools list failed: {response.status_code}[/red]")
                    console.print(f"Response: {response.text}")
                    return False
                    
            except Exception as e:
                console.print(f"[red]❌ MCP test error: {e}[/red]")
                return False
    
    async def _test_tool_call(self, client: httpx.AsyncClient, tools: list):
        """Test calling an MCP tool"""
        console.print("2. Testing MCP tool call...")
        
        # Find a simple tool to test
        test_tool = None
        for tool in tools:
            name = tool.get("name", "")
            if any(keyword in name.lower() for keyword in ["list", "get", "read", "info"]):
                test_tool = tool
                break
        
        if not test_tool:
            test_tool = tools[0]  # Use first tool if no "safe" one found
        
        tool_name = test_tool.get("name")
        console.print(f"Testing tool: [cyan]{tool_name}[/cyan]")
        
        try:
            # Try calling with minimal parameters
            call_data = {
                "name": tool_name,
                "arguments": {}
            }
            
            response = await client.post(
                f"{self.proxy_url}/mcp/tools/call",
                json=call_data
            )
            
            if response.status_code == 200:
                result = response.json()
                console.print("[green]✅ Tool call successful![/green]")
                console.print(f"Result preview: {str(result)[:200]}...")
            else:
                console.print(f"[yellow]⚠️ Tool call returned {response.status_code}[/yellow]")
                console.print(f"Response: {response.text[:200]}...")
                
        except Exception as e:
            console.print(f"[red]❌ Tool call error: {e}[/red]")
    
    async def run_interactive_test(self):
        """Run the full interactive test suite"""
        console.print(Panel.fit(
            "[bold green]🚀 Interactive OAuth FastMCP Proxy Test[/bold green]\n"
            "This test will open your browser for OAuth authentication",
            title="🧪 Interactive Test"
        ))
        
        # Test 1: Full OAuth flow
        oauth_success = await self.test_full_oauth_flow()
        
        if oauth_success:
            # Test 2: Authenticated MCP calls
            mcp_success = await self.test_authenticated_mcp_calls()
            
            if mcp_success:
                console.print("\n[bold green]🎉 All interactive tests passed![/bold green]")
                console.print("Your OAuth FastMCP Proxy is working correctly!")
            else:
                console.print("\n[yellow]⚠️ OAuth works, but MCP endpoint testing had issues[/yellow]")
        else:
            console.print("\n[red]❌ OAuth flow testing failed[/red]")
            console.print("Please check your Okta configuration and try again")
        
        return oauth_success

async def main():
    """Main interactive test function"""
    import argparse
    
    parser = argparse.ArgumentParser(description="Interactive OAuth FastMCP Proxy Test")
    parser.add_argument("--url", default="http://localhost:3001", help="Proxy server URL")
    
    args = parser.parse_args()
    
    tester = InteractiveOAuthTest(args.url)
    await tester.run_interactive_test()

if __name__ == "__main__":
    # Configure logging to be less verbose
    logging.basicConfig(level=logging.WARNING)
    
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        console.print("\n[yellow]Interactive test interrupted by user[/yellow]")
    except Exception as e:
        console.print(f"\n[red]Interactive test failed: {e}[/red]")
