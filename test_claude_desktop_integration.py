#!/usr/bin/env python3
"""
Test script to verify Claude Desktop OAuth integration
This simulates what Claude Desktop will do when connecting to the MCP server
"""

import asyncio
import httpx
import json
from rich.console import Console
from rich.panel import Panel

console = Console()

async def test_claude_desktop_integration():
    """Test the integration path that Claude Desktop will use"""
    
    console.print(Panel.fit(
        "[bold green]Testing Claude Desktop OAuth Integration[/bold green]\n"
        "This simulates the requests Claude Desktop will make",
        title="🤖 Claude Desktop Test"
    ))
    
    proxy_url = "http://localhost:3001"
    
    # Test 1: Check if server is accessible
    console.print("\n[bold blue]1. Testing Server Accessibility[/bold blue]")
    try:
        async with httpx.AsyncClient() as client:
            response = await client.get(f"{proxy_url}/health")
            if response.status_code == 200:
                console.print("[green]✅ OAuth proxy server is accessible[/green]")
            else:
                console.print(f"[red]❌ Server health check failed: {response.status_code}[/red]")
                return False
    except Exception as e:
        console.print(f"[red]❌ Cannot connect to OAuth proxy: {e}[/red]")
        console.print("[yellow]Make sure the OAuth proxy is running: python okta_oauth_fastmcp_proxy.py[/yellow]")
        return False
    
    # Test 2: Check MCP tools endpoint (should require auth)
    console.print("\n[bold blue]2. Testing MCP Tools Endpoint (Should Require Auth)[/bold blue]")
    try:
        async with httpx.AsyncClient() as client:
            response = await client.get(f"{proxy_url}/mcp/tools")
            if response.status_code == 401:
                console.print("[green]✅ MCP tools endpoint properly requires authentication[/green]")
                data = response.json()
                console.print(f"[dim]Response: {data}[/dim]")
            else:
                console.print(f"[yellow]⚠️ Unexpected response: {response.status_code}[/yellow]")
    except Exception as e:
        console.print(f"[red]❌ Error testing MCP endpoint: {e}[/red]")
        return False
    
    # Test 3: Check OAuth login redirect
    console.print("\n[bold blue]3. Testing OAuth Login Redirect[/bold blue]")
    try:
        async with httpx.AsyncClient(follow_redirects=False) as client:
            response = await client.get(f"{proxy_url}/oauth/login")
            if response.status_code == 302:
                location = response.headers.get("location", "")
                if "okta" in location.lower():
                    console.print("[green]✅ OAuth login redirect is working[/green]")
                    console.print(f"[dim]Redirects to: {location[:80]}...[/dim]")
                else:
                    console.print(f"[red]❌ Invalid redirect location: {location}[/red]")
                    return False
            else:
                console.print(f"[red]❌ OAuth login failed: {response.status_code}[/red]")
                return False
    except Exception as e:
        console.print(f"[red]❌ Error testing OAuth login: {e}[/red]")
        return False
    
    # Test 4: Simulate what happens after authentication
    console.print("\n[bold blue]4. Testing Post-Authentication Flow[/bold blue]")
    console.print("[yellow]⚠️ This requires manual OAuth authentication[/yellow]")
    console.print("Claude Desktop will:")
    console.print("  1. Make initial request to /mcp/tools")
    console.print("  2. Get 401 Unauthorized")
    console.print("  3. Open browser for OAuth flow")
    console.print("  4. User authenticates with Okta")
    console.print("  5. Browser gets session cookie")
    console.print("  6. Claude Desktop retries with session")
    console.print("  7. Gets MCP tools list successfully")
    
    # Summary
    console.print("\n[bold green]✅ OAuth Integration Test Complete![/bold green]")
    console.print("\n[bold yellow]Next Steps:[/bold yellow]")
    console.print("1. Copy the Claude Desktop configuration:")
    console.print("   File: examples/oauth/claude_desktop_config.json")
    console.print("2. Add to your Claude Desktop config:")
    console.print("   Windows: %APPDATA%\\Claude\\claude_desktop_config.json")
    console.print("3. Restart Claude Desktop")
    console.print("4. Try using MCP tools in Claude Desktop")
    console.print("5. Complete OAuth authentication when prompted")
    
    return True

async def main():
    """Main test function"""
    success = await test_claude_desktop_integration()
    if not success:
        console.print("\n[red]❌ Test failed. Please fix issues before configuring Claude Desktop.[/red]")
        exit(1)
    else:
        console.print("\n[green]🎉 Ready for Claude Desktop integration![/green]")

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        console.print("\n[yellow]Test interrupted by user[/yellow]")
    except Exception as e:
        console.print(f"\n[red]Test failed: {e}[/red]")
        exit(1)
