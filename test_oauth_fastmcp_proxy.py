#!/usr/bin/env python3
"""
Simple test client for the OAuth FastMCP Proxy Server
Tests the new implementation that combines FastMCP proxy with OAuth 2.0
"""

import asyncio
import logging
import httpx
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

console = Console()

class OAuthFastMCPProxyTest:
    """Test client for OAuth FastMCP Proxy"""
    
    def __init__(self, proxy_url: str = "http://localhost:3001"):
        self.proxy_url = proxy_url
        self.session_cookies = {}
        
    async def test_health_check(self):
        """Test the health check endpoint"""
        console.print("\n[bold blue]Testing Health Check[/bold blue]")
        
        try:
            async with httpx.AsyncClient() as client:
                response = await client.get(f"{self.proxy_url}/health")
                
                if response.status_code == 200:
                    data = response.json()
                    console.print("[green]✅ Health check passed[/green]")
                    
                    table = Table(title="Health Check Results")
                    table.add_column("Property", style="cyan")
                    table.add_column("Value", style="magenta")
                    
                    for key, value in data.items():
                        table.add_row(str(key), str(value))
                    
                    console.print(table)
                    return True
                else:
                    console.print(f"[red]❌ Health check failed: {response.status_code}[/red]")
                    return False
                    
        except Exception as e:
            console.print(f"[red]❌ Health check error: {e}[/red]")
            return False
    
    async def test_oauth_status_unauthenticated(self):
        """Test OAuth status when not authenticated"""
        console.print("\n[bold blue]Testing OAuth Status (Unauthenticated)[/bold blue]")
        
        try:
            async with httpx.AsyncClient() as client:
                response = await client.get(f"{self.proxy_url}/oauth/status")
                
                if response.status_code == 200:
                    data = response.json()
                    if not data.get("authenticated"):
                        console.print("[green]✅ Correctly shows unauthenticated[/green]")
                        console.print(f"Response: {data}")
                        return True
                    else:
                        console.print("[red]❌ Should not be authenticated[/red]")
                        return False
                else:
                    console.print(f"[red]❌ OAuth status failed: {response.status_code}[/red]")
                    return False
                    
        except Exception as e:
            console.print(f"[red]❌ OAuth status error: {e}[/red]")
            return False
    
    async def test_protected_endpoint_unauthorized(self):
        """Test that protected endpoints require authentication"""
        console.print("\n[bold blue]Testing Protected Endpoint (Should Fail)[/bold blue]")
        
        try:
            async with httpx.AsyncClient() as client:
                response = await client.get(f"{self.proxy_url}/mcp/tools")
                
                if response.status_code == 401:
                    console.print("[green]✅ Protected endpoint correctly requires authentication[/green]")
                    data = response.json()
                    console.print(f"Response: {data}")
                    return True
                else:
                    console.print(f"[red]❌ Expected 401, got {response.status_code}[/red]")
                    return False
                    
        except Exception as e:
            console.print(f"[red]❌ Protected endpoint test error: {e}[/red]")
            return False
    
    async def test_oauth_login_redirect(self):
        """Test OAuth login redirect"""
        console.print("\n[bold blue]Testing OAuth Login Redirect[/bold blue]")
        
        try:
            async with httpx.AsyncClient(follow_redirects=False) as client:
                response = await client.get(f"{self.proxy_url}/oauth/login")
                
                if response.status_code == 302:
                    location = response.headers.get("location", "")
                    if "okta" in location.lower() and "oauth" in location.lower():
                        console.print("[green]✅ OAuth login redirect works[/green]")
                        console.print(f"Redirect URL: {location[:100]}...")
                        
                        # Check for session cookie
                        cookies = response.cookies
                        if "oauth_session" in cookies:
                            console.print(f"[green]✅ Session cookie set: oauth_session[/green]")
                            self.session_cookies["oauth_session"] = cookies["oauth_session"]
                        
                        return True
                    else:
                        console.print(f"[red]❌ Invalid redirect URL: {location}[/red]")
                        return False
                else:
                    console.print(f"[red]❌ Expected 302 redirect, got {response.status_code}[/red]")
                    return False
                    
        except Exception as e:
            console.print(f"[red]❌ OAuth login test error: {e}[/red]")
            return False
    
    async def test_home_page(self):
        """Test the home page"""
        console.print("\n[bold blue]Testing Home Page[/bold blue]")
        
        try:
            async with httpx.AsyncClient() as client:
                response = await client.get(f"{self.proxy_url}/")
                
                if response.status_code == 200:
                    content = response.text
                    if "Okta MCP OAuth Proxy" in content:
                        console.print("[green]✅ Home page loads correctly[/green]")
                        
                        # Check if it shows login button (unauthenticated)
                        if "Login with Okta" in content:
                            console.print("[green]✅ Shows login button for unauthenticated user[/green]")
                        else:
                            console.print("[yellow]⚠️ No login button found[/yellow]")
                        
                        return True
                    else:
                        console.print("[red]❌ Home page content incorrect[/red]")
                        return False
                else:
                    console.print(f"[red]❌ Home page failed: {response.status_code}[/red]")
                    return False
                    
        except Exception as e:
            console.print(f"[red]❌ Home page test error: {e}[/red]")
            return False
    
    async def test_permissions_page(self):
        """Test the permissions information page"""
        console.print("\n[bold blue]Testing Permissions Page[/bold blue]")
        
        try:
            async with httpx.AsyncClient() as client:
                response = await client.get(f"{self.proxy_url}/oauth/permissions")
                
                if response.status_code == 200:
                    content = response.text
                    if "OAuth Permissions" in content and "okta.users.read" in content:
                        console.print("[green]✅ Permissions page loads correctly[/green]")
                        
                        # Check for key elements
                        checks = [
                            ("Scope descriptions", "Access your basic profile" in content),
                            ("Continue button", 'href="/oauth/login"' in content),
                            ("Cancel button", 'href="/"' in content),
                            ("Security note", "organization authorization server" in content)
                        ]
                        
                        for check_name, check_result in checks:
                            status = "✅" if check_result else "⚠️"
                            console.print(f"  {status} {check_name}")
                        
                        return True
                    else:
                        console.print("[red]❌ Permissions page content incorrect[/red]")
                        return False
                else:
                    console.print(f"[red]❌ Permissions page failed: {response.status_code}[/red]")
                    return False
                    
        except Exception as e:
            console.print(f"[red]❌ Permissions page test error: {e}[/red]")
            return False

    async def run_all_tests(self):
        """Run all tests"""
        console.print(Panel.fit(
            "[bold green]OAuth FastMCP Proxy Test Suite[/bold green]\n"
            "Testing the new implementation that combines FastMCP proxy with OAuth 2.0",
            title="🧪 Test Suite"
        ))
        
        tests = [
            ("Health Check", self.test_health_check),
            ("Home Page", self.test_home_page),
            ("OAuth Status (Unauthenticated)", self.test_oauth_status_unauthenticated),
            ("OAuth Login Redirect", self.test_oauth_login_redirect),
            ("Protected Endpoint (Should Fail)", self.test_protected_endpoint_unauthorized),
            ("Permissions Page", self.test_permissions_page),
        ]
        
        results = []
        
        for test_name, test_func in tests:
            try:
                result = await test_func()
                results.append((test_name, result))
            except Exception as e:
                console.print(f"[red]❌ {test_name} failed with exception: {e}[/red]")
                results.append((test_name, False))
        
        # Summary
        console.print("\n" + "="*50)
        console.print("[bold yellow]Test Results Summary[/bold yellow]")
        
        passed = sum(1 for _, result in results if result)
        total = len(results)
        
        table = Table(title=f"Test Results: {passed}/{total} Passed")
        table.add_column("Test", style="cyan")
        table.add_column("Result", style="magenta")
        
        for test_name, result in results:
            status = "[green]✅ PASS[/green]" if result else "[red]❌ FAIL[/red]"
            table.add_row(test_name, status)
        
        console.print(table)
        
        if passed == total:
            console.print("\n[bold green]🎉 All tests passed! The OAuth FastMCP Proxy is working correctly.[/bold green]")
        else:
            console.print(f"\n[bold red]❌ {total - passed} tests failed. Check the implementation.[/bold red]")
        
        return passed == total


async def main():
    """Main test function"""
    import argparse
    
    parser = argparse.ArgumentParser(description="Test OAuth FastMCP Proxy Server")
    parser.add_argument("--url", default="http://localhost:3001", help="Proxy server URL")
    
    args = parser.parse_args()
    
    tester = OAuthFastMCPProxyTest(args.url)
    success = await tester.run_all_tests()
    
    if not success:
        exit(1)


if __name__ == "__main__":
    # Configure logging
    logging.basicConfig(level=logging.INFO)
    
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        console.print("\n[yellow]Test interrupted by user[/yellow]")
    except Exception as e:
        console.print(f"\n[red]Test suite failed: {e}[/red]")
        exit(1)
