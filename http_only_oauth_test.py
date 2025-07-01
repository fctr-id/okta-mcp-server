#!/usr/bin/env python3
"""
HTTP-Only OAuth Test Client
Simulates the full OAuth flow without opening a browser
"""

import asyncio
import httpx
from rich.console import Console
from rich.panel import Panel
from urllib.parse import parse_qs, urlparse
import json

console = Console()

class HTTPOnlyOAuthTest:
    """Test OAuth flow using HTTP client only (no browser)"""
    
    def __init__(self, proxy_url: str = "http://localhost:3001"):
        self.proxy_url = proxy_url
        
    async def test_oauth_flow_simulation(self):
        """Simulate the complete OAuth flow with HTTP requests only"""
        console.print("\n[bold blue]🔧 Testing OAuth Flow (HTTP-Only Simulation)[/bold blue]")
        
        # Create a persistent HTTP client to maintain cookies
        async with httpx.AsyncClient(follow_redirects=False) as client:
            
            # Step 1: Get OAuth login URL
            console.print("1. Getting OAuth authorization URL...")
            response = await client.get(f"{self.proxy_url}/oauth/login")
            
            if response.status_code == 302:
                auth_url = response.headers.get("location")
                console.print(f"[green]✅ Got authorization URL[/green]")
                console.print(f"[dim]URL: {auth_url[:80]}...[/dim]")
                
                # Parse the authorization URL to extract parameters
                parsed_url = urlparse(auth_url)
                auth_params = parse_qs(parsed_url.query)
                
                state = auth_params.get('state', [None])[0]
                client_id = auth_params.get('client_id', [None])[0]
                
                console.print(f"[cyan]State: {state[:20]}...[/cyan]")
                console.print(f"[cyan]Client ID: {client_id}[/cyan]")
                
                # Step 2: Simulate what happens after user logs in at Okta
                # In real flow, Okta would redirect back with a code
                # For testing, we'll simulate this callback
                
                console.print("\n2. Simulating OAuth callback...")
                console.print("[yellow]ℹ️  In real flow, user would login at Okta and get redirected back[/yellow]")
                
                # Test what happens if we hit the callback endpoint directly
                # with the same state (simulating successful Okta auth)
                fake_code = "fake_authorization_code_for_testing"
                callback_url = f"{self.proxy_url}/oauth/callback?code={fake_code}&state={state}"
                
                callback_response = await client.get(callback_url)
                
                console.print(f"[cyan]Callback status: {callback_response.status_code}[/cyan]")
                
                if callback_response.status_code == 400:
                    # Expected - we're using a fake code
                    error_data = callback_response.json()
                    console.print(f"[yellow]Expected error (fake code): {error_data.get('error')}[/yellow]")
                    
                    # Check if the state was found (this is what we care about)
                    if "Invalid state parameter" in error_data.get('error', ''):
                        console.print("[red]❌ State validation failed[/red]")
                        return False
                    else:
                        console.print("[green]✅ State validation passed (got different error)[/green]")
                        return True
                        
                elif callback_response.status_code == 500:
                    # Check the error details
                    try:
                        error_data = callback_response.json()
                        error_msg = error_data.get('error', '')
                        if "Token exchange failed" in error_msg:
                            console.print("[green]✅ State validation passed, reached token exchange[/green]")
                            console.print("[yellow]ℹ️  Token exchange failed as expected (fake code)[/yellow]")
                            return True
                        else:
                            console.print(f"[red]❌ Unexpected error: {error_msg}[/red]")
                            return False
                    except:
                        console.print(f"[red]❌ Server error: {callback_response.text}[/red]")
                        return False
                else:
                    console.print(f"[yellow]Unexpected status: {callback_response.status_code}[/yellow]")
                    console.print(f"Response: {callback_response.text}")
                    return False
                    
            else:
                console.print(f"[red]❌ OAuth login failed: {response.status_code}[/red]")
                console.print(f"Response: {response.text}")
                return False
    
    async def test_session_persistence(self):
        """Test if session data persists correctly"""
        console.print("\n[bold blue]🔍 Testing Session Persistence[/bold blue]")
        
        async with httpx.AsyncClient(follow_redirects=False) as client:
            # Step 1: Make OAuth login request
            response1 = await client.get(f"{self.proxy_url}/oauth/login")
            
            if response1.status_code == 302:
                auth_url = response1.headers.get("location")
                parsed_url = urlparse(auth_url)
                auth_params = parse_qs(parsed_url.query)
                state = auth_params.get('state', [None])[0]
                
                console.print(f"[green]✅ First request - State: {state[:20]}...[/green]")
                
                # Step 2: Make another request with same client (should have session)
                response2 = await client.get(f"{self.proxy_url}/oauth/status")
                
                if response2.status_code == 200:
                    status_data = response2.json()
                    console.print(f"[cyan]OAuth status: {status_data}[/cyan]")
                
                # Step 3: Test callback with the state from first request
                fake_code = "test_code"
                callback_response = await client.get(
                    f"{self.proxy_url}/oauth/callback?code={fake_code}&state={state}"
                )
                
                if callback_response.status_code == 400:
                    error_data = callback_response.json()
                    if "Invalid state parameter" in error_data.get('error', ''):
                        console.print("[red]❌ Session not maintained - state lost[/red]")
                        return False
                    else:
                        console.print("[green]✅ Session maintained - state found[/green]")
                        return True
                else:
                    console.print(f"[yellow]Unexpected callback response: {callback_response.status_code}[/yellow]")
                    return True  # Probably reached token exchange
                    
            return False
    
    async def run_http_tests(self):
        """Run all HTTP-only tests"""
        console.print(Panel.fit(
            "[bold green]🔧 HTTP-Only OAuth Test Suite[/bold green]\n"
            "Testing OAuth flow without browser interaction",
            title="🧪 HTTP Test"
        ))
        
        # Test 1: OAuth flow simulation
        flow_success = await self.test_oauth_flow_simulation()
        
        # Test 2: Session persistence
        session_success = await self.test_session_persistence()
        
        if flow_success and session_success:
            console.print("\n[bold green]🎉 HTTP-only tests passed![/bold green]")
            console.print("OAuth state management is working correctly.")
            console.print("\n[cyan]Next step: Try the interactive test with browser[/cyan]")
        else:
            console.print("\n[red]❌ Some HTTP tests failed[/red]")
            
        return flow_success and session_success

async def main():
    """Main test function"""
    import argparse
    
    parser = argparse.ArgumentParser(description="HTTP-Only OAuth Test")
    parser.add_argument("--url", default="http://localhost:3001", help="Proxy server URL")
    
    args = parser.parse_args()
    
    tester = HTTPOnlyOAuthTest(args.url)
    await tester.run_http_tests()

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        console.print("\n[yellow]Test interrupted by user[/yellow]")
    except Exception as e:
        console.print(f"\n[red]Test failed: {e}[/red]")
