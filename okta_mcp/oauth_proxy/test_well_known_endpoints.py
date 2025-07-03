#!/usr/bin/env python3
"""
Test all well-known OAuth discovery endpoints
"""

import asyncio
import httpx
import json
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

console = Console()

async def test_well_known_endpoints():
    """Test all OAuth discovery endpoints"""
    
    base_url = "http://localhost:3001"
    endpoints = [
        "/.well-known/oauth-protected-resource",
        "/.well-known/oauth-authorization-server", 
        "/.well-known/jwks.json"
    ]
    
    console.print("\n[bold blue]🔍 Testing OAuth Discovery Endpoints[/bold blue]")
    
    table = Table(title="OAuth Discovery Endpoint Tests")
    table.add_column("Endpoint", style="cyan")
    table.add_column("Status", style="green")
    table.add_column("Response Size", style="yellow") 
    table.add_column("Key Fields", style="magenta")
    
    async with httpx.AsyncClient() as client:
        for endpoint in endpoints:
            try:
                url = f"{base_url}{endpoint}"
                response = await client.get(url, timeout=10.0)
                
                if response.status_code == 200:
                    data = response.json()
                    
                    # Extract key fields based on endpoint type
                    if "protected-resource" in endpoint:
                        key_fields = f"resource, {len(data.get('scopes_supported', []))} scopes"
                    elif "authorization-server" in endpoint:
                        key_fields = f"issuer, {len(data.get('scopes_supported', []))} scopes"
                    elif "jwks" in endpoint:
                        key_fields = f"{len(data.get('keys', []))} keys"
                    else:
                        key_fields = "unknown"
                    
                    table.add_row(
                        endpoint,
                        "✅ OK",
                        f"{len(response.content)} bytes",
                        key_fields
                    )
                    
                    # Show first few fields for debugging
                    console.print(f"\n[dim]Sample from {endpoint}:[/dim]")
                    if isinstance(data, dict):
                        for key, value in list(data.items())[:3]:
                            console.print(f"  {key}: {str(value)[:60]}{'...' if len(str(value)) > 60 else ''}")
                
                else:
                    table.add_row(
                        endpoint,
                        f"❌ {response.status_code}",
                        f"{len(response.content)} bytes",
                        "Error"
                    )
                    
            except Exception as e:
                table.add_row(
                    endpoint,
                    f"💥 Error",
                    "0 bytes", 
                    str(e)[:30]
                )
    
    console.print(table)
    
    # Test CORS headers
    console.print("\n[bold blue]🌐 Testing CORS Support[/bold blue]")
    
    async with httpx.AsyncClient() as client:
        for endpoint in endpoints:
            try:
                url = f"{base_url}{endpoint}"
                response = await client.options(url)
                
                cors_headers = {
                    key: value for key, value in response.headers.items()
                    if key.lower().startswith('access-control')
                }
                
                if cors_headers:
                    console.print(f"✅ {endpoint}: {len(cors_headers)} CORS headers")
                else:
                    console.print(f"⚠️  {endpoint}: No CORS headers")
                    
            except Exception as e:
                console.print(f"❌ {endpoint}: CORS test failed - {e}")

if __name__ == "__main__":
    console.print(Panel.fit("OAuth Discovery Endpoint Tester", style="bold green"))
    console.print("Make sure your OAuth proxy is running on http://localhost:3001")
    
    try:
        asyncio.run(test_well_known_endpoints())
    except KeyboardInterrupt:
        console.print("\n[yellow]Test interrupted[/yellow]")
    except Exception as e:
        console.print(f"\n[red]Test failed: {e}[/red]")
