#!/usr/bin/env python3
"""
Test script for OAuth discovery endpoints (.well-known)
Tests the RFC 8414 compliance of our OAuth proxy
"""

import asyncio
import httpx
import json
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
import time

console = Console()

class WellKnownEndpointTester:
    """Test OAuth discovery endpoints"""
    
    def __init__(self, proxy_url: str = "http://localhost:3001"):
        self.proxy_url = proxy_url
        self.endpoints = {
            "protected_resource": "/.well-known/oauth-protected-resource",
            "authorization_server": "/.well-known/oauth-authorization-server", 
            "jwks": "/.well-known/jwks.json",
            "health": "/health"
        }
    
    async def test_all_endpoints(self):
        """Test all well-known endpoints"""
        console.print("\n[bold blue]🔍 Testing OAuth Discovery Endpoints[/bold blue]")
        console.print(f"[dim]Proxy URL: {self.proxy_url}[/dim]\n")
        
        results = {}
        
        async with httpx.AsyncClient(timeout=10.0) as client:
            for name, endpoint in self.endpoints.items():
                console.print(f"Testing {name}...")
                results[name] = await self.test_endpoint(client, endpoint)
        
        self.display_results(results)
        return results
    
    async def test_endpoint(self, client: httpx.AsyncClient, endpoint: str) -> dict:
        """Test a single endpoint"""
        url = f"{self.proxy_url}{endpoint}"
        
        try:
            start_time = time.time()
            response = await client.get(url)
            duration = time.time() - start_time
            
            result = {
                "url": url,
                "status_code": response.status_code,
                "duration_ms": round(duration * 1000, 2),
                "success": response.status_code == 200,
                "content_type": response.headers.get("content-type", ""),
                "error": None
            }
            
            if response.status_code == 200:
                try:
                    data = response.json()
                    result["data"] = data
                    result["keys_count"] = len(data) if isinstance(data, dict) else 0
                    
                    # Specific validations
                    if endpoint == "/.well-known/oauth-protected-resource":
                        result["validation"] = self.validate_protected_resource(data)
                    elif endpoint == "/.well-known/oauth-authorization-server":
                        result["validation"] = self.validate_authorization_server(data)
                    elif endpoint == "/.well-known/jwks.json":
                        result["validation"] = self.validate_jwks(data)
                    elif endpoint == "/health":
                        result["validation"] = self.validate_health(data)
                        
                except json.JSONDecodeError as e:
                    result["error"] = f"Invalid JSON: {e}"
                    result["data"] = response.text[:200]
            else:
                result["error"] = f"HTTP {response.status_code}: {response.text[:200]}"
                
        except Exception as e:
            result = {
                "url": url,
                "status_code": None,
                "duration_ms": None,
                "success": False,
                "error": str(e)
            }
        
        return result
    
    def validate_protected_resource(self, data: dict) -> dict:
        """Validate OAuth protected resource metadata"""
        required_fields = ["resource", "authorization_servers", "scopes_supported"]
        validation = {"valid": True, "issues": []}
        
        for field in required_fields:
            if field not in data:
                validation["issues"].append(f"Missing required field: {field}")
                validation["valid"] = False
        
        if "mcp_protocol_version" in data:
            validation["mcp_compliant"] = True
        
        return validation
    
    def validate_authorization_server(self, data: dict) -> dict:
        """Validate OAuth authorization server metadata"""
        required_fields = ["issuer", "authorization_endpoint", "token_endpoint"]
        validation = {"valid": True, "issues": []}
        
        for field in required_fields:
            if field not in data:
                validation["issues"].append(f"Missing required field: {field}")
                validation["valid"] = False
        
        return validation
    
    def validate_jwks(self, data: dict) -> dict:
        """Validate JWKS structure"""
        validation = {"valid": True, "issues": []}
        
        if "keys" not in data:
            validation["issues"].append("Missing 'keys' array")
            validation["valid"] = False
        else:
            keys_count = len(data["keys"])
            validation["keys_count"] = keys_count
            if keys_count == 0:
                validation["issues"].append("No keys found in JWKS")
                validation["valid"] = False
        
        return validation
    
    def validate_health(self, data: dict) -> dict:
        """Validate health endpoint response"""
        validation = {"valid": True, "issues": []}
        
        if data.get("status") != "healthy":
            validation["issues"].append(f"Status not healthy: {data.get('status')}")
            validation["valid"] = False
        
        if "oauth_discovery" in data:
            validation["discovery_endpoints"] = True
        
        return validation
    
    def display_results(self, results: dict):
        """Display test results in a nice table"""
        table = Table(title="OAuth Discovery Endpoints Test Results")
        table.add_column("Endpoint", style="cyan")
        table.add_column("Status", style="green")
        table.add_column("Duration", style="yellow")
        table.add_column("Validation", style="magenta")
        table.add_column("Details", style="dim")
        
        for name, result in results.items():
            status = "✅ PASS" if result["success"] else "❌ FAIL"
            duration = f"{result.get('duration_ms', 0)}ms" if result.get('duration_ms') else "N/A"
            
            validation_info = ""
            if "validation" in result:
                val = result["validation"]
                if val.get("valid"):
                    validation_info = "✅ Valid"
                    if "keys_count" in val:
                        validation_info += f" ({val['keys_count']} keys)"
                else:
                    validation_info = f"❌ Issues: {len(val.get('issues', []))}"
            
            details = ""
            if result.get("error"):
                details = result["error"][:50]
            elif "validation" in result and result["validation"].get("issues"):
                details = "; ".join(result["validation"]["issues"][:2])
            else:
                details = f"HTTP {result.get('status_code', 'N/A')}"
            
            table.add_row(name, status, duration, validation_info, details)
        
        console.print(table)
        
        # Summary
        total_tests = len(results)
        passed_tests = sum(1 for r in results.values() if r["success"])
        
        if passed_tests == total_tests:
            console.print(f"\n[green]✅ All {total_tests} tests passed![/green]")
        else:
            console.print(f"\n[yellow]⚠️  {passed_tests}/{total_tests} tests passed[/yellow]")
        
        # Show sample data for successful endpoints
        for name, result in results.items():
            if result["success"] and "data" in result and name != "health":
                console.print(f"\n[bold]{name.replace('_', ' ').title()} Sample:[/bold]")
                sample_data = json.dumps(result["data"], indent=2)[:500]
                console.print(Panel(sample_data, expand=False))
    
    async def test_caching(self):
        """Test JWKS caching behavior"""
        console.print("\n[bold blue]🔄 Testing JWKS Caching[/bold blue]")
        
        jwks_url = f"{self.proxy_url}/.well-known/jwks.json"
        
        async with httpx.AsyncClient() as client:
            # First request
            start1 = time.time()
            response1 = await client.get(jwks_url)
            duration1 = time.time() - start1
            
            # Second request (should be cached)
            start2 = time.time()
            response2 = await client.get(jwks_url)
            duration2 = time.time() - start2
            
            console.print(f"First request: {duration1*1000:.2f}ms")
            console.print(f"Second request: {duration2*1000:.2f}ms")
            
            if duration2 < duration1 * 0.5:  # If second request is significantly faster
                console.print("[green]✅ Caching appears to be working[/green]")
            else:
                console.print("[yellow]⚠️  Caching may not be working optimally[/yellow]")

async def main():
    """Main test function"""
    tester = WellKnownEndpointTester()
    
    console.print("[bold green]🚀 OAuth Discovery Endpoints Test Suite[/bold green]")
    console.print("[dim]Make sure your OAuth proxy is running on http://localhost:3001[/dim]")
    
    # Test all endpoints
    results = await tester.test_all_endpoints()
    
    # Test caching
    await tester.test_caching()
    
    # Final recommendations
    console.print("\n[bold]📋 Recommendations:[/bold]")
    if all(r["success"] for r in results.values()):
        console.print("✅ All endpoints working correctly")
        console.print("✅ Ready for MCP client integration")
    else:
        console.print("❌ Some endpoints need attention")
        console.print("🔧 Check the proxy logs for detailed error information")

if __name__ == "__main__":
    asyncio.run(main())
