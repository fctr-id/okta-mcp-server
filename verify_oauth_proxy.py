#!/usr/bin/env python3
"""
Simple test to verify the OAuth FastMCP proxy implementation
"""
import sys
import os

# Add current directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

def test_imports():
    """Test all required imports"""
    print("Testing imports...")
    
    try:
        import fastmcp
        print("✅ fastmcp")
    except ImportError as e:
        print(f"❌ fastmcp: {e}")
        return False
    
    try:
        import aiohttp
        print("✅ aiohttp")
    except ImportError as e:
        print(f"❌ aiohttp: {e}")
        return False
    
    try:
        import authlib
        print("✅ authlib")
    except ImportError as e:
        print(f"❌ authlib: {e}")
        return False
    
    try:
        import httpx
        print("✅ httpx")
    except ImportError as e:
        print(f"❌ httpx: {e}")
        return False
    
    try:
        from okta_mcp.auth.oauth_provider import OAuthConfig
        print("✅ OAuthConfig")
    except ImportError as e:
        print(f"❌ OAuthConfig: {e}")
        return False
    
    try:
        from okta_oauth_fastmcp_proxy import OAuthFastMCPProxy
        print("✅ OAuthFastMCPProxy")
    except ImportError as e:
        print(f"❌ OAuthFastMCPProxy: {e}")
        return False
    
    return True

def test_initialization():
    """Test proxy initialization"""
    print("\nTesting proxy initialization...")
    
    try:
        from okta_oauth_fastmcp_proxy import OAuthFastMCPProxy
        
        # Mock environment variables for testing
        os.environ.setdefault("OKTA_ORG_URL", "https://test.okta.com")
        os.environ.setdefault("OKTA_CLIENT_ID", "test_client_id")
        os.environ.setdefault("OKTA_CLIENT_SECRET", "test_client_secret")
        os.environ.setdefault("OKTA_API_TOKEN", "test_api_token")
        
        proxy = OAuthFastMCPProxy("./main.py")
        print("✅ Proxy initialization successful")
        print(f"   Backend: {proxy.backend_server_path}")
        print(f"   Config: {proxy.config.org_url}")
        return True
        
    except Exception as e:
        print(f"❌ Proxy initialization failed: {e}")
        import traceback
        traceback.print_exc()
        return False

def main():
    """Run all tests"""
    print("=" * 50)
    print("OAuth FastMCP Proxy - Verification Test")
    print("=" * 50)
    
    success = True
    
    # Test imports
    if not test_imports():
        success = False
    
    # Test initialization
    if not test_initialization():
        success = False
    
    print("\n" + "=" * 50)
    if success:
        print("🎉 All tests passed! The OAuth FastMCP Proxy is ready to use.")
        print("\nNext steps:")
        print("1. Set your Okta environment variables")
        print("2. Run: python okta_oauth_fastmcp_proxy.py")
        print("3. Visit: http://localhost:3001")
    else:
        print("❌ Some tests failed. Check the errors above.")
    print("=" * 50)
    
    return success

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
