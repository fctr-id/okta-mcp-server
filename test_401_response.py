#!/usr/bin/env python3
"""
Test script to verify RFC 6750 compliant 401 response format
"""

from okta_mcp.oauth_proxy.utils import create_401_response


class MockRequest:
    """Mock request object for testing"""
    def __init__(self, scheme='https', host='resource.example.com'):
        self.scheme = scheme
        self.host = host


def test_401_response():
    """Test that our 401 response matches RFC 6750 requirements"""
    
    # Create a mock request
    request = MockRequest()
    
    # Generate 401 response
    response = create_401_response(request, "Authentication required")
    
    # Check the response
    print("=== RFC 6750 Compliance Test ===")
    print(f"Status Code: {response.status}")
    print(f"WWW-Authenticate Header: {response.headers.get('WWW-Authenticate')}")
    print(f"Expected Format: Bearer resource_metadata=\"https://resource.example.com/.well-known/oauth-protected-resource\"")
    
    # Verify compliance
    www_auth = response.headers.get('WWW-Authenticate', '')
    expected_base = 'Bearer resource_metadata="https://resource.example.com/.well-known/oauth-protected-resource"'
    
    if www_auth == expected_base:
        print("✅ PASS: WWW-Authenticate header matches RFC 6750 specification")
    else:
        print("❌ FAIL: WWW-Authenticate header does not match specification")
        print(f"   Got: {www_auth}")
        print(f"   Expected: {expected_base}")
    
    # Check other aspects
    if response.status == 401:
        print("✅ PASS: HTTP status is 401 Unauthorized")
    else:
        print(f"❌ FAIL: Expected 401, got {response.status}")
    
    print("\n=== Full Response Headers ===")
    for header, value in response.headers.items():
        print(f"{header}: {value}")


if __name__ == "__main__":
    test_401_response()
