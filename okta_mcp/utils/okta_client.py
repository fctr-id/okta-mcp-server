"""Okta client utilities for MCP server."""
import os
import time
import logging
from typing import Optional, Dict, Any

from okta.client import Client as OktaClient

logger = logging.getLogger(__name__)

class OktaMcpClient:
    """Wrapper around the Okta SDK client with rate limiting and error handling."""
    
    def __init__(self, client: OktaClient):
        """Initialize the Okta MCP client wrapper.
        
        Args:
            client: An initialized Okta SDK client
        """
        self.client = client
        self.rate_limits = {}  # Tracks rate limits by endpoint
    
    def update_rate_limit(self, endpoint: str, reset_seconds: int):
        """Update rate limit tracking for an endpoint.
        
        Args:
            endpoint: API endpoint that was rate limited
            reset_seconds: Seconds until rate limit resets
        """
        self.rate_limits[endpoint] = time.time() + reset_seconds
        logger.warning(f"Rate limit hit for {endpoint}, reset in {reset_seconds} seconds")
    
    def is_rate_limited(self, endpoint: str) -> bool:
        """Check if an endpoint is currently rate limited.
        
        Args:
            endpoint: API endpoint to check
            
        Returns:
            True if the endpoint is rate limited, False otherwise
        """
        if endpoint not in self.rate_limits:
            return False
        
        if time.time() > self.rate_limits[endpoint]:
            # Rate limit has expired, remove it
            del self.rate_limits[endpoint]
            return False
            
        return True


def create_okta_client(org_url: str, api_token: str) -> OktaClient:
    """Create an authenticated Okta client.
    
    Args:
        org_url: Okta organization URL
        api_token: Okta API token
        
    Returns:
        Initialized Okta SDK client
    """
    if not org_url or not api_token:
        raise ValueError("Okta organization URL and API token are required")
    
    config = {
        'orgUrl': org_url,
        'token': api_token,
        'requestTimeout': 30,  # 30 second timeout for requests
        'rateLimit': {
            'maxRetries': 1,   # Retry up to 3 times on rate limit
        }
    }
    
    logger.info(f"Initializing Okta client for {org_url}")
    return OktaClient(config)