"""Okta client utilities for MCP server."""
import os
import time
import logging
from typing import Optional, Dict, Any, Callable, Awaitable

from okta.client import Client as OktaClient

logger = logging.getLogger(__name__)

class OktaMcpClient:
    """Wrapper around the Okta SDK client with rate limiting and error handling."""
    
    def __init__(self, client: Optional[OktaClient] = None, request_manager=None):
        """Initialize the Okta MCP client wrapper.
        
        Args:
            client: An initialized Okta SDK client (optional, will be created on demand)
            request_manager: Optional RequestManager to control concurrent requests
        """
        self._client = client
        self._client_initialized = client is not None
        self.rate_limits = {}  # Tracks rate limits by endpoint
        self.request_manager = request_manager
    
    @property
    def client(self) -> OktaClient:
        """Get the Okta client, initializing if needed."""
        if not self._client_initialized:
            self._initialize_client()
        return self._client
    
    def _initialize_client(self):
        """Initialize the Okta client on demand."""
        org_url = os.getenv('OKTA_CLIENT_ORGURL')
        api_token = os.getenv('OKTA_API_TOKEN')
        
        if not org_url or not api_token:
            raise ValueError(
                "Okta configuration required. Set OKTA_CLIENT_ORGURL and OKTA_API_TOKEN environment variables."
            )
        
        self._client = create_okta_client(org_url, api_token)
        self._client_initialized = True
        logger.info("Okta client initialized on demand")
    
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
    
    async def execute_api_call(self, func, *args, **kwargs):
        """Execute an Okta API call with concurrency control.
        
        If a request_manager is available, the call will be
        managed to ensure we don't exceed concurrent call limits.
        
        Args:
            func: The API function to call
            args, kwargs: Arguments to pass to the function
            
        Returns:
            The result of the API call
        """
        # Ensure client is initialized
        _ = self.client  # This triggers initialization if needed
        
        # If we have a request manager, use it to control concurrency
        if self.request_manager:
            logger.debug(f"Executing API call via RequestManager: {func.__name__}")
            return await self.request_manager.execute(func, *args, **kwargs)
        
        # Otherwise execute directly
        logger.debug(f"Executing API call directly: {func.__name__}")
        return await func(*args, **kwargs)


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