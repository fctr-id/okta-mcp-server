"""Helper functions for API interaction."""

import logging
from typing import Any, Tuple, Optional

logger = logging.getLogger(__name__)

def normalize_okta_response(response):
    """Normalize different Okta API response formats to (results, resp, err).
    
    The Okta SDK can return responses in several formats:
    - 3-tuple: (results, response, error)
    - 2-tuple: (results, response)
    - Direct result object
    
    This function standardizes all formats to the 3-tuple form.
    
    Args:
        response: The raw response from an Okta API call
        
    Returns:
        Tuple of (results, response, error)
    """
    if isinstance(response, tuple):
        if len(response) == 3:
            return response  # Already in (results, resp, err) format
        elif len(response) == 2:
            results, resp = response
            return results, resp, None
        else:
            logger.error(f"Unexpected response format with {len(response)} elements")
            return None, None, ValueError(f"Unexpected response format: {response}")
    else:
        # Just a single result - try to extract response attribute if present
        return response, getattr(response, 'response', None), None