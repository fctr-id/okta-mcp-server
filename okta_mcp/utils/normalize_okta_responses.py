"""Helper functions for API interaction."""

import os
import logging
from typing import Any, Tuple, Optional, List

logger = logging.getLogger("okta_mcp_server")

# Read pagination limit from environment variable, default to 1 if not set
DEFAULT_PAGINATION_LIMIT = int(os.getenv('PAGINATION_LIMIT', '1'))

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


async def paginate_okta_response(initial_results, initial_resp, initial_err=None):
    # If there's an error in the initial response, return immediately
    if initial_err:
        return initial_results, initial_resp, initial_err, 1
        
    max_pages = DEFAULT_PAGINATION_LIMIT
    
    # Filter out empty objects from initial results
    all_results = [r for r in initial_results if r and hasattr(r, 'as_dict')]
    logger.info(f"Initial results: {len(initial_results)} raw items, {len(all_results)} valid")
    
    response = initial_resp
    page_count = 1
    
    # Continue fetching pages while available and within limit
    try:
        while (page_count < max_pages and 
               response and 
               hasattr(response, 'has_next') and 
               response.has_next()):
            
            logger.info(f"Fetching page {page_count + 1} of {max_pages}")
            page_count += 1
            
            # Get next page - important: use the Okta SDK's native pagination
            next_users, next_err = await response.next()
            
            if next_err:
                logger.error(f"Error fetching page {page_count}: {next_err}")
                break
                
            # Filter out empty objects
            valid_users = [user for user in next_users if user and hasattr(user, 'as_dict')]
            logger.info(f"Page {page_count}: {len(next_users)} raw items, {len(valid_users)} valid users")
            
            # Add valid users to our results
            all_results.extend(valid_users)
    except Exception as e:
        logger.error(f"Exception during pagination: {str(e)}")
    
    logger.info(f"Pagination complete: {len(all_results)} total valid results from {page_count} pages")
    return all_results, response, None, page_count