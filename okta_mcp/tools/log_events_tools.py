"""Log event management tools for Okta MCP server."""

import logging
import csv
import os
from typing import Dict, Any, Optional, List
from mcp.server.fastmcp import FastMCP, Context
from mcp.types import TextContent

from okta_mcp.utils.okta_client import OktaMcpClient
from okta_mcp.utils.error_handling import handle_okta_result
from okta_mcp.utils.normalize_okta_responses import normalize_okta_response, paginate_okta_response

logger = logging.getLogger("okta_mcp_server")

# Add these imports for Pydantic AI
from pydantic import BaseModel, Field
# Define Pydantic model for event codes
class OktaEventCode(BaseModel):
    """Model representing an Okta event code."""
    event_type: str = Field(..., description="The Okta event type identifier")
    description: str = Field(..., description="Description of what the event represents")

async def load_event_codes() -> List[OktaEventCode]:
    """Load event codes from CSV file."""
    event_codes = []
    # Adjust path based on your actual file location
    csv_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), 
                        'data', 'okta-event-codes.csv')
    
    try:
        with open(csv_path, 'r', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            for row in reader:
                # Use the exact column names from your CSV
                event_codes.append(OktaEventCode(
                    event_type=row.get('Event Type', ''),
                    description=row.get('Description', '')
                ))
        return event_codes
    except Exception as e:
        logger.error(f"Error loading event codes CSV: {e}")
        return []


def register_log_events_tools(server: FastMCP, okta_client: OktaMcpClient):
    """Register all log event-related tools with the MCP server.
    Args:
        server: The FastMCP server instance
        okta_client: The Okta client wrapper
    """
    
    @server.tool()
    async def get_okta_event_logs(
        since: str = None,
        until: str = None,
        filter_string: str = None,
        q: str = None,
        sort_order: str = None,
        after: str = None,
        ctx: Context = None
    ) -> Dict[str, Any]:
        """Get Okta system log events with various filtering options.
        
        Args:
            since: Starting time for log events (ISO 8601 format)
            until: Ending time for log events (ISO 8601 format)
            filter_string: Filter expression for log events
            q: Search term for log events
            sort_order: Order of results ('ASCENDING' or 'DESCENDING')
            after: Pagination cursor
            ctx: MCP Context for progress reporting and logging
            
        Returns:
            Dictionary containing log events and pagination information
        """
        try:
            limit = 500
            
            if ctx:
                await ctx.info(f"Getting logs with parameters: since={since}, until={until}, filter={filter_string}, q={q}")
            
            # Validate parameters
            if limit < 1 or limit > 1000:
                raise ValueError("Limit must be between 1 and 1000")
                
            # Prepare request parameters
            params = {
                'limit': limit
            }
            
            if since:
                params['since'] = since
                
            if until:
                params['until'] = until
                
            if filter_string:
                params['filter'] = filter_string
                
            if q:
                params['q'] = q
                
            if sort_order:
                # Validate sort order
                if sort_order.upper() not in ['ASCENDING', 'DESCENDING']:
                    raise ValueError("Sort order must be either 'ASCENDING' or 'DESCENDING'")
                params['sortOrder'] = sort_order.upper()
                    
            if after:
                params['after'] = after
            
            if ctx:
                await ctx.info(f"Executing Okta API request with params: {params}")
            
            # Execute Okta API request
            raw_response = await okta_client.client.get_logs(params)
            log_events, resp, err = normalize_okta_response(raw_response)
            
            if err:
                logger.error(f"Error retrieving log events: {err}")
                if ctx:
                    await ctx.error(f"Error retrieving log events: {err}")
                return handle_okta_result(err, "get_logs")
            
            # Apply pagination based on environment variable
            if ctx:
                await ctx.info("Retrieving paginated results...")
            
            all_log_events = []
            page_count = 0
            
            # Process first page
            if log_events:
                all_log_events.extend(log_events)
                page_count += 1
            
            # Process additional pages if available
            while resp and hasattr(resp, 'has_next') and resp.has_next():
                if ctx:
                    await ctx.info(f"Retrieving page {page_count + 1}...")
                    await ctx.report_progress(page_count, page_count + 5)  # Estimate 5 pages total
                
                try:
                    # Use the response object's next() method directly
                    next_logs, next_err = await resp.next()
                    
                    if next_err:
                        logger.error(f"Error during pagination: {next_err}")
                        if ctx:
                            await ctx.error(f"Error during pagination: {next_err}")
                        break
                        
                    # Process valid log events
                    valid_logs = [log for log in next_logs if log and hasattr(log, 'as_dict')]
                    
                    if valid_logs:
                        all_log_events.extend(valid_logs)
                        page_count += 1
                    
                except Exception as e:
                    logger.error(f"Exception during pagination: {str(e)}")
                    if ctx:
                        await ctx.error(f"Exception during pagination: {str(e)}")
                    break
            
            if ctx:
                await ctx.info(f"Retrieved {len(all_log_events)} log events across {page_count} pages")
                await ctx.report_progress(100, 100)  # Mark as complete
            
            # Format response with enhanced pagination info
            result = {
                "log_events": [event.as_dict() for event in all_log_events],
                "pagination": {
                    "limit": limit,
                    "page_count": page_count,
                    "total_results": len(all_log_events),
                    "has_more": bool(resp.has_next()) if hasattr(resp, 'has_next') else False,
                    "self": resp.self if hasattr(resp, 'self') else None,
                    "next": resp.next if hasattr(resp, 'next') and resp.has_next() else None
                }
            }
            
            return result
        
        except Exception as e:
            logger.exception("Error in get_logs tool")
            if ctx:
                await ctx.error(f"Error in get_logs tool: {str(e)}")
            return handle_okta_result(e, "get_logs")        
        
    #logger.info("Registered log event management tools")
    
#@server.tool()
async def analyze_event_codes(
    description: str,
    ctx: Context = None
) -> Dict[str, Any]:
    """Analyze Okta event codes based on a description and return relevant codes for filtering logs.
    This tool uses AI to analyze Okta event codes based on your description
    and returns the appropriate codes to use with the get_logs filter parameter.
    
    Args:
        description: Description of the types of events you want to find (e.g., "failed logins", "user creation")
        ctx: MCP Context for progress reporting and logging
        
    Returns:
        Dictionary containing recommended event codes and filter string to use with get_logs
    """
    try:
        if ctx:
            await ctx.info(f"Analyzing event codes for: {description}")
            await ctx.report_progress(10, 100)
        
        # Load event codes from CSV
        event_codes = await load_event_codes()
        
        if not event_codes:
            return {
                "error": "Failed to load event codes",
                "filter_string": None,
                "event_codes": []
            }
        
        if ctx:
            await ctx.info(f"Loaded {len(event_codes)} event codes")
            await ctx.report_progress(30, 100)
        
        # Create the model instance using the same approach as in mcp-cli-stdio-client.py
        # Use global model from the agent's existing setup
        # This assumes the agent's model is already set up and can be accessed
        
        # Import the Agent class from your existing setup
        from pydantic_ai import Agent
        from okta_mcp.utils.model_provider import get_model
        
        model = get_model()  # Get the model from your utility function
        
        # Create a system prompt specific to this task
        system_prompt = """
        You are an expert in Okta event codes. Your task is to analyze Okta event codes and 
        select the most relevant ones based on the user's query.
        
        Review the provided event codes and select only those that closely match what the user is looking for.
        Provide a brief explanation for why you selected these codes.
        
        Return your response as a JSON object with these properties:
        - event_codes: Array of relevant event type strings
        """
        
        # Create an agent for this specific task
        agent = Agent(
            model=model,
            system_prompt=system_prompt
        )
        
        if ctx:
            await ctx.info("Creating agent to analyze event codes")
            await ctx.report_progress(50, 100)
        
        # Format the event codes as a simple list for the AI
        event_data = "\n".join([f"Event Type: {e.event_type}" for e in event_codes])
        
        # Create the prompt for the AI
        prompt = f"""
        I need to find Okta log events related to: {description}
        
        Here are the available Okta event types:
        {event_data}
        
        Select the most relevant event types for this request and return them in the required JSON format.
        """
        
        # Run the analysis
        if ctx:
            await ctx.info("Running AI analysis of event codes")
            await ctx.report_progress(70, 100)
        
        result = await agent.run(prompt)
        
        # Extract the data from the result
        if hasattr(result, 'data') and isinstance(result.data, dict):
            response_data = result.data
        else:
            # Fallback if structuring failed
            response_data = {
                "event_codes": []
            }
        
        # Format the filter string for Okta's API
        event_codes = response_data.get("event_codes", [])
        if event_codes:
            if len(event_codes) == 1:
                filter_string = f"eventType eq \"{event_codes[0]}\""
            else:
                filter_parts = [f"eventType eq \"{code}\"" for code in event_codes]
                filter_string = "(" + " or ".join(filter_parts) + ")"
        else:
            filter_string = ""
        
        if ctx:
            await ctx.info("Analysis complete")
            await ctx.report_progress(100, 100)
        
        return {
            "event_codes": event_codes,
            "filter_string": filter_string,
            "explanation": response_data.get("explanation", "")
        }
        
    except Exception as e:
        logger.exception("Error in analyze_event_codes tool")
        if ctx:
            await ctx.error(f"Error in analyze_event_codes tool: {str(e)}")
        return {
            "error": str(e),
            "filter_string": None,
            "event_codes": []
        }