"""AI-powered sampling capabilities using FastMCP for intelligent Okta operations."""
import logging
import json
from typing import Dict, Any, List, Optional, Union
from datetime import datetime, timedelta

from fastmcp import FastMCP, Context
from fastmcp.client.sampling import (
    RequestContext,
    SamplingMessage,
    SamplingParams
)

from okta_mcp.utils.model_provider import get_model

logger = logging.getLogger(__name__)

# Initialize the model client (could be OpenAI, Ollama, etc.)
try:
    llm_client = get_model()
    logger.info(f"AI model client initialized: {type(llm_client).__name__}")
except Exception as e:
    logger.error(f"Failed to initialize AI model client: {e}")
    llm_client = None

async def sampling_handler(
    messages: List[SamplingMessage],
    params: SamplingParams,
    ctx: RequestContext,
) -> str:
    """Handle sampling requests from the server using the LLM client."""
    
    if not llm_client:
        return "AI model not available"
    
    try:
        system_instruction = params.systemPrompt or "You are a helpful Okta administrator assistant."
        payload = [{"role": "system", "content": system_instruction}]
        
        for m in messages:
            if m.content.type == "text":
                payload.append({"role": "user", "content": m.content.text})
        
        logger.info(f"Processing sampling request with {len(messages)} messages")
        
        # Use your model provider (adapt this based on your get_model() implementation)
        if hasattr(llm_client, 'chat') and hasattr(llm_client.chat, 'completions'):
            # OpenAI-compatible client
            response = llm_client.chat.completions.create(
                messages=payload,
                model="gpt-4o-mini",  # or whatever model you're using
                max_tokens=500
            )
            return response.choices[0].message.content
        else:
            # Pydantic AI or other client
            from pydantic_ai import Agent
            agent = Agent(model=llm_client, system_prompt=system_instruction)
            
            # Get the last user message
            user_message = ""
            for m in messages:
                if m.content.type == "text":
                    user_message = m.content.text
            
            result = await agent.run(user_message)
            return str(result.data)
            
    except Exception as e:
        logger.error(f"Error in sampling handler: {e}")
        return f"Sorry, I encountered an error: {str(e)}"

def register_sampling_tools(server: FastMCP):
    """Register AI-powered sampling tools with the FastMCP server."""
    
    @server.tool()
    async def generate_okta_scim_query(user_intent: str, context: Context) -> Dict[str, Any]:
        """Convert natural language intent to Okta SCIM query using AI."""
        
        if not context:
            return {"error": "Context not available"}
        
        try:
            await context.info(f"Generating SCIM query from: '{user_intent}'")
            
            system_prompt = """You are an expert in Okta SCIM filtering. Convert natural language requests into proper Okta SCIM filter expressions.

SCIM Filter Operators:
- eq (equals): profile.firstName eq "John"
- ne (not equals): profile.department ne "IT"
- sw (starts with): profile.email sw "john"  
- co (contains): profile.displayName co "Smith"
- pr (present): profile.mobilePhone pr
- gt/ge (greater): lastLogin gt "2024-01-01T00:00:00.000Z"
- lt/le (less): created lt "2024-12-31T23:59:59.000Z"
- and/or: status eq "ACTIVE" and profile.department eq "Engineering"

Common Profile Fields:
- profile.firstName, profile.lastName, profile.email
- profile.department, profile.title, profile.city
- profile.employeeNumber, profile.mobilePhone
- status (ACTIVE, SUSPENDED, DEPROVISIONED)
- created, lastLogin, lastUpdated

Return ONLY the SCIM filter expression, no explanation."""
            
            response = await context.sample(
                f"Convert this request to an Okta SCIM filter: '{user_intent}'",
                system_prompt=system_prompt
            )
            
            scim_filter = response.strip() if hasattr(response, 'strip') else str(response).strip()
            
            await context.info(f"Generated SCIM filter: {scim_filter}")
            
            return {
                "original_intent": user_intent,
                "scim_filter": scim_filter,
                "generated_by": "ai"
            }
            
        except Exception as e:
            logger.error(f"Error generating SCIM query: {e}")
            await context.error(f"Failed to generate SCIM query: {str(e)}")
            
            # Fallback to simple pattern matching
            fallback_filter = _simple_pattern_matching(user_intent)
            
            return {
                "original_intent": user_intent,
                "scim_filter": fallback_filter,
                "generated_by": "fallback",
                "error": str(e)
            }

    @server.tool()
    async def analyze_user_data(users_data: str, analysis_type: str = "general", context: Context = None) -> str:
        """Generate AI-powered analysis of user data."""
        
        if not context:
            return "Context not available"
        
        try:
            await context.info(f"Analyzing user data with {analysis_type} analysis")
            
            # Parse users data (expecting JSON string)
            try:
                users = json.loads(users_data)
                user_count = len(users) if isinstance(users, list) else 1
            except json.JSONDecodeError:
                user_count = "unknown"
            
            analysis_prompts = {
                "general": "Analyze this Okta user data and provide insights about user distribution, patterns, and administrative recommendations.",
                "security": "Analyze this user data from a security perspective, identifying potential risks and security recommendations.",
                "compliance": "Analyze this user data for compliance issues and provide recommendations for compliance improvement.",
                "activity": "Analyze user activity patterns and provide user lifecycle recommendations."
            }
            
            system_prompt = f"""You are an IT administrator analyzing Okta user data. {analysis_prompts.get(analysis_type, analysis_prompts['general'])}
            
Provide a clear, actionable summary with:
- Key insights
- Notable patterns  
- Specific recommendations
- Action items for administrators"""
            
            response = await context.sample(
                f"Analyze this user data ({user_count} users):\n\n{users_data[:2000]}...",  # Truncate for token limits
                system_prompt=system_prompt
            )
            
            analysis = response if hasattr(response, 'strip') else str(response)
            
            await context.info(f"Generated {len(analysis)} character analysis")
            
            return analysis
            
        except Exception as e:
            logger.error(f"Error analyzing user data: {e}")
            if context:
                await context.error(f"Analysis failed: {str(e)}")
            return f"Error generating analysis: {str(e)}"

    @server.tool()
    async def suggest_user_actions(user_data: str, action_context: str = "", context: Context = None) -> List[str]:
        """Suggest relevant actions for a specific user based on their profile."""
        
        if not context:
            return ["Context not available"]
        
        try:
            await context.info(f"Generating action suggestions for user")
            
            system_prompt = """You are an IT administrator assistant. Based on user data, suggest 3-5 specific, actionable recommendations.

Consider:
- User status and account health
- Login patterns and security
- Profile completeness  
- Compliance requirements
- User lifecycle management

Return suggestions as a simple numbered list."""
            
            prompt = f"Suggest actions for this user:\n\nUser Data: {user_data}\nContext: {action_context}"
            
            response = await context.sample(prompt, system_prompt=system_prompt)
            
            suggestions_text = response if hasattr(response, 'strip') else str(response)
            
            # Parse suggestions into list
            suggestions = [
                line.strip().lstrip('1234567890.-*•').strip() 
                for line in suggestions_text.split('\n') 
                if line.strip() and len(line.strip()) > 10
            ]
            
            # Clean and filter suggestions
            clean_suggestions = []
            for suggestion in suggestions[:5]:  # Limit to 5
                if suggestion and not suggestion.lower().startswith(('here', 'based', 'the')):
                    clean_suggestions.append(suggestion)
            
            await context.info(f"Generated {len(clean_suggestions)} action suggestions")
            
            return clean_suggestions
            
        except Exception as e:
            logger.error(f"Error generating user action suggestions: {e}")
            if context:
                await context.error(f"Failed to generate suggestions: {str(e)}")
            return [f"Error generating suggestions: {str(e)}"]

    @server.tool()
    async def detect_user_anomalies(users_data: str, context: Context = None) -> Dict[str, Any]:
        """Use AI to detect potential anomalies or security concerns in user data."""
        
        if not context:
            return {"error": "Context not available"}
        
        try:
            await context.info("Running AI-powered anomaly detection")
            
            system_prompt = """You are a security analyst reviewing Okta user data for anomalies.

Look for:
- Users with unusual login patterns
- Accounts created in suspicious batches  
- Users with incomplete security profiles
- Dormant accounts with elevated access
- Geographic inconsistencies
- Unusual naming patterns

Respond with a JSON object:
{
    "anomalies_found": true/false,
    "total_issues": number,
    "critical_issues": ["list of critical issues"],
    "recommendations": ["list of recommendations"],
    "summary": "brief summary"
}"""
            
            response = await context.sample(
                f"Analyze for anomalies in this user data:\n\n{users_data[:1500]}...",
                system_prompt=system_prompt
            )
            
            try:
                # Try to parse as JSON
                result = json.loads(str(response))
                await context.info(f"Detected {result.get('total_issues', 0)} potential issues")
                return result
            except json.JSONDecodeError:
                # Fallback if not valid JSON
                return {
                    "anomalies_found": True,
                    "total_issues": 0,
                    "critical_issues": [],
                    "recommendations": [],
                    "summary": str(response),
                    "note": "Could not parse structured response"
                }
                
        except Exception as e:
            logger.error(f"Error in anomaly detection: {e}")
            if context:
                await context.error(f"Anomaly detection failed: {str(e)}")
            return {"error": str(e), "anomalies_found": False}

    logger.info("✅ AI sampling tools registered successfully")

def _simple_pattern_matching(user_intent: str) -> str:
    """Simple fallback pattern matching for SCIM generation."""
    intent_lower = user_intent.lower()
    
    if "dan" in intent_lower:
        return 'profile.firstName sw "Dan" or profile.lastName sw "Dan"'
    elif "active" in intent_lower:
        return 'status eq "ACTIVE"'
    elif "department" in intent_lower:
        return 'profile.department pr'
    elif "email" in intent_lower:
        return 'profile.email pr'
    elif "first name" in intent_lower or "firstname" in intent_lower:
        return 'profile.firstName pr'
    elif "last name" in intent_lower or "lastname" in intent_lower:
        return 'profile.lastName pr'
    else:
        # Extract any word that looks like a name
        words = [w.strip() for w in user_intent.split() if w.strip().isalpha() and len(w) > 2]
        if words:
            name = words[0].title()
            return f'profile.displayName co "{name}"'
        return 'status eq "ACTIVE"'
    
def register_sampling_capabilities(server: FastMCP, okta_client=None):
    """Alias for compatibility with tool registry."""
    logger.info("Registering sampling capabilities via compatibility alias")
    return register_sampling_tools(server)    

# Export main components
__all__ = [
    "sampling_handler",
    "register_sampling_tools",
    "register_sampling_capabilities"
]