"""
Enhanced elicitation capabilities for FastMCP.
Provides interactive user input collection and confirmation workflows.
"""

import logging
from typing import Dict, Any, List, Optional, Union, Type
from dataclasses import dataclass
from pydantic import BaseModel, Field

try:
    from okta_mcp.utils.logging import get_logger
    logger = get_logger(__name__)
except (ImportError, AttributeError):
    logger = logging.getLogger("okta_mcp.capabilities.elicitation")

# Check if FastMCP elicitation is available
try:
    from fastmcp import Context
    ELICITATION_AVAILABLE = hasattr(Context, 'elicit')
except ImportError:
    ELICITATION_AVAILABLE = False

# ==================== ELICITATION SCHEMAS ====================

@dataclass
class ConfirmationData:
    """Basic confirmation schema."""
    confirm: bool
    reason: str = ""

@dataclass
class UserSearchRefinement:
    """Schema for refining user search parameters."""
    add_filters: str = ""
    remove_filters: str = ""
    change_limit: int = 0
    include_deactivated: bool = False

@dataclass
class UserCreationConfirmation:
    """Schema for confirming user creation."""
    confirm: bool
    activate_immediately: bool = True
    send_welcome_email: bool = True
    notes: str = ""

@dataclass
class UserUpdateConfirmation:
    """Schema for confirming user updates."""
    confirm: bool
    notify_user: bool = False
    reason: str = ""

# ==================== ELICITATION FUNCTIONS ====================

async def elicit_confirmation(
    ctx, 
    message: str, 
    response_type: Type = ConfirmationData,
    auto_confirm: bool = True
) -> Any:
    """
    Elicit user confirmation with fallback support.
    
    Args:
        ctx: FastMCP Context object
        message: Message to display to user
        response_type: Dataclass type for the response
        auto_confirm: Whether to auto-confirm if elicitation unavailable
        
    Returns:
        ElicitationResult or fallback data
    """
    if ELICITATION_AVAILABLE and hasattr(ctx, 'elicit'):
        try:
            logger.info(f"Eliciting user input: {message[:50]}...")
            result = await ctx.elicit(
                message=message,
                response_type=response_type
            )
            logger.info(f"Elicitation result: {result.action}")
            return result
        except Exception as e:
            logger.error(f"Elicitation failed: {e}")
            
    # Fallback mode
    logger.info(f"Elicitation fallback for: {message[:50]}...")
    
    if auto_confirm:
        try:
            # Create mock accepted result
            if response_type == str:
                data = "confirmed"
            elif hasattr(response_type, '__dataclass_fields__'):
                # For dataclasses, create with defaults
                fields = response_type.__dataclass_fields__
                kwargs = {}
                for field_name, field_info in fields.items():
                    if field_name == 'confirm':
                        kwargs[field_name] = True
                    elif hasattr(field_info, 'default'):
                        kwargs[field_name] = field_info.default
                    elif hasattr(field_info, 'default_factory'):
                        kwargs[field_name] = field_info.default_factory()
                data = response_type(**kwargs)
            else:
                data = response_type()
                
            # Mock result object
            class MockResult:
                def __init__(self, action, data):
                    self.action = action
                    self.data = data
                    
            return MockResult("accept", data)
        except Exception as e:
            logger.error(f"Error creating fallback response: {e}")
            class MockResult:
                def __init__(self, action):
                    self.action = action
                    self.data = None
            return MockResult("cancel")
    else:
        class MockResult:
            def __init__(self, action):
                self.action = action
                self.data = None
        return MockResult("decline")

async def elicit_user_search_refinement(
    ctx,
    current_query: str,
    result_count: int,
    suggested_refinements: List[str] = None
) -> Any:
    """Elicit user search refinement."""
    message = f"Search for '{current_query}' returned {result_count} results. Would you like to refine the search?"
    if suggested_refinements:
        message += f"\n\nSuggested refinements:\n" + "\n".join(f"- {ref}" for ref in suggested_refinements)
    
    return await elicit_confirmation(ctx, message, UserSearchRefinement, auto_confirm=False)

async def elicit_user_creation_confirmation(
    ctx,
    user_data: Dict[str, Any]
) -> Any:
    """Elicit user creation confirmation."""
    email = user_data.get('email', 'Unknown')
    first_name = user_data.get('firstName', '')
    last_name = user_data.get('lastName', '')
    
    message = f"Confirm creation of user:\n"
    message += f"Email: {email}\n"
    if first_name or last_name:
        message += f"Name: {first_name} {last_name}\n"
    message += f"Department: {user_data.get('department', 'Not specified')}\n"
    message += "\nProceed with user creation?"
    
    return await elicit_confirmation(ctx, message, UserCreationConfirmation, auto_confirm=True)

async def elicit_user_update_confirmation(
    ctx,
    user_id: str,
    current_data: Dict[str, Any],
    updates: Dict[str, Any]
) -> Any:
    """Elicit user update confirmation."""
    message = f"Confirm update of user: {current_data.get('email', user_id)}\n\n"
    message += "Changes to be made:\n"
    for key, value in updates.items():
        old_value = current_data.get(key, 'Not set')
        message += f"- {key}: '{old_value}' → '{value}'\n"
    message += "\nProceed with user update?"
    
    return await elicit_confirmation(ctx, message, UserUpdateConfirmation, auto_confirm=True)

async def elicit_simple_confirmation(ctx, message: str) -> bool:
    """Simple yes/no confirmation."""
    result = await elicit_confirmation(ctx, message, bool, auto_confirm=True)
    
    if result.action == "accept":
        return result.data if isinstance(result.data, bool) else True
    return False

# ==================== UTILITY FUNCTIONS ====================

def is_elicitation_available() -> bool:
    """Check if elicitation capabilities are available."""
    return ELICITATION_AVAILABLE

def get_elicitation_schemas() -> Dict[str, Type]:
    """Get available elicitation schemas."""
    return {
        "confirmation": ConfirmationData,
        "user_search_refinement": UserSearchRefinement,
        "user_creation": UserCreationConfirmation,
        "user_update": UserUpdateConfirmation,
    }

# ==================== REGISTRATION FUNCTION ====================

def register_elicitation_capabilities() -> Dict[str, Any]:
    """Register elicitation capabilities and return status."""
    try:
        logger.info(f"Registering elicitation capabilities (available: {ELICITATION_AVAILABLE})...")
        
        capabilities = {
            "available": ELICITATION_AVAILABLE,
            "fallback_mode": not ELICITATION_AVAILABLE,
            "schemas": list(get_elicitation_schemas().keys()),
            "functions": [
                "elicit_confirmation",
                "elicit_user_search_refinement", 
                "elicit_user_creation_confirmation",
                "elicit_user_update_confirmation",
                "elicit_simple_confirmation"
            ]
        }
        
        mode = "active" if ELICITATION_AVAILABLE else "fallback"
        logger.info(f"Elicitation capabilities registered in {mode} mode")
        return capabilities
        
    except Exception as e:
        logger.error(f"Failed to register elicitation capabilities: {e}")
        return {"available": False, "error": str(e)}

# Export main components
__all__ = [
    "elicit_confirmation",
    "elicit_user_search_refinement",
    "elicit_user_creation_confirmation", 
    "elicit_user_update_confirmation",
    "elicit_simple_confirmation",
    "is_elicitation_available",
    "get_elicitation_schemas",
    "register_elicitation_capabilities",
    "ConfirmationData",
    "UserSearchRefinement",
    "UserCreationConfirmation",
    "UserUpdateConfirmation"
]