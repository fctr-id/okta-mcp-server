"""
Unified Session Store for OAuth tokens and RBAC roles.
Stores access tokens + mapped roles, fetches groups from /userinfo endpoint.
"""
import time
import os
from typing import Dict, Any, Optional
from .role_mapper import OktaGroupRoleMapper
from ..utils.logging import get_logger

logger = get_logger(__name__)

class UnifiedSessionStore:
    def __init__(self, role_mapper: OktaGroupRoleMapper):
        self.sessions = {}  # In-memory MVP, Redis for production
        self.role_mapper = role_mapper
        self.session_store_type = os.getenv('SESSION_STORE_TYPE', 'memory').lower()
        
        if self.session_store_type == 'redis':
            logger.warning("Redis session store not yet implemented, using in-memory store")
            # TODO: Initialize Redis client when implementing production store
        
        logger.debug(f"Initialized session store (type: {self.session_store_type})")
        
    async def store_user_session(self, device_id: str, access_token: str, user_info: Dict[str, Any], ttl: int = 3600):
        """Store session with access token and mapped role"""
        # Get groups from user_info (fetched from /userinfo endpoint)
        user_groups = user_info.get('groups', [])
        logger.debug(f"User {user_info.get('sub')} has groups: {user_groups}")
        
        # Map groups to single role (highest role wins)
        user_role = self.role_mapper.get_user_role(user_groups)
        
        session_data = {
            'access_token': access_token,
            'role': user_role,                   # Single role or None
            'user_id': user_info.get('sub'),
            'email': user_info.get('email'),
            'name': user_info.get('name'),
            'groups': user_groups,               # Store for debugging/audit
            'expires_at': time.time() + ttl,
            'device_id': device_id,
            'created_at': time.time()
        }
        
        session_key = f"session:{device_id}"
        self.sessions[session_key] = session_data
        
        logger.debug(f"Stored session for user {user_info.get('sub')} with role '{user_role}' (expires in {ttl}s)")
        return session_data
        
    async def get_user_session(self, device_id: str) -> Optional[Dict[str, Any]]:
        """Get user session if not expired"""
        session_key = f"session:{device_id}"
        session = self.sessions.get(session_key)
        
        if not session:
            logger.debug(f"No session found for device {device_id}")
            return None
            
        if time.time() > session.get('expires_at', 0):
            logger.info(f"Session expired for device {device_id}")
            # Clean up expired session
            del self.sessions[session_key]
            return None
            
        logger.debug(f"Retrieved valid session for device {device_id}")
        return session
        
    async def update_access_token(self, device_id: str, new_access_token: str, user_info: Dict[str, Any], ttl: int = 3600):
        """Update access token and role on token refresh - REPLACES cached token"""
        session = await self.get_user_session(device_id)
        if not session:
            logger.warning(f"No session found to update for device {device_id}")
            return None
            
        # Re-fetch groups from fresh user_info and re-map to role
        user_groups = user_info.get('groups', [])
        user_role = self.role_mapper.get_user_role(user_groups)
        
        # REPLACE the cached access token and role completely
        session['access_token'] = new_access_token
        session['role'] = user_role  # May be None if no groups/mapping
        session['expires_at'] = time.time() + ttl
        session['user_id'] = user_info.get('sub')  # Update user info too
        session['email'] = user_info.get('email')
        session['name'] = user_info.get('name')
        session['groups'] = user_groups
        session['updated_at'] = time.time()
        
        session_key = f"session:{device_id}"
        self.sessions[session_key] = session
        
        logger.debug(f"Updated session for device {device_id}: new token + role '{user_role}'")
        return session
        
    async def get_user_by_access_token(self, access_token: str) -> Optional[Dict[str, Any]]:
        """Find user session by access token"""
        for session in self.sessions.values():
            if session.get('access_token') == access_token:
                # Check if session is still valid
                if time.time() <= session.get('expires_at', 0):
                    return session
                    
        logger.debug(f"No valid session found for access token")
        return None
        
    async def invalidate_session(self, device_id: str):
        """Remove session from store"""
        session_key = f"session:{device_id}"
        if session_key in self.sessions:
            del self.sessions[session_key]
            logger.info(f"Invalidated session for device {device_id}")
        else:
            logger.debug(f"No session to invalidate for device {device_id}")
            
    async def cleanup_expired_sessions(self):
        """Remove expired sessions (should be called periodically)"""
        current_time = time.time()
        expired_keys = []
        
        for key, session in self.sessions.items():
            if current_time > session.get('expires_at', 0):
                expired_keys.append(key)
                
        for key in expired_keys:
            del self.sessions[key]
            
        if expired_keys:
            logger.info(f"Cleaned up {len(expired_keys)} expired sessions")
            
    def get_session_stats(self) -> Dict[str, Any]:
        """Get session store statistics"""
        current_time = time.time()
        total_sessions = len(self.sessions)
        expired_sessions = sum(1 for s in self.sessions.values() if current_time > s.get('expires_at', 0))
        
        return {
            'total_sessions': total_sessions,
            'active_sessions': total_sessions - expired_sessions,
            'expired_sessions': expired_sessions,
            'store_type': self.session_store_type
        }
        
    # TODO: Redis migration methods
    # async def _redis_get(self, key: str) -> Optional[Dict[str, Any]]:
    # async def _redis_set(self, key: str, value: Dict[str, Any], ttl: int):
    # async def _redis_delete(self, key: str):
