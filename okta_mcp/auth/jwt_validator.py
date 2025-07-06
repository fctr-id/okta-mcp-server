"""
JWT Token Validation Utility for FastMCP OAuth Server

Implements enterprise-grade JWT validation following OAuth 2.1 and MCP security best practices.
Provides cryptographic signature verification, audience validation, issuer validation, and 
comprehensive error handling.
"""

import jwt
import json
import httpx
import logging
from datetime import datetime, timezone
from typing import Dict, Any, Optional, List
from dataclasses import dataclass
from cryptography.hazmat.primitives import serialization

logger = logging.getLogger(__name__)

@dataclass
class JWTValidationResult:
    """Result of JWT token validation"""
    is_valid: bool
    user_claims: Optional[Dict[str, Any]] = None
    error: Optional[str] = None
    error_type: Optional[str] = None

class JWTValidator:
    """
    Enterprise-grade JWT validator for Okta-issued tokens.
    
    Implements all security requirements from MCP Security Best Practices:
    - Cryptographic signature verification using RS256
    - Issuer validation against configured Okta org
    - Audience validation for proper token scope
    - Expiration enforcement with strict timing
    - Fail-secure error handling
    """
    
    def __init__(self, oauth_config):
        self.config = oauth_config
        self.jwks_cache: Optional[Dict[str, Any]] = None
        self.jwks_cache_expiry: Optional[datetime] = None
        self.jwks_cache_ttl = 300  # 5 minutes TTL for JWKS cache
        
        logger.info(f"JWT validator initialized for issuer: {self.config.org_url}")
        logger.info(f"Expected audience: {self.config.audience}")
    
    async def validate_token(self, access_token: str) -> JWTValidationResult:
        """
        Validate JWT token with comprehensive security checks.
        
        Implements fail-secure validation:
        - Any validation failure results in immediate rejection
        - All security claims are verified (signature, issuer, audience, expiration)
        - Detailed error logging for security monitoring
        
        Args:
            access_token: JWT token to validate
            
        Returns:
            JWTValidationResult with validation status and user claims or error details
        """
        try:
            # Step 1: Get unverified header to find signing key
            try:
                unverified_header = jwt.get_unverified_header(access_token)
                kid = unverified_header.get('kid')
                
                if not kid:
                    logger.error("JWT token missing 'kid' claim in header")
                    return JWTValidationResult(
                        is_valid=False, 
                        error="JWT token missing key ID", 
                        error_type="invalid_token"
                    )
                    
            except Exception as e:
                logger.error(f"Failed to decode JWT header: {e}")
                return JWTValidationResult(
                    is_valid=False, 
                    error="Invalid JWT token format", 
                    error_type="invalid_token"
                )
            
            # Step 2: Get JWKS and find signing key
            try:
                signing_key = await self._get_signing_key(kid)
                if not signing_key:
                    logger.error(f"Unable to find signing key for kid: {kid}")
                    return JWTValidationResult(
                        is_valid=False, 
                        error="Unable to find signing key", 
                        error_type="invalid_token"
                    )
            except Exception as e:
                logger.error(f"Failed to retrieve signing key: {e}")
                return JWTValidationResult(
                    is_valid=False, 
                    error="Unable to retrieve signing key", 
                    error_type="invalid_token"
                )
            
            # Step 3: Validate audience claims
            valid_audiences = self._get_valid_audiences()
            logger.debug(f"Valid audiences for validation: {valid_audiences}")
            
            # Step 4: Full JWT validation with all security checks
            try:
                decoded = jwt.decode(
                    access_token,
                    signing_key,
                    algorithms=['RS256'],
                    audience=valid_audiences,
                    issuer=self.config.org_url,
                    options={
                        "verify_signature": True,   # CRITICAL: Verify signature
                        "verify_exp": True,         # CRITICAL: Check expiration  
                        "verify_aud": True,         # CRITICAL: Check audience
                        "verify_iss": True,         # CRITICAL: Check issuer
                        "require_exp": True,        # CRITICAL: Require expiration
                        "require_aud": True,        # CRITICAL: Require audience
                        "require_iss": True         # CRITICAL: Require issuer
                    }
                )
                
                logger.debug(f"JWT validation successful for user: {decoded.get('sub', 'unknown')}")
                
                # Step 5: Additional security validations
                current_time = datetime.now(timezone.utc).timestamp()
                
                # Check not-before claim if present
                nbf = decoded.get('nbf')
                if nbf and current_time < nbf:
                    logger.error("JWT token not yet valid (nbf claim)")
                    return JWTValidationResult(
                        is_valid=False, 
                        error="Token not yet valid", 
                        error_type="invalid_token"
                    )
                
                # Check issued-at claim for reasonable time bounds
                iat = decoded.get('iat')
                if iat and current_time - iat > 86400:  # More than 24 hours old
                    logger.warning(f"JWT token issued more than 24 hours ago: {current_time - iat} seconds")
                
                return JWTValidationResult(
                    is_valid=True, 
                    user_claims=decoded
                )
                
            except jwt.InvalidSignatureError:
                logger.error("JWT signature validation failed - potential token forgery attempt")
                return JWTValidationResult(
                    is_valid=False, 
                    error="Invalid token signature", 
                    error_type="invalid_token"
                )
                
            except jwt.InvalidIssuerError:
                logger.error(f"JWT issuer validation failed - expected {self.config.org_url}")
                return JWTValidationResult(
                    is_valid=False, 
                    error="Invalid token issuer", 
                    error_type="invalid_token"
                )
                
            except jwt.InvalidAudienceError:
                logger.error(f"JWT audience validation failed - expected one of {valid_audiences}")
                return JWTValidationResult(
                    is_valid=False, 
                    error="Invalid token audience", 
                    error_type="invalid_token"
                )
                
            except jwt.ExpiredSignatureError:
                logger.error("JWT token has expired")
                return JWTValidationResult(
                    is_valid=False, 
                    error="Token has expired", 
                    error_type="invalid_token"
                )
                
            except jwt.InvalidTokenError as e:
                logger.error(f"JWT token validation failed: {e}")
                return JWTValidationResult(
                    is_valid=False, 
                    error=f"Invalid token: {str(e)}", 
                    error_type="invalid_token"
                )
                
        except Exception as e:
            logger.error(f"Unexpected error during JWT validation: {e}")
            return JWTValidationResult(
                is_valid=False, 
                error="Token validation error", 
                error_type="server_error"
            )
    
    async def _get_signing_key(self, kid: str):
        """
        Get signing key from JWKS with caching for performance.
        
        Args:
            kid: Key ID from JWT header
            
        Returns:
            RSA public key for signature verification
        """
        # Check cache first
        if (self.jwks_cache and self.jwks_cache_expiry and 
            datetime.now(timezone.utc) < self.jwks_cache_expiry):
            logger.debug("Using cached JWKS")
            jwks = self.jwks_cache
        else:
            # Fetch fresh JWKS
            jwks_url = f"{self.config.org_url}/oauth2/v1/keys"
            logger.debug(f"Fetching JWKS from: {jwks_url}")
            
            try:
                async with httpx.AsyncClient(timeout=10.0) as client:
                    response = await client.get(jwks_url)
                    response.raise_for_status()
                    jwks = response.json()
                    
                    # Cache the JWKS
                    self.jwks_cache = jwks
                    self.jwks_cache_expiry = datetime.now(timezone.utc).replace(
                        second=0, microsecond=0
                    ).timestamp() + self.jwks_cache_ttl
                    
                    logger.debug(f"JWKS cached until: {self.jwks_cache_expiry}")
                    
            except httpx.TimeoutException:
                logger.error("Timeout fetching JWKS from Okta")
                raise Exception("JWKS fetch timeout")
            except httpx.HTTPError as e:
                logger.error(f"HTTP error fetching JWKS: {e}")
                raise Exception(f"JWKS fetch failed: {e}")
            except Exception as e:
                logger.error(f"Error fetching JWKS: {e}")
                raise Exception(f"JWKS fetch error: {e}")
        
        # Find the key with matching kid
        for key_data in jwks.get('keys', []):
            if key_data.get('kid') == kid:
                try:
                    # Convert JWK to RSA public key
                    signing_key = jwt.algorithms.RSAAlgorithm.from_jwk(key_data)
                    logger.debug(f"Found signing key for kid: {kid}")
                    return signing_key
                except Exception as e:
                    logger.error(f"Failed to convert JWK to RSA key: {e}")
                    raise Exception(f"Key conversion failed: {e}")
        
        logger.error(f"No signing key found for kid: {kid}")
        return None
    
    def _get_valid_audiences(self) -> List[str]:
        """
        Get list of valid audiences for token validation.
        
        Returns:
            List of valid audience values
        """
        audiences = []
        
        # Primary audience from config
        if self.config.audience:
            audiences.append(self.config.audience)
        
        # Okta org URL as fallback audience
        audiences.append(self.config.org_url)
        
        # API identifier patterns
        if self.config.audience and self.config.audience != "okta-mcp-server":
            audiences.append("okta-mcp-server")  # Legacy support
        
        return audiences
    
    def get_user_info_from_claims(self, claims: Dict[str, Any]) -> Dict[str, Any]:
        """
        Extract user information from validated JWT claims.
        
        Args:
            claims: Validated JWT claims
            
        Returns:
            Normalized user information dictionary
        """
        return {
            'user_id': claims.get('sub'),
            'email': claims.get('email') or claims.get('preferred_username'),
            'name': claims.get('name') or claims.get('given_name', '') + ' ' + claims.get('family_name', '').strip(),
            'groups': claims.get('groups', []),
            'scopes': claims.get('scp', []),  # Okta uses 'scp' for scopes
            'issued_at': claims.get('iat'),
            'expires_at': claims.get('exp'),
            'audience': claims.get('aud'),
            'issuer': claims.get('iss')
        }
