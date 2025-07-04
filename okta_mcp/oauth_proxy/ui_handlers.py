"""
UI Handlers for OAuth Proxy Server

This module contains all user interface related handlers and templates,
separated from the core authentication logi         
"""

import logging
from aiohttp import web
from typing import Dict, Any
from urllib.parse import urlparse
from datetime import datetime, timezone

logger = logging.getLogger(__name__)


class UIHandlers:
    """Handles all UI-related routes and templates for the OAuth proxy"""
    
    def __init__(self, auth_handler):
        """Initialize UI handlers with reference to auth handler"""
        self.auth_handler = auth_handler
    
    def _get_client_display_info(self, redirect_uri: str, user_agent: str, virtual_client: dict = None) -> dict:
        """Extract client display information from request context"""
        client_info = {
            'name': 'MCP Client Application',
            'icon': '🔗',
            'platform': 'Unknown Platform',
            'purpose': 'MCP Server Integration'
        }
        
        # Use virtual client name if available, otherwise keep generic
        if virtual_client and virtual_client.get('client_name'):
            client_info['name'] = virtual_client['client_name']
        
        return client_info
    
    def _get_consent_template(self, client_display_info: dict, virtual_client_id: str, 
                            redirect_uri: str, state: str, server_scopes: list,
                            identity_scope_list: str, okta_scope_list: str, user_agent: str = '', 
                            okta_domain: str = '') -> str:
        """Generate the modern, business-appropriate consent page HTML template"""
        
        # Extract client domain from redirect URI
        client_domain = self._get_redirect_domain(redirect_uri) if redirect_uri else "Unknown Domain"
        
        # Get client type for display (optional, only show if meaningful)
        client_type_display = ""
        if user_agent:
            client_type = self._identify_client_type(user_agent)
            if client_type and not client_type.startswith("Unknown"):
                client_type_display = client_type
        
        return f"""
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Authorization Request</title>
            <link rel="preconnect" href="https://fonts.googleapis.com">
            <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
            <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&display=swap" rel="stylesheet">
            <style>
                * {{ margin: 0; padding: 0; box-sizing: border-box; }}
                
                body {{ 
                    font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
                    background: linear-gradient(180deg, #e5eaf5, #f0f4fb);
                    min-height: 100vh;
                    position: relative;
                    overflow-y: auto;
                    display: flex;
                    flex-direction: column;
                    align-items: center;
                    justify-content: center;
                    padding: 20px;
                    font-feature-settings: 'cv02', 'cv03', 'cv04', 'cv11';
                    font-optical-sizing: auto;
                    text-rendering: optimizeLegibility;
                    -webkit-font-smoothing: antialiased;
                    -moz-osx-font-smoothing: grayscale;
                }}
                
                .consent-card {{
                    background: white;
                    border-radius: 20px;
                    box-shadow: 0 20px 60px rgba(0,0,0,0.08), 0 8px 30px rgba(0,0,0,0.06);
                    max-width: 520px;
                    width: 100%;
                    overflow: hidden;
                    border: 1px solid rgba(255,255,255,0.8);
                    backdrop-filter: blur(10px);
                    position: relative;
                }}
                
                .consent-card::before {{
                    content: '';
                    position: absolute;
                    top: 0;
                    left: 0;
                    right: 0;
                    height: 1px;
                    background: linear-gradient(90deg, transparent, rgba(255,255,255,0.6), transparent);
                    pointer-events: none;
                }}
                
                .header {{
                    background: white;
                    padding: 40px 32px 40px;
                    text-align: center;
                    border-bottom: 1px solid #f0f0f0;
                }}
                
                .logo-container {{
                    width: 60px;
                    height: 60px;
                    border-radius: 50%;
                    margin: 0 auto 20px;
                    position: relative;
                    background: white;
                    padding: 8px;
                    box-shadow: 0 4px 16px rgba(0, 0, 0, 0.1);
                    border: 2px solid #e5eaf5;
                    display: flex;
                    align-items: center;
                    justify-content: center;
                }}
                
                .logo-container img {{
                    width: 80%;
                    height: 80%;
                    object-fit: contain;
                    border-radius: 50%;
                }}
                
                .header h1 {{
                    color: #1a1a1a;
                    font-size: 20px;
                    font-weight: 600;
                    margin-bottom: 8px;
                    text-align: center;
                }}
                
                .header p {{
                    color: #666;
                    font-size: 14px;
                    text-align: center;
                }}
                
                .header .tenant-info {{
                    color: #666;
                    font-size: 12px;
                    font-weight: 500;
                    margin-top: 12px;
                    text-align: center;
                }}
                
                .content {{
                    padding: 40px 32px 40px;
                }}
                
                .client-info {{
                    background: #f8f9fa;
                    border-radius: 8px;
                    padding: 16px;
                    margin-bottom: 24px;
                }}
                
                .client-row {{
                    display: flex;
                    justify-content: space-between;
                    align-items: center;
                    margin-bottom: 8px;
                }}
                
                .client-row:last-child {{
                    margin-bottom: 0;
                }}
                
                .client-label {{
                    color: #666;
                    font-size: 13px;
                    font-weight: 500;
                }}
                
                .client-value {{
                    color: #1a1a1a;
                    font-size: 13px;
                    font-weight: 600;
                    text-align: right;
                    max-width: 60%;
                    word-break: break-word;
                }}
                
                .permissions-summary {{
                    margin-bottom: 24px;
                }}
                
                .permissions-summary h3 {{
                    color: #1a1a1a;
                    font-size: 16px;
                    font-weight: 600;
                    margin-bottom: 12px;
                }}
                
                .permission-item {{
                    display: flex;
                    align-items: center;
                    gap: 8px;
                    padding: 8px 0;
                    border-bottom: 1px solid #f0f0f0;
                }}
                
                .permission-item:last-child {{
                    border-bottom: none;
                }}
                
                .permission-icon {{
                    color: #0066cc;
                    font-size: 14px;
                    width: 16px;
                }}
                
                .permission-text {{
                    color: #333;
                    font-size: 14px;
                }}
                
                .notice {{
                    background: #f8fafc;
                    border: 1px solid #cbd5e1;
                    border-radius: 6px;
                    padding: 16px;
                    margin-bottom: 24px;
                    font-size: 14px;
                    line-height: 1.5;
                    color: #334155;
                    text-align: left;
                }}
                
                .notice p {{
                    margin-bottom: 12px;
                }}
                
                .notice p:last-child {{
                    margin-bottom: 0;
                }}
                
                .notice strong {{
                    color: #1e293b;
                    font-weight: 600;
                }}
                
                .actions {{
                    display: flex;
                    gap: 12px;
                    margin-top: 8px;
                }}
                
                .action-form {{
                    flex: 1;
                    margin: 0;
                }}
                
                .btn {{
                    flex: 1;
                    padding: 16px 28px;
                    border: none;
                    border-radius: 12px;
                    font-size: 15px;
                    font-weight: 600;
                    font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
                    cursor: pointer;
                    transition: all 0.2s cubic-bezier(0.4, 0, 0.2, 1);
                    letter-spacing: -0.01em;
                    position: relative;
                    outline: none;
                    text-decoration: none;
                    user-select: none;
                    min-height: 48px;
                    display: flex;
                    align-items: center;
                    justify-content: center;
                    width: 100%;
                }}
                
                .btn:focus {{
                    box-shadow: 0 0 0 3px rgba(59, 130, 246, 0.15);
                }}
                
                .btn:hover {{
                    transform: translateY(-1px);
                }}
                
                .btn:active {{
                    transform: translateY(0);
                    transition: transform 0.1s;
                }}
                
                .btn-primary {{
                    background: linear-gradient(135deg, #8b9dc3 0%, #6b7a99 100%);
                    color: white;
                    border: 1px solid #6b7a99;
                }}
                
                .btn-primary:hover {{
                    background: linear-gradient(135deg, #6b7a99 0%, #5a6580 100%);
                    border-color: #5a6580;
                }}
                
                .btn-primary:active {{
                    background: linear-gradient(135deg, #5a6580 0%, #4a5366 100%);
                }}
                
                .btn-secondary {{
                    background: #f8f9fa;
                    color: #495057;
                    border: 2px solid #dee2e6;
                    box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
                }}
                
                .btn-secondary:hover {{
                    background: #e9ecef;
                    border-color: #adb5bd;
                    color: #343a40;
                    box-shadow: 0 4px 8px rgba(0, 0, 0, 0.15);
                }}
                
                .btn-secondary:active {{
                    background: #dee2e6;
                    border-color: #6c757d;
                }}
                
                @media (max-width: 480px) {{
                    .consent-card {{
                        margin: 0 10px;
                    }}
                    
                    .header, .content {{
                        padding: 24px 20px;
                    }}
                }}
            </style>
        </head>
        <body>
            <div class="consent-card">
                <div class="header">
                    <div class="logo-container">
                        <img src="/images/fctr-logo.png" alt="Fctr Identity Logo" onerror="this.style.display='none'; this.nextElementSibling.style.display='flex';">
                        <div style="display: none; width: 100%; height: 100%; align-items: center; justify-content: center; background: linear-gradient(135deg, #0066cc 0%, #004499 100%); color: white; font-weight: 700; font-size: 20px; border-radius: 50%;">F</div>
                    </div>
                    <h1>AI Agent Authorization</h1>
                    <div class="tenant-info">Connecting to Okta Tenant: {okta_domain}</div>
                </div>
                
                <div class="content">
                    <div class="client-info">
                        <div class="client-row">
                            <span class="client-label">Application:</span>
                            <span class="client-value">{client_display_info['name']}</span>
                        </div>
                        <div class="client-row">
                            <span class="client-label">Domain:</span>
                            <span class="client-value">{client_domain}</span>
                        </div>
                        <div class="client-row">
                            <span class="client-label">Platform:</span>
                            <span class="client-value">{client_display_info['platform']}</span>
                        </div>
                        {f'''
                        <div class="client-row">
                            <span class="client-label">Client Type:</span>
                            <span class="client-value">{client_type_display}</span>
                        </div>
                        ''' if client_type_display else ''}
                    </div>
                    
                    <div class="permissions-summary">
                        <h3>Requested Access</h3>
                        <div class="permission-item">
                            <span class="permission-icon">🏢</span>
                            <span class="permission-text">Interact with your Okta tenant</span>
                        </div>
                        <div class="permission-item">
                            <span class="permission-icon">👤</span>
                            <span class="permission-text">Access your profile information</span>
                        </div>
                        <div class="permission-item">
                            <span class="permission-icon">🛠️</span>
                            <span class="permission-text">Use MCP tools filtered for your access level</span>
                        </div>
                    </div>
                    
                    <div class="notice">
                        <p><strong>You have an AI client requesting access to the MCP Server for Okta by Fctr Identity.</strong></p>
                        <p><strong>Important:</strong> If you are not actively trying to connect an AI client or authorize access, please reject this request.</p>
                    </div>
                    
                    <div class="actions">
                        <form method="post" action="/oauth/consent" class="action-form">
                            <input type="hidden" name="client_id" value="{virtual_client_id}">
                            <input type="hidden" name="redirect_uri" value="{redirect_uri or ''}">
                            <input type="hidden" name="state" value="{state or ''}">
                            <input type="hidden" name="scope" value="{' '.join(server_scopes)}">
                            <input type="hidden" name="action" value="allow">
                            <button type="submit" class="btn btn-primary">Authorize</button>
                        </form>
                        
                        <form method="post" action="/oauth/consent" class="action-form">
                            <input type="hidden" name="client_id" value="{virtual_client_id}">
                            <input type="hidden" name="redirect_uri" value="{redirect_uri or ''}">
                            <input type="hidden" name="state" value="{state or ''}">
                            <input type="hidden" name="action" value="deny">
                            <button type="submit" class="btn btn-secondary">Cancel</button>
                        </form>
                    </div>
                </div>
            </div>
        </body>
        </html>
        """
    
    def _identify_client_type(self, user_agent: str) -> str:
        """Identify client type from user agent for logging"""
        if not user_agent:
            return "Unknown Client"
        
        # Simple generic detection for logging purposes only
        if 'curl' in user_agent.lower():
            return "Command Line Tool"
        elif any(browser in user_agent.lower() for browser in ['chrome', 'firefox', 'safari', 'edge']):
            return "Web Browser"
        elif 'python' in user_agent.lower():
            return "Python Client"
        else:
            return "Application Client"
    
    def _get_redirect_domain(self, redirect_uri: str) -> str:
        """Extract domain from redirect URI for logging"""
        if not redirect_uri:
            return "Unknown"
        try:
            parsed = urlparse(redirect_uri)
            if parsed.hostname:
                if 'localhost' in parsed.hostname or '127.0.0.1' in parsed.hostname:
                    return f"localhost:{parsed.port or 80}"
                else:
                    return parsed.hostname
            return "Invalid URI"
        except Exception:
            return "Parse Error"

    async def consent_page(self, request: web.Request) -> web.Response:
        """Display consent page for virtual client authorization"""
        try:
            # Get parameters from query string
            virtual_client_id = request.query.get('client_id')
            redirect_uri = request.query.get('redirect_uri')
            state = request.query.get('state')
            scope = request.query.get('scope', '').split()
            user_agent = request.headers.get('User-Agent', '')
            
            # Log consent page request with enhanced details
            client_type = self._identify_client_type(user_agent)
            redirect_domain = self._get_redirect_domain(redirect_uri)
            
            logger.info(f"🔐 Consent page requested - ID: {virtual_client_id}")
            logger.info(f"📱 Client: {client_type}, Domain: {redirect_domain}")
            logger.debug(f"Consent details - State: {state[:10] if state else 'None'}, Scopes: {scope}")
            
            if not virtual_client_id or not virtual_client_id.startswith('virtual-'):
                logger.warning(f"❌ Invalid consent request - Client ID: {virtual_client_id}")
                return web.Response(text="Invalid or missing virtual client ID", status=400)
            
            # Check if virtual client is registered
            if virtual_client_id not in self.auth_handler.virtual_clients:
                logger.warning(f"❌ Unknown virtual client - ID: {virtual_client_id}")
                return web.Response(text=f"Unknown virtual client: {virtual_client_id}", status=400)
            
            virtual_client = self.auth_handler.virtual_clients[virtual_client_id]
            
            # Validate redirect URI
            if redirect_uri and redirect_uri not in virtual_client['redirect_uris']:
                logger.warning(f"❌ Invalid redirect URI - "
                              f"Provided: {redirect_uri}, "
                              f"Allowed: {virtual_client['redirect_uris']}")
                return web.Response(text="Invalid redirect URI", status=400)
            
            # Enhanced client identification based on request context
            client_display_info = self._get_client_display_info(redirect_uri, user_agent, virtual_client)
            
            logger.info(f"📱 Displaying consent for {client_display_info['name']} "
                       f"({client_display_info['platform']})")
            
            # Enhanced scope descriptions with better categorization
            scope_descriptions = {
                # Identity & Profile Scopes
                'openid': 'Verify your identity',
                'profile': 'Access your basic profile information (name, username)',
                'email': 'Access your email address',
                'address': 'Access your address information',
                'phone': 'Access your phone number',
                'groups': 'Access your group memberships',
                'offline_access': 'Maintain access when you\'re offline',
                
                # Okta API Scopes (what the server actually uses)
                'okta.users.read': 'View users in your Okta tenant',
                'okta.groups.read': 'View groups in your Okta tenant', 
                'okta.apps.read': 'View applications in your Okta tenant',
                'okta.events.read': 'View system events in your Okta tenant',
                'okta.logs.read': 'View audit logs in your Okta tenant',
                'okta.policies.read': 'View security policies in your Okta tenant',
                'okta.devices.read': 'View registered devices in your Okta tenant',
                'okta.factors.read': 'View authentication factors in your Okta tenant'
            }
            
            # Get the server's actual scopes (not just client requested)
            server_scopes = self.auth_handler.oauth_provider.default_scopes
            
            # Build scope categories for better UX
            identity_scopes = []
            okta_api_scopes = []
            
            for scope_name in server_scopes:
                description = scope_descriptions.get(scope_name, f"Access {scope_name}")
                if scope_name.startswith('okta.'):
                    okta_api_scopes.append(f"<li><span class='scope-name'>{scope_name}</span><br><small>{description}</small></li>")
                else:
                    identity_scopes.append(f"<li><span class='scope-name'>{scope_name}</span><br><small>{description}</small></li>")
            
            identity_scope_list = "".join(identity_scopes) if identity_scopes else "<li><small>No identity scopes requested</small></li>"
            okta_scope_list = "".join(okta_api_scopes) if okta_api_scopes else "<li><small>No Okta API access requested</small></li>"

            # Get Okta domain for display
            okta_domain = self.auth_handler.oauth_provider.okta_domain

            # Generate the HTML template
            html = self._get_consent_template(
                client_display_info, virtual_client_id, redirect_uri, state, 
                server_scopes, identity_scope_list, okta_scope_list, user_agent, okta_domain
            )
            
            return web.Response(text=html, content_type='text/html')
            
        except Exception as e:
            logger.error(f"Consent page error: {e}")
            return web.Response(text=f"Error displaying consent page: {str(e)}", status=500)

    async def handle_consent(self, request: web.Request) -> web.Response:
        """Handle user consent response"""
        from aiohttp_session import get_session
        from urllib.parse import urlencode
        from datetime import datetime, timezone
        
        try:
            # Get form data
            data = await request.post()
            virtual_client_id = data.get('client_id')
            redirect_uri = data.get('redirect_uri')
            state = data.get('state')
            scope = data.get('scope', '').split()
            action = data.get('action')
            
            if not virtual_client_id or not virtual_client_id.startswith('virtual-'):
                return web.Response(text="Invalid virtual client ID", status=400)
            
            if action == "deny":
                # User denied consent - redirect back with error
                if redirect_uri:
                    error_params = {
                        'error': 'access_denied',
                        'error_description': 'User denied the request',
                        'state': state
                    }
                    error_query = urlencode({k: v for k, v in error_params.items() if v})
                    redirect_url = f"{redirect_uri}?{error_query}"
                    return web.Response(status=302, headers={'Location': redirect_url})
                else:
                    return web.Response(text="Access denied by user", status=403)
            
            elif action == "allow":
                # Store pending consent (will be finalized after OAuth callback)
                session = await get_session(request)
                session['pending_consent'] = {
                    'virtual_client_id': virtual_client_id,
                    'redirect_uri': redirect_uri,
                    'state': state,
                    'scope': scope,
                    'granted_at': datetime.now(timezone.utc).isoformat()
                }
                
                # Now redirect to the authorization proxy to start OAuth flow
                auth_params = {
                    'client_id': virtual_client_id,
                    'redirect_uri': redirect_uri,
                    'state': state,
                    'scope': ' '.join(scope),
                    'response_type': 'code'
                }
                auth_query = urlencode({k: v for k, v in auth_params.items() if v})
                auth_url = f"/oauth2/v1/authorize?{auth_query}"
                
                return web.Response(status=302, headers={'Location': auth_url})
            
            else:
                return web.Response(text="Invalid action", status=400)
                
        except Exception as e:
            logger.error(f"Consent handling error: {e}")
            return web.Response(text=f"Error processing consent: {str(e)}", status=500)

    async def permissions_info(self, request: web.Request) -> web.Response:
        """Display information about permissions requested"""
        scopes = self.auth_handler.oauth_provider.default_scopes
        
        scope_descriptions = {
            'openid': 'Verify your identity',
            'profile': 'Access your basic profile information (name, etc.)',
            'email': 'Access your email address',
            'okta.users.read': 'Read user information from your Okta organization',
            'okta.groups.read': 'Read group information from your Okta organization', 
            'okta.apps.read': 'Read application information from your Okta organization',
            'okta.events.read': 'Read event information from your Okta organization',
            'okta.logs.read': 'Read log information from your Okta organization',
            'okta.policies.read': 'Read policy information from your Okta organization',
            'okta.devices.read': 'Read device information from your Okta organization',
            'okta.factors.read': 'Read authentication factor information from your Okta organization'
        }
        
        scope_list = ""
        for scope in scopes:
            description = scope_descriptions.get(scope, f"Access {scope}")
            scope_list += f"<li><strong>{scope}</strong>: {description}</li>"
        
        html = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>OAuth Permissions - Okta MCP Server</title>
            <style>
                body {{ font-family: Arial, sans-serif; max-width: 800px; margin: 50px auto; padding: 20px; }}
                .header {{ text-align: center; margin-bottom: 30px; }}
                .permissions {{ background: #f5f5f5; padding: 20px; border-radius: 8px; margin: 20px 0; }}
                .note {{ background: #e7f3ff; padding: 15px; border-left: 4px solid #2196F3; margin: 20px 0; }}
                .actions {{ text-align: center; margin: 30px 0; }}
                .btn {{ padding: 12px 24px; margin: 0 10px; border: none; border-radius: 4px; cursor: pointer; text-decoration: none; display: inline-block; }}
                .btn-primary {{ background: #007bff; color: white; }}
                .btn-secondary {{ background: #6c757d; color: white; }}
                ul {{ line-height: 1.6; }}
            </style>
        </head>
        <body>
            <div class="header">
                <h1>🔐 OAuth Permissions</h1>
                <p>The Okta MCP Server is requesting the following permissions:</p>
            </div>
            
            <div class="permissions">
                <h3>Requested Permissions:</h3>
                <ul>
                    {scope_list}
                </ul>
            </div>
            
            <div class="note">
                <strong>Note:</strong> This application uses Okta's organization authorization server to access API resources. 
                You will be prompted to explicitly grant consent for each virtual client that requests access to your Okta data.
            </div>
            
            <div class="actions">
                <a href="/oauth/login" class="btn btn-primary">Continue to Login</a>
                <a href="/" class="btn btn-secondary">Cancel</a>
            </div>
            
            <div style="margin-top: 40px; padding-top: 20px; border-top: 1px solid #ddd; text-align: center; color: #666;">
                <small>For more information about OAuth security, see our <a href="/docs">documentation</a>.</small>
            </div>
        </body>
        </html>
        """
        
        return web.Response(text=html, content_type="text/html")
