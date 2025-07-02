"""
Simple OAuth proxy methods to add to the main proxy class.
Copy these methods into the OAuthFastMCPProxy class.
"""

async def oauth_authorize_proxy(self, request):
    """Proxy OAuth authorization requests, mapping virtual client IDs to real client ID"""
    try:
        # Get the client_id from query parameters
        client_id = request.query.get('client_id')
        
        if not client_id:
            return web.Response(text="Missing client_id parameter", status=400)
        
        # Check if this is a virtual client
        if client_id.startswith('virtual-'):
            # Map virtual client to real Okta client
            if client_id not in self.sessions:
                return web.Response(text=f"Unknown virtual client: {client_id}", status=400)
            
            logger.info(f"Mapping virtual client {client_id} to real Okta client")
            
            # Build new query parameters with real client ID
            new_query_params = dict(request.query)
            new_query_params['client_id'] = self.config.client_id
            
            # Build Okta authorization URL
            from urllib.parse import urlencode
            query_string = urlencode(new_query_params)
            okta_auth_url = f"https://{self.config.okta_domain}/oauth2/v1/authorize?{query_string}"
            
            logger.info(f"Redirecting to Okta: {okta_auth_url}")
            
            # Redirect to Okta with real client ID
            return web.Response(status=302, headers={'Location': okta_auth_url})
        else:
            # Not a virtual client, pass through to Okta
            query_string = str(request.query_string, 'utf-8')
            okta_auth_url = f"https://{self.config.okta_domain}/oauth2/v1/authorize?{query_string}"
            return web.Response(status=302, headers={'Location': okta_auth_url})
            
    except Exception as e:
        logger.error(f"Authorization proxy error: {e}")
        return web.Response(text=f"Authorization failed: {str(e)}", status=500)
