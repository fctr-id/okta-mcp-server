"""Utility functions for working with Pydantic-AI models."""

import os
import json
from enum import Enum
from dotenv import load_dotenv
from typing import Any, Dict
from pydantic_ai.models.openai import OpenAIModel
from pydantic_ai.models.gemini import GeminiModel
from pydantic_ai.providers.openai import OpenAIProvider
from pydantic_ai.providers.google_vertex import GoogleVertexProvider
from openai import AsyncAzureOpenAI
from pydantic_ai.models.anthropic import AnthropicModel
from pydantic_ai.providers.anthropic import AnthropicProvider
import httpx

load_dotenv()

def parse_headers() -> Dict[str, str]:
    """Parse the CUSTOM_HTTP_HEADERS environment variable into a dictionary."""
    headers_str = os.getenv('CUSTOM_HTTP_HEADERS')
    if not headers_str:
        return {}
        
    try:
        # Parse the JSON string into a Python dictionary
        return json.loads(headers_str)
    except json.JSONDecodeError as e:
        print(f"Error parsing CUSTOM_HTTP_HEADERS: {e}")
        return {}

class AIProvider(str, Enum):
    VERTEX_AI = "vertex_ai"
    OPENAI = "openai"
    AZURE_OPENAI = "azure_openai"
    OPENAI_COMPATIBLE = "openai_compatible"
    ANTHROPIC = "anthropic"

def get_model() -> Any:
    """Initialize and return the appropriate LLM model based on environment settings."""
    provider = os.getenv('AI_PROVIDER', 'openai').lower()
    
    if provider == AIProvider.VERTEX_AI:
        service_account = os.getenv('GOOGLE_APPLICATION_CREDENTIALS') or os.getenv('VERTEX_AI_SERVICE_ACCOUNT_FILE')
        project_id = os.getenv('VERTEX_AI_PROJECT')
        region = os.getenv('VERTEX_AI_LOCATION', 'us-central1')
        model_name = os.getenv('VERTEX_AI_REASONING_MODEL', 'gemini-1.5-pro')
        
        vertex_provider = GoogleVertexProvider(
            service_account_file=service_account,
            project_id=project_id,
            region=region
        )
        
        return GeminiModel(model_name, provider=vertex_provider)
    
    elif provider == AIProvider.OPENAI_COMPATIBLE:
        custom_headers = parse_headers()
        client = httpx.AsyncClient(verify=False, headers=custom_headers)
        
        # Create OpenAI compatible provider with http_client directly in constructor
        openai_compat_provider = OpenAIProvider(
            base_url=os.getenv('OPENAI_COMPATIBLE_BASE_URL'),
            api_key=os.getenv('OPENAI_COMPATIBLE_TOKEN'),
            http_client=client
        )
        
        reasoning_model_name = os.getenv('OPENAI_COMPATIBLE_REASONING_MODEL')
        
        return OpenAIModel(
            model_name=reasoning_model_name,
            provider=openai_compat_provider,
        )
        
    elif provider == AIProvider.AZURE_OPENAI:
        # Create Azure OpenAI client
        azure_client = AsyncAzureOpenAI(
            azure_endpoint=os.getenv('AZURE_OPENAI_ENDPOINT'),
            api_version=os.getenv('AZURE_OPENAI_VERSION', '2024-07-01-preview'),
            api_key=os.getenv('AZURE_OPENAI_KEY')
        )
        
        # Create OpenAI provider with the Azure client
        azure_provider = OpenAIProvider(openai_client=azure_client)
        
        return OpenAIModel(
            model_name=os.getenv('AZURE_OPENAI_REASONING_DEPLOYMENT', 'gpt-4'),
            provider=azure_provider
        )
   
    elif provider == AIProvider.OPENAI:
        # Create OpenAI provider with the OpenAI client
        api_key = os.getenv('OPENAI_API_KEY')
        model_name = os.getenv('OPENAI_REASONING_MODEL', 'gpt-4')
            
        openai_provider = OpenAIProvider(api_key=api_key)
        return OpenAIModel(model_name=model_name, provider=openai_provider)

    elif provider == AIProvider.ANTHROPIC:
        # Get API key from environment
        api_key = os.getenv('ANTHROPIC_API_KEY')
        if not api_key:
            raise ValueError("ANTHROPIC_API_KEY environment variable is required for Anthropic provider")
        
        # Get model name with default
        model_name = os.getenv('ANTHROPIC_MODEL_NAME', 'claude-3-5-sonnet-latest')
        
        # Create and return the model
        return AnthropicModel(
            model_name=model_name
        )    
    
    else:
        # Default to OpenAI if provider not recognized
        api_key = os.getenv('OPENAI_API_KEY')
        model_name = os.getenv('OPENAI_REASONING_MODEL', 'gpt-4')
        
        openai_provider = OpenAIProvider(api_key=api_key)
        return OpenAIModel(model_name=model_name, provider=openai_provider)