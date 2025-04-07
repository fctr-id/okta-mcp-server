"""
STDIO MCP Client for Okta MCP Server
Connects directly to an Okta MCP server via STDIO transport.
"""

import os
import sys
import json
import asyncio
import logging
import datetime
import inspect
from enum import Enum
from logging.handlers import RotatingFileHandler
from typing import Dict, Any, List, Optional
from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt
from rich.syntax import Syntax
from dotenv import load_dotenv
from pydantic_ai import Agent
from pydantic_ai.models.gemini import GeminiModel
from pydantic_ai.models.openai import OpenAIModel
from pydantic_ai.providers.google_vertex import GoogleVertexProvider
from pydantic_ai.providers.openai import OpenAIProvider
from pydantic_ai.mcp import MCPServerStdio
from openai import AsyncAzureOpenAI

# Add the parent directory to sys.path to enable imports
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from okta_mcp.utils.logging import configure_logging
main_logger = configure_logging()

# Load environment variables
load_dotenv()

# Configure console
console = Console()

# Custom formatter with ISO8601 timestamps and Z suffix

system_prompt="""
You are a an expert in Okta identity management suite. You understand the the OKTA APIs and how identities work in an enterprise environment.
Since this is a technical AI agent , your responses should be output in JSON format. no other words or characters should be present in the output.
Do NOT summarize or explain the output. Just give the JSON output.
When passing groups or users to the API, you have to just use the name provided in the query . Do not append any other words or charactares to the name.
Every entity in OKTA has a unique ID. You have to get the ID first using the list_ or get_ tools 

        ### Core Concepts ###
    
    1. User Access:
        - Users can access applications through direct assignment or group membership
        - DO NOT show application assignments when asked about users unless specifically asked about it
        - Users are identified by email or login
        - User status can be: STAGED, PROVISIONED (also known as pending user action), ACTIVE, PASSWORD_RESET, PASSWORD_EXPIRED, LOCKED_OUT, SUSPENDED , DEPROVISIONED
        - ALways list users and groups of all statuses unless specifically asked for a particular status
    
    2. Applications:
        - Applications have a technical name and a user-friendly label
        - Applications can be active or inactive
        - Always prefer ACTIVE applications only unless specified
        - Applications can be assigned to users directly or to groups
    
    3. Groups:
        - Groups can be assigned to applications
        - Users can be members of multiple groups
    
    4. Authentication:
        - Users can have multiple authentication factors
        - Factors include: email, SMS, push, security questions, etc.
        - Factors can be active or inactive

        ##Key Columns to use in the queries##
        - Always use the following columns when answering queries unless more ore less are asked
        - For user related query Users: email, login, first_name, last_name, status
        - groups: name, description
        - applications: label, name, status
        - factors: factor_type, provider, status
        
"""
class ISO8601Formatter(logging.Formatter):
    def formatTime(self, record, datefmt=None):
        # Create ISO8601 format with milliseconds and Z suffix
        dt = datetime.datetime.fromtimestamp(record.created)
        return dt.strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3] + 'Z'

# Set up protocol logging
def setup_protocol_logging():
    """Set up protocol-level logging to capture all MCP messages."""
    # Use src/logs as the directory (create if it doesn't exist)
    log_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '../logs'))
    os.makedirs(log_dir, exist_ok=True)
    log_file = os.path.join(log_dir, "mcp_protocol.log")
    
    # Create ISO8601 formatter
    formatter = ISO8601Formatter('%(asctime)s [%(levelname)s] [%(name)s] %(message)s')
    
    # Create file handler with rotation
    file_handler = RotatingFileHandler(
        log_file, 
        maxBytes=10*1024*1024,  # 10MB
        backupCount=5
    )
    file_handler.setFormatter(formatter)
    file_handler.setLevel(logging.INFO)
    
    # Create console handler for warnings and errors
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(formatter)
    console_handler.setLevel(logging.WARNING)
    
    # Set up the main protocol logger
    protocol_logger = logging.getLogger("okta-mcp-server")
    protocol_logger.setLevel(logging.INFO)
    
    # Remove existing handlers to avoid duplicates
    for handler in protocol_logger.handlers[:]:
        protocol_logger.removeHandler(handler)
    
    # Add the handlers
    protocol_logger.addHandler(file_handler)
    protocol_logger.addHandler(console_handler)
    
    # Disable propagation to avoid duplicate logs
    protocol_logger.propagate = False
    
    # Also set up a filesystem logger for the same file
    fs_logger = logging.getLogger("filesystem")
    fs_logger.setLevel(logging.INFO)
    
    for handler in fs_logger.handlers[:]:
        fs_logger.removeHandler(handler)
    
    # Share the same handler for consistent formatting
    fs_logger.addHandler(file_handler)
    fs_logger.propagate = False
    
    console.print(f"[green]Protocol logs will be saved to:[/] {log_file}")
    return protocol_logger, fs_logger

# Setup loggers
protocol_logger, fs_logger = setup_protocol_logging()
client_logger = logging.getLogger("mcp_stdio_client")

# Determine if we're in debug mode
DEBUG_MODE = os.getenv('DEBUG', 'false').lower() == 'true'

def load_env_vars():
    """Load all environment variables from .env file and current environment."""
    # Start with current environment variables
    all_vars = dict(os.environ)
    
    # Also explicitly read from .env file to ensure we get everything
    env_path = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '.env'))
    if os.path.exists(env_path):
        with open(env_path, 'r') as f:
            for line in f:
                line = line.strip()
                # Skip comments and empty lines
                if line and not line.startswith('#') and '=' in line:
                    key, value = line.split('=', 1)
                    all_vars[key.strip()] = value.strip()
    
    protocol_logger.info(f"Loaded {len(all_vars)} environment variables")
    return all_vars


# Server configuration
PYTHON_PATH = "../venv/Scripts/python"
SERVER_SCRIPT = "../main.py"


ENV_VARS = load_env_vars()

def format_json_with_newlines(obj: Any) -> str:
    """Format JSON with proper newlines and indentation."""
    if obj is None:
        return "null"
    
    try:
        json_str = json.dumps(obj, indent=2, default=str)
        json_str = json_str.replace('\\n', '\n')
        return json_str
    except Exception as e:
        client_logger.debug(f"Error formatting JSON: {e}")
        return str(obj)

# Enhanced MCPServerStdio with logging capabilities
class LoggingMCPServerStdio(MCPServerStdio):
    """Enhanced MCPServerStdio with logging capabilities."""
    
    def __init__(self, *args, **kwargs):
        protocol_logger.info("Creating LoggingMCPServerStdio instance")
        fs_logger.info("Creating LoggingMCPServerStdio instance")
        
        # Wrap the process to capture STDIO
        self._original_process = None
        super().__init__(*args, **kwargs)
        
        # Set up instance-specific logging
        self._setup_logging()
    
    def _setup_logging(self):
        """Set up logging hooks for this instance."""
        # Let's inspect what methods we have access to
        methods = [m for m in dir(self) if not m.startswith('_') and callable(getattr(self, m))]
        protocol_logger.info(f"Available public methods: {methods}")
        
        # Try to identify message handling methods
        if hasattr(self, 'send') and callable(getattr(self, 'send')):
            self._wrap_method('send')
        if hasattr(self, 'receive') and callable(getattr(self, 'receive')):
            self._wrap_method('receive')
        if hasattr(self, 'list_tools'):
            self._wrap_method('list_tools') 
    
    def _wrap_method(self, method_name):
        """Wrap a method to add logging before and after."""
        original_method = getattr(self, method_name)
        
        if asyncio.iscoroutinefunction(original_method):
            async def wrapped_method(*args, **kwargs):
                protocol_logger.info(f"Calling {method_name} with args: {args}, kwargs: {kwargs}")
                fs_logger.info(f"Calling {method_name}")
                try:
                    result = await original_method(*args, **kwargs)
                    protocol_logger.info(f"{method_name} returned: {json.dumps(result, default=str) if result else 'None'}")
                    fs_logger.info(f"{method_name} completed")
                    return result
                except Exception as e:
                    protocol_logger.error(f"Error in {method_name}: {e}")
                    fs_logger.error(f"Error in {method_name}: {e}")
                    raise
        else:
            def wrapped_method(*args, **kwargs):
                protocol_logger.info(f"Calling {method_name} with args: {args}, kwargs: {kwargs}")
                fs_logger.info(f"Calling {method_name}")
                try:
                    result = original_method(*args, **kwargs)
                    protocol_logger.info(f"{method_name} returned: {json.dumps(result, default=str) if result else 'None'}")
                    fs_logger.info(f"{method_name} completed")
                    return result
                except Exception as e:
                    protocol_logger.error(f"Error in {method_name}: {e}")
                    fs_logger.error(f"Error in {method_name}: {e}")
                    raise
                
        setattr(self, method_name, wrapped_method)
        protocol_logger.info(f"Successfully wrapped method: {method_name}")
        fs_logger.info(f"Successfully wrapped method: {method_name}")

class MessageHandler:
    """Hook to capture messages directly from the network layer."""
    
    @staticmethod
    async def capture_jsonrpc(func):
        """Decorator to capture JSONRPC messages."""
        async def wrapper(*args, **kwargs):
            # Try to extract the message
            message = None
            if args and len(args) > 0:
                message = args[0]
            
            if message and isinstance(message, dict):
                msg_str = json.dumps(message, default=str)
                protocol_logger.info(f"JSONRPC message: {msg_str}")
                fs_logger.info(f"JSONRPC message: {msg_str}")
            
            return await func(*args, **kwargs)
        return wrapper
# Update the AIProvider enum to match the SSE client
class AIProvider(str, Enum):
    VERTEX_AI = "vertex_ai"
    OPENAI = "openai"
    AZURE_OPENAI = "azure_openai"
    OPENAI_COMPATIBLE = "openai_compatible"
    
class OktaMCPStdioClient:
    """Client that connects to Okta MCP server using STDIO transport."""
    
    def __init__(self):
        self.model = self._initialize_model()
        self.agent = None
        self.mcp_server = None
    
    def _initialize_model(self):
        """Initialize the LLM model based on environment variables."""
        provider = os.getenv('AI_PROVIDER', 'openai').lower()
        console.print(f"[bold]Using AI provider: {provider}[/]")
        
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
            openai_compat_provider = OpenAIProvider(
                base_url=os.getenv('OPENAI_COMPATIBLE_BASE_URL'),
                api_key=os.getenv('OPENAI_COMPATIBLE_TOKEN')
            )
            
            reasoning_model_name = os.getenv('OPENAI_COMPATIBLE_REASONING_MODEL')
            
            return OpenAIModel(
                model_name=reasoning_model_name,
                provider=openai_compat_provider
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
    
    async def connect(self):
        """Connect to the MCP server using STDIO transport."""
        console.print("[bold]Connecting to Okta MCP server via STDIO...[/]")
        
        try:
            protocol_logger.info("Initializing server...")
            fs_logger.info("Initializing server...")
            
            # Capture MCP Server methods for introspection
            protocol_logger.info(f"MCPServerStdio methods: {[m for m in dir(MCPServerStdio) if not m.startswith('_') and callable(getattr(MCPServerStdio, m))]}")
            
            # Create the LoggingMCPServerStdio instance
            self.mcp_server = LoggingMCPServerStdio(
                PYTHON_PATH,
                [SERVER_SCRIPT],
                env=ENV_VARS
            )
            
            # Create the agent with the MCP server
            self.agent = Agent(
                model=self.model,
                system_prompt=system_prompt,
                mcp_servers=[self.mcp_server]
            )
            
            protocol_logger.info("Server started and connected successfully")
            fs_logger.info("Server started and connected successfully")
            
            console.print(Panel.fit(
                "[bold green]Ready to connect to Okta MCP Server via STDIO[/]",
                title="Connection Status"
            ))
            
            return True
            
        except Exception as e:
            protocol_logger.error(f"Error setting up MCP client: {e}")
            fs_logger.error(f"Error setting up MCP client: {e}")
            console.print(Panel(
                f"[bold red]Error setting up MCP client:[/]\n{str(e)}",
                title="Setup Error",
                border_style="red"
            ))
            return False
    
    async def test_connection(self):
        """Test the connection by making a simple request."""
        try:
            protocol_logger.info("Testing connection...")
            fs_logger.info("Testing connection...")
            
            async with self.agent.run_mcp_servers():
                # If we get here, the connection is working
                protocol_logger.info("Connection test successful")
                fs_logger.info("Connection test successful")
                return True
        except Exception as e:
            protocol_logger.error(f"Connection test failed: {e}")
            fs_logger.error(f"Connection test failed: {e}")
            return False
    
    async def process_query(self, query: str):
        """Process a user query using the agent with STDIO transport."""
        if not self.agent:
            raise ValueError("Agent not initialized")
        
        with console.status(f"[bold green]Processing query: {query}"):
            try:
                # Log that we're about to process a query
                protocol_logger.info(f"Processing query: {query}")
                fs_logger.info(f"Processing query: {query}")
                
                # Add direct console logging for visibility
                console.print(f"[dim]Starting query processing...[/]")
                
                # Run the query through the agent
                async with self.agent.run_mcp_servers():
                    # Log MCP servers are running
                    protocol_logger.info("MCP servers started for query")
                    fs_logger.info("MCP servers started for query")
                    
                    # Log the start of the agent run
                    protocol_logger.info("Starting agent.run(query)")
                    fs_logger.info("Starting agent.run(query)")
                    
                    # Execute the query
                    result = await self.agent.run(query)
                    
                    # Log the completion of the query
                    protocol_logger.info("Agent.run completed successfully")
                    fs_logger.info("Agent.run completed successfully")
                    
                    # Try to log all messages exchanged
                    try:
                        if hasattr(result, 'all_messages'):
                            messages = result.all_messages()
                            protocol_logger.info(f"Message exchange count: {len(messages)}")
                            fs_logger.info(f"Message exchange count: {len(messages)}")
                            
                            for i, msg in enumerate(messages):
                                # Convert to string in case it's not serializable
                                msg_str = str(msg)
                                try:
                                    if isinstance(msg, dict):
                                        msg_str = json.dumps(msg, default=str)
                                except:
                                    pass
                                
                                protocol_logger.info(f"Message {i}: {msg_str}")
                                fs_logger.info(f"Message {i}: {msg_str}")
                    except Exception as e:
                        protocol_logger.error(f"Error logging messages: {e}")
                        fs_logger.error(f"Error logging messages: {e}")
                    
                    # Always print detailed output in debug mode
                    if DEBUG_MODE:
                        console.print("[cyan]===== Full message exchange =====[/]")
                        console.print(result.all_messages())
                    else:
                        console.print("[green]Query processed successfully[/]")
                    
                    return result.data
                    
            except Exception as e:
                protocol_logger.error(f"Error processing query: {e}")
                fs_logger.error(f"Error processing query: {e}")
                console.print(f"[bold red]Query processing error: {e}[/]")
                return f"Error processing query: {str(e)}"

    async def inspect_tool_definitions(self):
        """Show what tool definitions the LLM actually sees."""
        try:
            console.print("[yellow]Inspecting tool definitions...[/]")
            protocol_logger.info("Inspecting tool definitions")
            fs_logger.info("Inspecting tool definitions")
            
            if not self.mcp_server:
                raise ValueError("MCP Server not initialized")
                
            async with self.agent.run_mcp_servers():
                tools = await self.mcp_server.list_tools()
                
                # Log the tools we found
                protocol_logger.info(f"Found {len(tools) if tools else 0} tools")
                fs_logger.info(f"Found {len(tools) if tools else 0} tools")
                
                console.print(Panel(
                    format_json_with_newlines(tools),
                    title="Tool Definitions",
                    border_style="yellow"
                ))
                
                return tools
        except Exception as e:
            protocol_logger.error(f"Error inspecting tool definitions: {e}")
            fs_logger.error(f"Error inspecting tool definitions: {e}")
            console.print(f"[bold red]Error inspecting tools: {e}[/]")
            return f"Error: {str(e)}"

async def interactive_client():
    """Run an interactive session with the STDIO client."""
    client = OktaMCPStdioClient()
    
    try:
        if not await client.connect():
            return
        
        # Test the connection to make sure it's working
        if not await client.test_connection():
            console.print("[bold yellow]Warning: Connection test failed. Functionality may be limited.[/]")
        
        console.print("\n[bold cyan]Okta MCP STDIO Client[/]")
        console.print("Type 'exit' to quit")
        console.print("Type 'tools' to show available tools")
        console.print("Type 'debug on' to enable debug mode")
        console.print("Type 'debug off' to disable debug mode")
        
        while True:
            try:
                query = Prompt.ask("\n[bold]Enter your query")
                
                # Handle special commands
                query_lower = query.lower().strip()
                
                # Exit command
                if query_lower in ("exit", "quit"):
                    break
                
                # Debug mode commands
                if query_lower == "debug on":
                    os.environ['DEBUG'] = 'true'
                    console.print("[green]Debug mode enabled[/]")
                    continue
                
                if query_lower == "debug off":
                    os.environ['DEBUG'] = 'false'
                    console.print("[green]Debug mode disabled[/]")
                    continue
                
                # Tools inspection command
                if query_lower in ("tools", "tool", "?"):
                    await client.inspect_tool_definitions()
                    continue
                
                # Process normal query
                result = await client.process_query(query)
                
                # Display structured result if available
                if result:
                    formatted_result = format_json_with_newlines(result)
                    result_syntax = Syntax(
                        formatted_result, 
                        "json", 
                        theme="monokai",
                        line_numbers=True,
                        word_wrap=True
                    )
                    
                    console.print(Panel(
                        result_syntax,
                        title="Structured Result",
                        border_style="green"
                    ))
                
            except KeyboardInterrupt:
                console.print("\n[yellow]Command interrupted[/]")
                break
            except Exception as e:
                client_logger.error(f"Error in interactive loop: {e}")
                fs_logger.error(f"Error in interactive loop: {e}")
                console.print(f"[bold red]Error: {e}[/]")
    
    finally:
        protocol_logger.info("Client session ended")
        fs_logger.info("Client session ended")

if __name__ == "__main__":
    try:
        asyncio.run(interactive_client())
    except KeyboardInterrupt:
        console.print("\n[italic]Client terminated by user[/]")
        protocol_logger.info("Client terminated by keyboard interrupt")
        fs_logger.info("Client terminated by keyboard interrupt")
    except Exception as e:
        client_logger.error(f"Unhandled error: {e}")
        protocol_logger.error(f"Unhandled error: {e}")
        fs_logger.error(f"Unhandled error: {e}")
        console.print(f"[bold red]Unhandled error: {e}[/]")