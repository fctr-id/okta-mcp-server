"""
Unified logging configuration for Okta MCP server.
Handles standard logging, MCP protocol logging, and context notifications.
"""

import os
import sys
import json
import logging
import datetime
import asyncio
from logging.handlers import RotatingFileHandler
from typing import Dict, Any, List, Optional, Tuple, Callable
from pathlib import Path
from dotenv import load_dotenv
from rich.console import Console
from rich.panel import Panel
from rich.syntax import Syntax

# Initialize Rich console for pretty output
console = Console()

# Load environment variables
load_dotenv()

# Custom formatter for ISO8601 timestamps with Z suffix
class ISO8601Formatter(logging.Formatter):
    """Formatter that outputs timestamps in ISO8601 format with Z suffix."""
    def formatTime(self, record, datefmt=None):
        # Create ISO8601 format with milliseconds and Z suffix
        dt = datetime.datetime.fromtimestamp(record.created)
        return dt.strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3] + 'Z'

def get_log_directory():
    """Get the logs directory, creating it if it doesn't exist."""
    # Use logs directory at the project root
    log_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '../../logs'))
    os.makedirs(log_dir, exist_ok=True)
    return log_dir

def get_logger(name: str = None) -> logging.Logger:
    """
    Get a logger with the specified name.
    
    Args:
        name: Logger name (defaults to 'okta_mcp' if None)
        
    Returns:
        Configured logger instance
    """
    if name is None:
        name = "okta_mcp"
    
    # Get the logger - it will inherit from the root logger configuration
    logger = logging.getLogger(name)
    
    # If this logger doesn't have handlers, it will use the root logger's handlers
    # which were configured in configure_logging()
    
    return logger

def configure_logging(log_level=None, console_level=None, suppress_mcp_logs=True):
    """
    Configure root logging for the application.
    
    Args:
        log_level: The log level for file output (defaults to LOG_LEVEL env var or INFO)
        console_level: The log level for console output (defaults to INFO or higher)
        suppress_mcp_logs: Whether to suppress MCP framework logs
    
    Returns:
        The configured root logger
    """
    # Determine log levels from environment or parameters
    if log_level is None:
        log_level_str = os.getenv('LOG_LEVEL', 'INFO').upper()
        log_level = getattr(logging, log_level_str, logging.INFO)
    
    # For console, default to INFO if LOG_LEVEL is DEBUG, otherwise use LOG_LEVEL
    # On Windows, show INFO level by default for better visibility
    if console_level is None:
        is_windows = os.name == 'nt'
        console_level = logging.INFO if is_windows else max(logging.INFO, log_level)
    
    # Configure the root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(min(log_level, console_level))  # Set to the more verbose level
    
    # Remove any existing handlers to avoid duplicates
    for handler in root_logger.handlers[:]:
        root_logger.removeHandler(handler)
    
    # Create formatter (use ISO8601 formatter for consistent timestamps)
    formatter = ISO8601Formatter('%(asctime)s [%(levelname)s] [%(name)s] %(message)s')
    
    # Create and add console handler with the specified console level
    # Explicitly use sys.stdout for better Windows compatibility
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(formatter)
    console_handler.setLevel(console_level)
    root_logger.addHandler(console_handler)
    
    # Create and add file handler with the file log level
    log_dir = get_log_directory()
    
    file_handler = logging.handlers.RotatingFileHandler(
        os.path.join(log_dir, 'app.log'),
        maxBytes=10*1024*1024,  # 10MB
        backupCount=5
    )
    file_handler.setFormatter(formatter)
    file_handler.setLevel(log_level)  # File gets the full log level (can be DEBUG)
    root_logger.addHandler(file_handler)
    
    # Configure third-party loggers
    for logger_name in ['asyncio', 'openai', 'httpx', 'json', 'requests']:
        third_party_logger = logging.getLogger(logger_name)
        third_party_logger.setLevel(log_level)  # They can log at the file level
        third_party_logger.propagate = True     # But they should use our handlers
    
    # Suppress noisy MCP framework logs if requested
    if suppress_mcp_logs:
        # This will suppress INFO messages from the MCP framework
        logging.getLogger("mcp.server.lowlevel.server").setLevel(logging.WARNING)
        logging.getLogger("mcp.server").setLevel(logging.WARNING)
        logging.getLogger("mcp.client").setLevel(logging.WARNING)
        logging.getLogger("pydantic_ai.mcp").setLevel(logging.WARNING)
        logging.getLogger("pydantic_ai.server").setLevel(logging.WARNING)
        logging.getLogger('httpx').setLevel(logging.WARNING)
        logging.getLogger("okta_mcp").setLevel(logging.WARNING)
        logging.getLogger("okta_mcp.utils").setLevel(logging.WARNING)
        logging.getLogger("okta_mcp.tools").setLevel(logging.WARNING)
        logging.getLogger("okta_mcp.tools.tool_registry").setLevel(logging.WARNING)
    
    return root_logger

def setup_protocol_logging(logger_name="okta-mcp-server", fs_logger_name="filesystem", 
                           show_fs_logs=False, log_level=None):
    """
    Set up protocol-level logging to capture all MCP messages.
    
    Args:
        logger_name: The name for the protocol logger
        fs_logger_name: The name for the filesystem logger
        show_fs_logs: Whether to show filesystem logs in console
        log_level: The logging level to use (defaults to LOG_LEVEL env var or INFO)
    """
    log_dir = get_log_directory()
    log_file = os.path.join(log_dir, "mcp_protocol.log")
    
    # Determine log level from environment if not specified
    if log_level is None:
        log_level_str = os.getenv('LOG_LEVEL', 'INFO').upper()
        log_level = getattr(logging, log_level_str, logging.INFO)
    
    # Create ISO8601 formatter
    formatter = ISO8601Formatter('%(asctime)s [%(levelname)s] [%(name)s] %(message)s')
    
    # Create file handler with rotation - everything still goes to file
    file_handler = RotatingFileHandler(
        log_file, 
        maxBytes=10*1024*1024,  # 10MB
        backupCount=5
    )
    file_handler.setFormatter(formatter)
    file_handler.setLevel(log_level)  # Use provided log level
    
    # Create console handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(formatter)
    console_handler.setLevel("INFO")  # Use provided log level
    
    # Set up the main protocol logger
    protocol_logger = logging.getLogger(logger_name)
    protocol_logger.setLevel(log_level)  # Use provided log level
    
    # Remove existing handlers to avoid duplicates
    for handler in protocol_logger.handlers[:]:
        protocol_logger.removeHandler(handler)
    
    # Add the handlers to protocol logger
    protocol_logger.addHandler(file_handler)
    protocol_logger.addHandler(console_handler)
    protocol_logger.propagate = False
    
    # Set up filesystem logger
    fs_logger = logging.getLogger(fs_logger_name)
    fs_logger.setLevel(log_level)  # Use provided log level
    
    for handler in fs_logger.handlers[:]:
        fs_logger.removeHandler(handler)
    
    # Add file handler to fs_logger - will ALWAYS log to file
    fs_logger.addHandler(file_handler)
    
    # Only add console handler to fs_logger if explicitly requested
    if show_fs_logs:
        fs_logger.addHandler(console_handler)
    
    fs_logger.propagate = False
    
    # Suppress noisy MCP framework logs
    #logging.getLogger("mcp.server.lowlevel.server").setLevel(logging.WARNING)
    #logging.getLogger("mcp.server").setLevel(logging.WARNING)
    #logging.getLogger("mcp.client").setLevel(logging.WARNING)
    logging.getLogger("pydantic_ai.mcp").setLevel(logging.WARNING)
    logging.getLogger("pydantic_ai.server").setLevel(logging.WARNING)
    logging.getLogger("okta_mcp").setLevel(logging.WARNING)
    logging.getLogger("okta_mcp.utils").setLevel(logging.WARNING)
    logging.getLogger("okta_mcp.tools").setLevel(logging.WARNING)
    logging.getLogger("okta_mcp.tools.tool_registry").setLevel(logging.WARNING)
    
    return protocol_logger, fs_logger

def get_client_logger(name="mcp_client", log_level=logging.INFO):
    """
    Get a logger for client-side usage.
    
    Args:
        name: The name for the client logger
        log_level: The overall logging level
        
    Returns:
        Logger configured for client-side logging
    """
    log_dir = get_log_directory()
    log_file = os.path.join(log_dir, f"{name}.log")
    
    # Create formatter
    formatter = ISO8601Formatter('%(asctime)s [%(levelname)s] [%(name)s] %(message)s')
    
    logger = logging.getLogger(name)
    logger.setLevel(log_level)
    
    # Remove existing handlers to avoid duplicates
    for handler in logger.handlers[:]:
        logger.removeHandler(handler)
    
    # Create file handler with rotation
    file_handler = RotatingFileHandler(
        log_file, 
        maxBytes=5*1024*1024,  # 5MB
        backupCount=3
    )
    file_handler.setFormatter(formatter)
    file_handler.setLevel(log_level)
    logger.addHandler(file_handler)
    
    # Create console handler - use stdout for Windows compatibility
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(formatter)
    console_handler.setLevel(log_level)
    logger.addHandler(console_handler)
    
    # Disable propagation to avoid duplicate logs
    logger.propagate = False
    
    return logger

def format_json_with_newlines(data: Any) -> str:
    """
    Format JSON data with proper indentation and newlines for readability.
    
    Args:
        data: Any JSON-serializable data structure
        
    Returns:
        Formatted JSON string with newlines
    """
    if data is None:
        return "null"
    
    try:
        json_str = json.dumps(data, indent=2, default=str)
        # Replace escaped newlines with actual newlines for better readability
        json_str = json_str.replace('\\n', '\n')
        return json_str
    except Exception as e:
        # Get the logger only when needed to avoid circular imports
        logger = logging.getLogger('okta-mcp-server')
        logger.debug(f"Error formatting JSON: {e}")
        return str(data)  # Fall back to string representation

def extract_tool_info(data: dict) -> Optional[dict]:
    """Extract tool usage information from JSON-RPC messages."""
    try:
        if not isinstance(data, dict):
            return None
        
        # Log raw message for debugging
        logging.getLogger("okta-mcp-server").debug(f"Extracting from: {json.dumps(data, default=str)[:200]}")
            
        # Check if this is a JSON-RPC request with function call
        if data.get('jsonrpc') == '2.0' and data.get('method') == 'callFunction':
            params = data.get('params', {})
            if isinstance(params, dict) and 'name' in params:
                return {
                    'type': 'tool_call',
                    'tool_name': params.get('name'),
                    'args': params.get('arguments', {}),
                    'id': data.get('id')
                }
        
        # Alternative format - check for direct message format that might be used
        elif 'function_call' in data or 'name' in data:
            # Handle OpenAI or Claude format for function calls
            name = data.get('function_call', {}).get('name') if 'function_call' in data else data.get('name')
            args = data.get('function_call', {}).get('arguments', {}) if 'function_call' in data else data.get('arguments', {})
            
            if name:
                return {
                    'type': 'tool_call',
                    'tool_name': name,
                    'args': args,
                    'id': data.get('id', 'unknown')
                }
                
        # Check if this is a JSON-RPC response
        elif data.get('jsonrpc') == '2.0' and 'result' in data and 'id' in data:
            return {
                'type': 'tool_response',
                'result': data.get('result'),
                'id': data.get('id')
            }
            
        # Direct response format
        elif 'content' in data and data.get('role') == 'function':
            return {
                'type': 'tool_response',
                'result': data.get('content'),
                'id': data.get('name', 'unknown')
            }
            
        return None
    except Exception as e:
        logging.getLogger("okta-mcp-server").error(f"Error extracting tool info: {e}")
        return None

class LoggingMCPServerStdio:
    """
    Enhanced MCP Server with proper notification handling and real-time display.
    
    This class extends the standard MCP server to properly:
    1. Display context logging messages (logger.info(), logger.error(), etc.)
    2. Show progress notifications
    3. Show tool execution information
    4. Log all server activity
    """
    
    def __init__(self, python_path, script_args, env=None, protocol_logger=None, fs_logger=None):
        """
        Initialize the enhanced MCP server.
        
        Args:
            python_path: Path to Python executable
            script_args: Arguments to pass to the script
            env: Environment variables for the process
            protocol_logger: Logger for protocol messages
            fs_logger: Logger for filesystem operations
        """
        from pydantic_ai.mcp import MCPServerStdio
        
        # Initialize loggers if not provided
        self.protocol_logger = protocol_logger or logging.getLogger("okta-mcp-server")
        self.fs_logger = fs_logger or logging.getLogger("filesystem")
        self.protocol_logger.info("Creating LoggingMCPServerStdio instance")
        
        # Create the actual MCP server
        self.server = MCPServerStdio(python_path, script_args, env=env)
    
    async def send(self, message):
        """Send a message to the MCP server with logging."""
        try:
            # Log the outgoing message
            self.protocol_logger.info(f"Sending message: {message.get('method', 'unknown')} (ID: {message.get('id', 'none')})")
            
            # Log the full message at debug level
            if 'params' in message:
                self.protocol_logger.debug(f"Message params: {format_json_with_newlines(message.get('params'))}")
                
            # Extract and log tool calls specifically
            if message.get('method') == 'tools/call':
                tool_name = message.get('params', {}).get('name', 'unknown')
                tool_params = message.get('params', {}).get('parameters', {})
                self.protocol_logger.info(f"Calling tool: {tool_name}")
                
                # Also show on the console for user visibility - especially on Windows
                if os.name == 'nt':
                    console.print(f"[cyan]Calling tool:[/] [bold magenta]{tool_name}[/]")
            
            # Forward the message to the actual server
            return await self.server.send(message)
        except Exception as e:
            self.protocol_logger.error(f"Error sending message: {e}")
            self.fs_logger.error(f"Error sending message: {e}")
            raise
    
    async def receive(self):
        """
        Receive a message from the MCP server with enhanced logging.
        """
        try:
            # Get the message from the actual server
            message = await self.server.receive()
            
            if not message or not isinstance(message, dict):
                return message
            
            # Debug all messages to see what's coming through
            if isinstance(message, dict) and 'method' in message:
                method = message.get('method', '')
                if method.startswith('notifications/'):
                    self.protocol_logger.debug(f"NOTIFICATION RECEIVED: {method}")
                    self.protocol_logger.debug(f"WITH PARAMS: {format_json_with_newlines(message.get('params', {}))}")            
            
            # Process different message types
            method = message.get('method', '')
            
            # Handle standard MCP notifications (THIS IS KEY FOR CONTEXT MESSAGES)
            if method.startswith('notifications/'):
                params = message.get('params', {})
                
                # Handle logging notifications from Context.info() etc.
                # Support both notifications/logging (custom) and notifications/message (standard MCP)
                if method == 'notifications/logging' or method == 'notifications/message':
                    # For notifications/message, extract message and level from params
                    if method == 'notifications/message':
                        log_message = params.get('data', {}).get('message', '') or str(params.get('data', ''))
                        log_level = params.get('level', 'INFO').upper()
                    else:
                        # Original code for notifications/logging
                        log_message = params.get('message', '')
                        log_level = params.get('level', 'INFO').upper()
                    
                    # Map the level string to a Python log level
                    level_map = {
                        'DEBUG': logging.DEBUG,
                        'INFO': logging.INFO,
                        'WARN': logging.WARNING,
                        'WARNING': logging.WARNING,
                        'ERROR': logging.ERROR,
                        'CRITICAL': logging.CRITICAL
                    }
                    py_level = level_map.get(log_level, logging.INFO)
                    
                    # Log at the appropriate level
                    self.protocol_logger.log(py_level, f"TOOL: {log_message}")
                    
                    # Also show directly on the console with nice formatting
                    # This ensures context.info() messages are visible to the user
                    level_color = {
                        'DEBUG': 'dim',
                        'INFO': 'cyan',
                        'WARN': 'yellow',
                        'WARNING': 'yellow',
                        'ERROR': 'red',
                        'CRITICAL': 'bold red'
                    }.get(log_level, 'cyan')
                    
                    # Always show context messages to users with improved visibility
                    console.print(f"[{level_color}]► {log_message}[/]")
            
            # CRITICAL: Return the message to continue the message pipeline
            return message
            
        except Exception as e:
            self.protocol_logger.error(f"Error receiving message: {e}")
            self.fs_logger.error(f"Error receiving message: {e}")
            raise
        
    # Add this method to check if the server is running
    def is_running(self) -> bool:
        """Check if the MCP server is currently running."""
        # Forward to the underlying server if it has this method
        if hasattr(self.server, 'is_running'):
            return self.server.is_running()
        # Otherwise default to True if we have a server instance
        return self.server is not None        
    
    # Forward all other methods to the actual server
    async def list_tools(self):
        """List all tools available in the MCP server."""
        self.protocol_logger.debug("Listing tools")
        return await self.server.list_tools()

    
    async def call_tool(self, name, parameters=None, **kwargs):
        """Call a tool with the given parameters."""
        self.protocol_logger.info(f"Directly calling tool: {name}")
        if parameters:
            self.protocol_logger.debug(f"Tool parameters: {format_json_with_newlines(parameters)}")
        return await self.server.call_tool(name, parameters, **kwargs)
    
    async def read_resource(self, resource_uri):
        """Read a resource from the MCP server."""
        self.protocol_logger.info(f"Reading resource: {resource_uri}")
        return await self.server.read_resource(resource_uri)
    
    async def write_resource(self, resource_uri, content):
        """Write a resource to the MCP server."""
        self.protocol_logger.info(f"Writing resource: {resource_uri}")
        return await self.server.write_resource(resource_uri, content)
    
    async def delete_resource(self, resource_uri):
        """Delete a resource from the MCP server."""
        self.protocol_logger.info(f"Deleting resource: {resource_uri}")
        return await self.server.delete_resource(resource_uri)
    
    # Support context manager for consistency with the original
    async def __aenter__(self):
        await self.server.__aenter__()
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.server.__aexit__(exc_type, exc_val, exc_tb)