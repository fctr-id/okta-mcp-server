"""
Logging utilities for MCP clients and servers.
Provides standardized logging configuration and enhanced transport layers with logging.
"""

import os
import json
import logging
import datetime
import asyncio
from logging.handlers import RotatingFileHandler
from typing import Any, List, Dict, Callable, Optional
from pydantic_ai.mcp import MCPServerStdio

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

def setup_protocol_logging(logger_name="okta-mcp-server", fs_logger_name="filesystem"):
    """
    Set up protocol-level logging to capture all MCP messages.
    
    Args:
        logger_name: The name for the protocol logger
        fs_logger_name: The name for the filesystem logger
        
    Returns:
        Tuple containing (protocol_logger, fs_logger)
    """
    log_dir = get_log_directory()
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
    protocol_logger = logging.getLogger(logger_name)
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
    fs_logger = logging.getLogger(fs_logger_name)
    fs_logger.setLevel(logging.INFO)
    
    for handler in fs_logger.handlers[:]:
        fs_logger.removeHandler(handler)
    
    # Share the same handler for consistent formatting
    fs_logger.addHandler(file_handler)
    fs_logger.propagate = False
    
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
    
    # Create console handler
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(formatter)
    console_handler.setLevel(log_level)
    logger.addHandler(console_handler)
    
    # Disable propagation to avoid duplicate logs
    logger.propagate = False
    
    return logger

def format_json_with_newlines(obj: Any) -> str:
    """Format JSON with proper newlines and indentation."""
    if obj is None:
        return "null"
    
    try:
        json_str = json.dumps(obj, indent=2, default=str)
        json_str = json_str.replace('\\n', '\n')
        return json_str
    except Exception as e:
        return str(obj)

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

class LoggingMCPServerStdio(MCPServerStdio):
    """Enhanced MCPServerStdio with logging capabilities and progress callbacks."""
    
    def __init__(self, *args, **kwargs):
        # Get or create loggers
        self.protocol_logger = kwargs.pop('protocol_logger', logging.getLogger("okta-mcp-server"))
        self.fs_logger = kwargs.pop('fs_logger', logging.getLogger("filesystem"))
        
        # Store callbacks for send/receive events
        self.on_send_callback = kwargs.pop('on_send_callback', None)
        self.on_receive_callback = kwargs.pop('on_receive_callback', None)
        
        self.protocol_logger.info("Creating LoggingMCPServerStdio instance")
        self.fs_logger.info("Creating LoggingMCPServerStdio instance")
        
        # Wrap the process to capture STDIO
        self._original_process = None
        
        # Add direct message logging
        self._enable_direct_message_logging = kwargs.pop('enable_direct_logging', True)
        
        super().__init__(*args, **kwargs)
        
        # Set up instance-specific logging
        self._setup_logging()
    
    async def send(self, data):
        """Override send to log and track tool usage."""
        # Log the raw message
        self.protocol_logger.info(f"Sending message: {json.dumps(data, default=str)[:200]}")
        
        # Check if this is a tool call
        if self.on_send_callback:
            tool_info = extract_tool_info(data)
            if tool_info:
                self.protocol_logger.info(f"Identified tool call: {json.dumps(tool_info, default=str)}")
                self.on_send_callback(tool_info)
        
        # Call the original implementation
        return await super().send(data)
    
    async def receive(self):
        """Override receive to log and track tool responses."""
        # Call the original implementation
        result = await super().receive()
        
        # Log the raw message
        if result:
            self.protocol_logger.info(f"Received message: {json.dumps(result, default=str)[:200]}")
            
            # Check if this is a tool response
            if self.on_receive_callback:
                tool_info = extract_tool_info(result)
                if tool_info:
                    self.protocol_logger.info(f"Identified tool response: {json.dumps(tool_info, default=str)}")
                    self.on_receive_callback(tool_info)
        
        return result
    
    def _setup_logging(self):
        """Set up logging hooks for this instance."""
        # Only wrap what we haven't overridden
        methods = [m for m in dir(self) if not m.startswith('_') and callable(getattr(self, m)) 
                   and m not in ['send', 'receive']]
        
        self.protocol_logger.info(f"Available public methods: {methods}")
        
        # Try to identify message handling methods
        if hasattr(self, 'list_tools'):
            self._wrap_method('list_tools') 
    
    def _wrap_method(self, method_name):
        """Wrap a method to add logging before and after."""
        original_method = getattr(self, method_name)
        
        if asyncio.iscoroutinefunction(original_method):
            async def wrapped_method(*args, **kwargs):
                self.protocol_logger.info(f"Calling {method_name} with args: {args}, kwargs: {kwargs}")
                self.fs_logger.info(f"Calling {method_name}")
                
                try:
                    # For send method, execute callback before sending
                    if method_name == 'send' and self.on_send_callback and args and len(args) > 0:
                        tool_info = extract_tool_info(args[0])
                        if tool_info:
                            self.on_send_callback(tool_info)
                    
                    result = await original_method(*args, **kwargs)
                    
                    # For receive method, execute callback after receiving
                    if method_name == 'receive' and self.on_receive_callback and result:
                        tool_info = extract_tool_info(result)
                        if tool_info:
                            self.on_receive_callback(tool_info)
                    
                    self.protocol_logger.info(f"{method_name} returned: {json.dumps(result, default=str) if result else 'None'}")
                    self.fs_logger.info(f"{method_name} completed")
                    return result
                except Exception as e:
                    self.protocol_logger.error(f"Error in {method_name}: {e}")
                    self.fs_logger.error(f"Error in {method_name}: {e}")
                    raise
        else:
            def wrapped_method(*args, **kwargs):
                self.protocol_logger.info(f"Calling {method_name} with args: {args}, kwargs: {kwargs}")
                self.fs_logger.info(f"Calling {method_name}")
                
                try:
                    # For synchronous methods, handle callbacks similarly
                    if method_name == 'send' and self.on_send_callback and args and len(args) > 0:
                        tool_info = extract_tool_info(args[0])
                        if tool_info:
                            self.on_send_callback(tool_info)
                    
                    result = original_method(*args, **kwargs)
                    
                    if method_name == 'receive' and self.on_receive_callback and result:
                        tool_info = extract_tool_info(result)
                        if tool_info:
                            self.on_receive_callback(tool_info)
                    
                    self.protocol_logger.info(f"{method_name} returned: {json.dumps(result, default=str) if result else 'None'}")
                    self.fs_logger.info(f"{method_name} completed")
                    return result
                except Exception as e:
                    self.protocol_logger.error(f"Error in {method_name}: {e}")
                    self.fs_logger.error(f"Error in {method_name}: {e}")
                    raise
                
        setattr(self, method_name, wrapped_method)
        self.protocol_logger.info(f"Successfully wrapped method: {method_name}")
        self.fs_logger.info(f"Successfully wrapped method: {method_name}")

class MessageHandler:
    """Hook to capture messages directly from the network layer."""
    
    @staticmethod
    async def capture_jsonrpc(func):
        """Decorator to capture JSONRPC messages."""
        protocol_logger = logging.getLogger("okta-mcp-server")
        fs_logger = logging.getLogger("filesystem")
        
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