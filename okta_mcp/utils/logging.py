"""Logging configuration for Okta MCP server."""

import os
import logging
import datetime
from logging.handlers import RotatingFileHandler
from pathlib import Path
from dotenv import load_dotenv

load_dotenv()  # Load environment variables from .env file
# Custom formatter for ISO8601 timestamps with Z suffix
class ISO8601Formatter(logging.Formatter):
    def formatTime(self, record, datefmt=None):
        # Create ISO8601 format with milliseconds and Z suffix
        dt = datetime.datetime.fromtimestamp(record.created)
        return dt.strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3] + 'Z'

def configure_logging(log_level=None, console_level=None):
    """
    Configure root logging for the application.
    
    Args:
        log_level: The log level for file output (defaults to LOG_LEVEL env var or INFO)
        console_level: The log level for console output (defaults to INFO or higher)
    
    Returns:
        The configured root logger
    """
    # Determine log levels from environment or parameters
    if log_level is None:
        log_level_str = os.getenv('LOG_LEVEL', 'INFO').upper()
        log_level = getattr(logging, log_level_str, logging.INFO)
    
    # For console, default to INFO if LOG_LEVEL is DEBUG, otherwise use LOG_LEVEL
    if console_level is None:
        console_level = max(logging.INFO, log_level) if log_level_str != 'DEBUG' else logging.INFO
    
    # Configure the root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(min(log_level, console_level))  # Set to the more verbose level
    
    # Remove any existing handlers to avoid duplicates
    for handler in root_logger.handlers[:]:
        root_logger.removeHandler(handler)
    
    # Create formatter
    formatter = logging.Formatter('%(asctime)s [%(levelname)s] [%(name)s] %(message)s')
    
    # Create and add console handler with the specified console level
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(formatter)
    console_handler.setLevel(console_level)  # Important: Console only gets INFO or higher
    root_logger.addHandler(console_handler)
    
    # Create and add file handler with the file log level
    log_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '../../../logs'))
    os.makedirs(log_dir, exist_ok=True)
    
    file_handler = logging.handlers.RotatingFileHandler(
        os.path.join(log_dir, 'app.log'),
        maxBytes=10*1024*1024,  # 10MB
        backupCount=5
    )
    file_handler.setFormatter(formatter)
    file_handler.setLevel(log_level)  # File gets the full log level (can be DEBUG)
    root_logger.addHandler(file_handler)
    
    # Configure third-party loggers (make sure they respect our console level)
    for logger_name in ['asyncio', 'openai', 'httpx', 'pydantic_ai', 'json', 'requests']:
        third_party_logger = logging.getLogger(logger_name)
        third_party_logger.setLevel(log_level)  # They can log at the file level
        third_party_logger.propagate = True     # But they should use our handlers
    
    return root_logger