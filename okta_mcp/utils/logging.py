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

def configure_logging(log_level=os.getenv("LOG_LEVEL", "INFO").upper()):
    """
    Configure logging to both console and file with rotation.
    
    Args:
        log_level: Logging level (default: INFO)
        
    Returns:
        Logger instance
    """
    # Find the project root by going up from the current file location 
    # instead of using the current working directory
    current_file = Path(__file__)  # Get the path of this logging.py file
    project_root = current_file.parent.parent.parent  # Navigate up to root
    
    # Create logs directory in project root
    log_path = project_root / "logs"
    log_path.mkdir(exist_ok=True)
    
    # Define log file path
    log_file = log_path / "okta_mcp_server.log"
    
    # Create custom ISO8601 formatter
    formatter = ISO8601Formatter('%(asctime)s [%(levelname)s] [%(name)s] %(message)s')
    
    # Set up file handler with rotation (10MB files, keep 5 backups)
    file_handler = RotatingFileHandler(
        log_file, 
        maxBytes=10*1024*1024,  # 10MB
        backupCount=5
    )
    file_handler.setFormatter(formatter)
    file_handler.setLevel(log_level)
    
    # Set up console handler
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(formatter)
    console_handler.setLevel(log_level)
    
    # Configure root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(log_level)
    
    # Remove existing handlers to avoid duplicates
    for handler in root_logger.handlers[:]:
        root_logger.removeHandler(handler)
        
    # Add handlers
    root_logger.addHandler(file_handler)
    root_logger.addHandler(console_handler)
    
    # Create server logger
    logger = logging.getLogger("okta_mcp_server")
    
    return logger