"""Logging configuration for Okta MCP server."""

import os
import logging
from logging.handlers import RotatingFileHandler
from pathlib import Path

def configure_logging(log_dir="logs", log_level=logging.INFO):
    """
    Configure logging to both console and file with rotation.
    
    Args:
        log_dir: Directory to store log files
        log_level: Logging level (default: INFO)
        
    Returns:
        Logger instance
    """
    # Create logs directory if it doesn't exist
    log_path = Path(log_dir)
    log_path.mkdir(exist_ok=True)
    
    # Define log file path
    log_file = log_path / "okta_mcp_server.log"
    
    # Create formatter
    formatter = logging.Formatter(
        '%(asctime)s [%(levelname)s] [%(name)s] %(message)s',
        datefmt='%Y-%m-%dT%H:%M:%S.%fZ'
    )
    
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
    logger.info(f"Logging initialized. Logs saved to: {log_file}")
    
    return logger