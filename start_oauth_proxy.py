#!/usr/bin/env python3
"""
Okta MCP OAuth Proxy Startup Script

Simple script to start the OAuth proxy with sensible defaults.
"""

import sys
import subprocess
import os
from pathlib import Path

def main():
    """Start the OAuth proxy with default settings"""
    
    # Get the directory of this script
    script_dir = Path(__file__).parent
    
    # Default settings
    backend = script_dir / "main.py"
    host = "localhost"
    port = "3001"
    
    # Check if backend exists
    if not backend.exists():
        print(f"Error: Backend MCP server not found at {backend}")
        sys.exit(1)
    
    # Check if .env file exists
    env_file = script_dir / ".env"
    if not env_file.exists():
        print("Warning: .env file not found. Make sure to configure Okta settings.")
    
    # Build command
    oauth_proxy = script_dir / "oauth_proxy.py"
    cmd = [
        sys.executable,
        str(oauth_proxy),
        "--backend", str(backend),
        "--host", host,
        "--port", port
    ]
    
    print(f"Starting Okta MCP OAuth Proxy...")
    print(f"Backend: {backend}")
    print(f"Server: http://{host}:{port}")
    print(f"Command: {' '.join(cmd)}")
    print()
    
    try:
        subprocess.run(cmd, check=True)
    except KeyboardInterrupt:
        print("\nShutting down...")
    except subprocess.CalledProcessError as e:
        print(f"Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
