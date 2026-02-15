#!/usr/bin/env python3
"""
Entry point script for running the IDS backend.
"""

import os

# Load .env before any other imports (optional)
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass  # python-dotenv not installed; use pip install python-dotenv

import sys
import argparse
import logging

def main():
    parser = argparse.ArgumentParser(description='Intrusion Detection System Backend')
    
    parser.add_argument(
        '--host',
        default=os.environ.get('IDS_HOST', '0.0.0.0'),
        help='Host to bind to (default: 0.0.0.0)'
    )
    parser.add_argument(
        '--port',
        type=int,
        default=int(os.environ.get('IDS_PORT', 5000)),
        help='Port to bind to (default: 5000)'
    )
    parser.add_argument(
        '--debug',
        action='store_true',
        default=os.environ.get('IDS_DEBUG', 'false').lower() == 'true',
        help='Enable debug mode'
    )
    parser.add_argument(
        '--interface',
        default=os.environ.get('NETWORK_INTERFACE', 'eth0'),
        help='Network interface to monitor (default: eth0)'
    )
    parser.add_argument(
        '--no-monitor',
        action='store_true',
        help='Start without auto-starting the traffic monitor'
    )
    parser.add_argument(
        '--log-level',
        choices=['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'],
        default='INFO',
        help='Logging level (default: INFO)'
    )
    
    args = parser.parse_args()
    
    # Configure logging
    logging.basicConfig(
        level=getattr(logging, args.log_level),
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    logger = logging.getLogger(__name__)
    
    # Set environment variables
    os.environ['NETWORK_INTERFACE'] = args.interface
    
    # Import and create app
    from app import create_app
    app = create_app()
    
    logger.info(f"Starting IDS Backend")
    logger.info(f"  Host: {args.host}")
    logger.info(f"  Port: {args.port}")
    logger.info(f"  Interface: {args.interface}")
    logger.info(f"  Debug: {args.debug}")
    
    # Run the application
    app.run(
        host=args.host,
        port=args.port,
        debug=args.debug,
        threaded=True
    )


if __name__ == '__main__':
    main()