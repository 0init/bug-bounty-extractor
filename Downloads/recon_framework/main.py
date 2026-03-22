#!/usr/bin/env python3
"""
Automated Reconnaissance and Vulnerability Scanning Framework
Main execution script that integrates all modules.
"""

import os
import sys
import logging
import argparse
from datetime import datetime
from dotenv import load_dotenv

# Add the current directory to the Python path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

# Import modules - try both relative and absolute imports
try:
    # Try absolute imports first (when installed as a package)
    from recon_framework.subdomain_enum import subdomain_enumeration
    from recon_framework.host_discovery import host_discovery
    from recon_framework.scan import vulnerability_scan
    from recon_framework.notification import notification_handler
    from recon_framework.program_extractor import program_extraction
    from recon_framework.utils import db_handler, config_loader, config_validator
except ImportError:
    # Fall back to relative imports (when running directly)
    from subdomain_enum import subdomain_enumeration
    from host_discovery import host_discovery
    from scan import vulnerability_scan
    from notification import notification_handler
    from program_extractor import program_extraction
    from utils import db_handler, config_loader, config_validator

def setup_logging(log_level=logging.INFO):
    """Set up logging configuration."""
    log_filename = f"recon_framework_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
    
    logging.basicConfig(
        level=log_level,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler(log_filename),
            logging.StreamHandler()
        ]
    )
    
    logger = logging.getLogger(__name__)
    logger.info(f"Logging initialized. Log file: {log_filename}")
    return logger

def parse_arguments():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(description='Automated Reconnaissance and Vulnerability Scanning Framework')
    
    parser.add_argument('-c', '--config', type=str, help='Path to configuration file')
    parser.add_argument('-d', '--domains', type=str, nargs='+', help='Target domains to scan')
    parser.add_argument('-m', '--module', type=str, choices=['all', 'subdomain', 'host', 'scan', 'notify', 'programs'],
                        default='all', help='Specific module to run')
    parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose logging')
    
    return parser.parse_args()

def main():
    """Main function to run the reconnaissance framework."""
    # Parse command line arguments
    args = parse_arguments()
    
    # Setup logging
    log_level = logging.DEBUG if args.verbose else logging.INFO
    logger = setup_logging(log_level)
    
    logger.info("Starting Automated Reconnaissance and Vulnerability Scanning Framework")
    
    # Load configuration
    config = config_loader.load_config(args.config)
    if not config:
        logger.error("Failed to load configuration. Exiting.")
        sys.exit(1)
    
    # Override target domains if specified in command line
    if args.domains:
        if 'targets' not in config:
            config['targets'] = {}
        config['targets']['domains'] = args.domains
        logger.info(f"Using command line specified domains: {args.domains}")
    
    # Validate configuration
    is_valid, missing_settings = config_validator.validate_config(config)
    if not is_valid:
        logger.error(f"Invalid configuration. Missing settings: {', '.join(missing_settings)}")
        logger.info("Example minimal configuration:")
        logger.info(config_validator.get_minimal_config_example())
        sys.exit(1)
    
    # Initialize database connection
    db = db_handler.initialize_db(config)
    if not db:
        logger.error("Failed to connect to MongoDB. Exiting.")
        sys.exit(1)
    
    # Determine which modules to run
    run_all = args.module == 'all'
    run_subdomain = run_all or args.module == 'subdomain'
    run_host = run_all or args.module == 'host'
    run_scan = run_all or args.module == 'scan'
    run_notify = run_all or args.module == 'notify'
    
    # Track results for each module
    results = {
        'program_results': None,
        'subdomain_results': None,
        'host_results': None,
        'scan_results': None,
        'notification_results': None
    }
    
    # Run program extraction
    run_programs = run_all or args.module == 'programs'
    if run_programs:
        logger.info("Running Program Extractor Module")
        try:
            results['program_results'] = program_extraction.run(config, db, interactive=True)
            logger.info(f"Program extraction completed. Found {len(results['program_results'].get('programs_found', []))} domains.")
        except Exception as e:
            logger.error(f"Error in Program Extractor Module: {str(e)}")
            if not run_all:
                sys.exit(1)

    # Run subdomain enumeration
    if run_subdomain:
        logger.info("Running Subdomain Enumeration Module")
        try:
            results['subdomain_results'] = subdomain_enumeration.run(config, db)
            logger.info(f"Subdomain enumeration completed. Found {len(results['subdomain_results'].get('new_subdomains', []))} new subdomains.")
        except Exception as e:
            logger.error(f"Error in Subdomain Enumeration Module: {str(e)}")
            if not run_all:
                sys.exit(1)
    
    # Run host discovery on new subdomains
    if run_host and (run_all or (results['subdomain_results'] and results['subdomain_results'].get('new_subdomains'))):
        logger.info("Running Host Discovery Module")
        try:
            results['host_results'] = host_discovery.run(config, db)
            logger.info(f"Host discovery completed. Found {len(results['host_results'].get('new_hosts', []))} new hosts.")
        except Exception as e:
            logger.error(f"Error in Host Discovery Module: {str(e)}")
            if not run_all:
                sys.exit(1)
    
    # Run vulnerability scanning on new hosts
    if run_scan and (run_all or (results['host_results'] and results['host_results'].get('new_hosts'))):
        logger.info("Running Scan Module")
        try:
            results['scan_results'] = vulnerability_scan.run(config, db)
            logger.info(f"Vulnerability scanning completed. Found {len(results['scan_results'].get('vulnerabilities', []))} vulnerabilities.")
        except Exception as e:
            logger.error(f"Error in Scan Module: {str(e)}")
            if not run_all:
                sys.exit(1)
    
    # Send notifications based on scan results
    if run_notify and (run_all or (results['scan_results'] and results['scan_results'].get('vulnerabilities'))):
        logger.info("Sending notifications")
        try:
            results['notification_results'] = notification_handler.send_notifications(config, db, results['scan_results'])
            logger.info(f"Notifications sent: {results['notification_results'].get('notifications_sent', 0)}")
        except Exception as e:
            logger.error(f"Error in Notification Module: {str(e)}")
            if not run_all:
                sys.exit(1)
    
    # Print summary
    logger.info("Reconnaissance framework execution completed")
    logger.info("Summary:")
    if results['program_results']:
        logger.info(f"- Program domains found: {len(results['program_results'].get('programs_found', []))}")
    if results['subdomain_results']:
        logger.info(f"- New subdomains: {len(results['subdomain_results'].get('new_subdomains', []))}")
    if results['host_results']:
        logger.info(f"- New hosts: {len(results['host_results'].get('new_hosts', []))}")
    if results['scan_results']:
        logger.info(f"- Vulnerabilities found: {len(results['scan_results'].get('vulnerabilities', []))}")
    if results['notification_results']:
        logger.info(f"- Notifications sent: {results['notification_results'].get('notifications_sent', 0)}")

if __name__ == "__main__":
    main()
