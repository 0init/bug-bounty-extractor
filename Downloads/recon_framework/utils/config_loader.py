"""
Configuration loader utility for the reconnaissance framework.
Handles loading and parsing of configuration files.
"""

import os
import logging
import configparser
import json
from dotenv import load_dotenv

logger = logging.getLogger(__name__)

def load_config(config_path=None):
    """
    Load configuration from .ini file or environment variables.
    
    Args:
        config_path (str, optional): Path to configuration file. Defaults to None.
        
    Returns:
        dict: Configuration dictionary
    """
    config = {}
    
    # Try to load from .env file first
    load_dotenv()
    
    # If config_path is not provided, check for environment variable
    if not config_path:
        config_path = os.environ.get('RECON_CONFIG_PATH', 'config/.config')
    
    # Check if config file exists
    if not os.path.exists(config_path):
        logger.warning(f"Configuration file not found at {config_path}")
        logger.info("Attempting to use environment variables for configuration")
        return load_config_from_env()
    
    try:
        # Parse config file
        parser = configparser.ConfigParser()
        parser.read(config_path)
        
        # MongoDB configuration
        if 'mongodb' in parser:
            config['mongodb'] = {
                'host': parser.get('mongodb', 'host', fallback='localhost'),
                'port': parser.get('mongodb', 'port', fallback='27017'),
                'database': parser.get('mongodb', 'database', fallback='recon_framework'),
                'username': parser.get('mongodb', 'username', fallback=None),
                'password': parser.get('mongodb', 'password', fallback=None)
            }
        
        # VirusTotal configuration
        if 'virustotal' in parser:
            try:
                api_keys = json.loads(parser.get('virustotal', 'api_key', fallback='[]'))
                config['virustotal'] = {'api_key': api_keys}
            except json.JSONDecodeError:
                logger.error("Failed to parse VirusTotal API keys as JSON")
                config['virustotal'] = {'api_key': []}
        
        # Gmail configuration
        if 'gmail' in parser:
            config['gmail'] = {
                'username': parser.get('gmail', 'username', fallback=None),
                'password': parser.get('gmail', 'password', fallback=None)
            }
        
        # Discord configuration
        if 'discord' in parser:
            config['discord'] = {
                'webhook_url': parser.get('discord', 'webhook_url', fallback=None)
            }
        
        # Acunetix configuration
        if 'acunetix' in parser:
            try:
                servers = json.loads(parser.get('acunetix', 'servers', fallback='[]'))
                config['acunetix'] = {'servers': servers}
            except json.JSONDecodeError:
                logger.error("Failed to parse Acunetix servers as JSON")
                config['acunetix'] = {'servers': []}
        
        # Nuclei configuration
        if 'nuclei' in parser:
            config['nuclei'] = {
                'templates_path': parser.get('nuclei', 'templates_path', fallback=None)
            }
        
        # Tools configuration
        if 'tools' in parser:
            config['tools'] = {
                'subfinder': parser.get('tools', 'subfinder', fallback='/usr/bin/subfinder'),
                'assetfinder': parser.get('tools', 'assetfinder', fallback='/usr/bin/assetfinder'),
                'naabu': parser.get('tools', 'naabu', fallback='/usr/bin/naabu'),
                'nuclei': parser.get('tools', 'nuclei', fallback='/usr/bin/nuclei')
            }
        
        # Target domains
        if 'targets' in parser:
            try:
                domains = json.loads(parser.get('targets', 'domains', fallback='[]'))
                config['targets'] = {'domains': domains}
            except json.JSONDecodeError:
                logger.error("Failed to parse target domains as JSON")
                config['targets'] = {'domains': []}

        # Program extractor configuration
        if 'program_extractor' in parser:
            config['program_extractor'] = {
                'output_file': parser.get('program_extractor', 'output_file', fallback='domains.txt'),
                'request_timeout': int(parser.get('program_extractor', 'request_timeout', fallback='30')),
                'security_txt_threads': int(parser.get('program_extractor', 'security_txt_threads', fallback='10')),
                'security_txt_max_domains': int(parser.get('program_extractor', 'security_txt_max_domains', fallback='500')),
            }

        logger.info(f"Successfully loaded configuration from {config_path}")
        return config
    
    except Exception as e:
        logger.error(f"Error loading configuration: {str(e)}")
        return load_config_from_env()

def load_config_from_env():
    """
    Load configuration from environment variables.
    
    Returns:
        dict: Configuration dictionary
    """
    config = {}
    
    # MongoDB configuration
    config['mongodb'] = {
        'host': os.environ.get('MONGO_HOST', 'localhost'),
        'port': os.environ.get('MONGO_PORT', '27017'),
        'database': os.environ.get('MONGO_DB', 'recon_framework'),
        'username': os.environ.get('MONGO_USERNAME'),
        'password': os.environ.get('MONGO_PASSWORD')
    }
    
    # VirusTotal configuration
    vt_api_keys = os.environ.get('VT_API_KEYS')
    if vt_api_keys:
        try:
            config['virustotal'] = {'api_key': json.loads(vt_api_keys)}
        except json.JSONDecodeError:
            config['virustotal'] = {'api_key': [vt_api_keys]}
    else:
        config['virustotal'] = {'api_key': []}
    
    # Gmail configuration
    config['gmail'] = {
        'username': os.environ.get('GMAIL_USERNAME'),
        'password': os.environ.get('GMAIL_PASSWORD')
    }
    
    # Discord configuration
    config['discord'] = {
        'webhook_url': os.environ.get('DISCORD_WEBHOOK_URL')
    }
    
    # Acunetix configuration
    acunetix_servers = os.environ.get('ACUNETIX_SERVERS')
    if acunetix_servers:
        try:
            config['acunetix'] = {'servers': json.loads(acunetix_servers)}
        except json.JSONDecodeError:
            config['acunetix'] = {'servers': []}
    else:
        config['acunetix'] = {'servers': []}
    
    # Nuclei configuration
    config['nuclei'] = {
        'templates_path': os.environ.get('NUCLEI_TEMPLATES_PATH')
    }
    
    # Tools configuration
    config['tools'] = {
        'subfinder': os.environ.get('SUBFINDER_PATH', '/usr/bin/subfinder'),
        'assetfinder': os.environ.get('ASSETFINDER_PATH', '/usr/bin/assetfinder'),
        'naabu': os.environ.get('NAABU_PATH', '/usr/bin/naabu'),
        'nuclei': os.environ.get('NUCLEI_PATH', '/usr/bin/nuclei')
    }
    
    # Target domains
    target_domains = os.environ.get('TARGET_DOMAINS')
    if target_domains:
        try:
            config['targets'] = {'domains': json.loads(target_domains)}
        except json.JSONDecodeError:
            config['targets'] = {'domains': []}
    else:
        config['targets'] = {'domains': []}

    # Program extractor configuration
    config['program_extractor'] = {
        'output_file': os.environ.get('PROGRAM_EXTRACTOR_OUTPUT_FILE', 'domains.txt'),
        'request_timeout': int(os.environ.get('PROGRAM_EXTRACTOR_REQUEST_TIMEOUT', '30')),
        'security_txt_threads': int(os.environ.get('PROGRAM_EXTRACTOR_SECURITY_TXT_THREADS', '10')),
        'security_txt_max_domains': int(os.environ.get('PROGRAM_EXTRACTOR_SECURITY_TXT_MAX_DOMAINS', '500')),
    }

    logger.info("Loaded configuration from environment variables")
    return config
