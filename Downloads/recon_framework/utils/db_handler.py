"""
Database handler utility for the reconnaissance framework.
Handles MongoDB connections and operations.
"""

import logging
from pymongo import MongoClient
from pymongo.errors import ConnectionFailure, ServerSelectionTimeoutError

logger = logging.getLogger(__name__)

def initialize_db(config):
    """
    Initialize MongoDB connection using configuration.
    
    Args:
        config (dict): Configuration dictionary containing MongoDB settings
        
    Returns:
        MongoClient or None: MongoDB client if connection successful, None otherwise
    """
    try:
        # Extract MongoDB configuration
        mongo_config = config.get('mongodb', {})
        host = mongo_config.get('host', 'localhost')
        port = int(mongo_config.get('port', 27017))
        database = mongo_config.get('database', 'recon_framework')
        username = mongo_config.get('username')
        password = mongo_config.get('password')
        
        # Create connection string
        if username and password:
            connection_string = f"mongodb://{username}:{password}@{host}:{port}/{database}"
        else:
            connection_string = f"mongodb://{host}:{port}/{database}"
        
        # Connect to MongoDB
        client = MongoClient(connection_string, serverSelectionTimeoutMS=5000)
        
        # Verify connection
        client.admin.command('ping')
        logger.info(f"Successfully connected to MongoDB at {host}:{port}")
        
        # Initialize collections if they don't exist
        db = client[database]
        if 'subdomains_monitor' not in db.list_collection_names():
            db.create_collection('subdomains_monitor')
            logger.info("Created 'subdomains_monitor' collection")
        
        if 'new_discovered_subdomains' not in db.list_collection_names():
            db.create_collection('new_discovered_subdomains')
            logger.info("Created 'new_discovered_subdomains' collection")
            
        if 'new_hosts_discovered' not in db.list_collection_names():
            db.create_collection('new_hosts_discovered')
            logger.info("Created 'new_hosts_discovered' collection")
            
        if 'notifications' not in db.list_collection_names():
            db.create_collection('notifications')
            logger.info("Created 'notifications' collection")

        if 'program_discoveries' not in db.list_collection_names():
            db.create_collection('program_discoveries')
            logger.info("Created 'program_discoveries' collection")

        return client
    
    except (ConnectionFailure, ServerSelectionTimeoutError) as e:
        logger.error(f"Failed to connect to MongoDB: {str(e)}")
        return None
    except Exception as e:
        logger.error(f"Unexpected error when initializing database: {str(e)}")
        return None
