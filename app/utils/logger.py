import logging
import sys

def setup_logger(name):
    """Creates a configured logger."""
    logger = logging.getLogger(name)
    
    # Only configure if it doesn't already have handlers
    if not logger.handlers:
        logger.setLevel(logging.INFO)
        handler = logging.StreamHandler(sys.stdout)
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        handler.setFormatter(formatter)
        logger.addHandler(handler)
        
    return logger
