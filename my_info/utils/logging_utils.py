import logging
import logging.handlers
import os
from django.conf import settings  # Import Django settings

def setup_integration_logger(log_level=logging.INFO):
    """
    Sets up a logger for the integration service.  Uses a rotating file handler.
    """
    #  Ensure the logs directory exists.
    log_dir = os.path.join(settings.BASE_DIR, 'logs')  # Use the project-level logs dir
    if not os.path.exists(log_dir):
        os.makedirs(log_dir)

    log_file_path = os.path.join(log_dir, 'my_info.log')

    # Create a rotating file handler.  This will create a new log file
    #  every time the log file reaches a certain size, and it will keep
    #  a limited number of old log files.
    handler = logging.handlers.RotatingFileHandler(
        log_file_path,
        maxBytes=10 * 1024 * 1024,  # 10 MB
        backupCount=5,  # Keep 5 backup files
    )

    #  Set up a logging format.  Include a timestamp, log level,
    #  and the name of the logger.
    formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    handler.setFormatter(formatter)

    #  Get the logger for this module.  Use 'integration_service'
    #  as the logger name.
    logger = logging.getLogger('my_info')
    logger.addHandler(handler)
    logger.setLevel(log_level)  # Set the logging level

    return logger


#  Create a global logger instance.  This is what other modules will use.
logger = setup_integration_logger()

# Example usage (in other modules):
# from my_info.myinfo_utils.logging_utils import integration_logger
# integration_logger.info("Starting integration process...")
# integration_logger.error("An error occurred: %s", error_message)