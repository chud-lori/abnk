import logging
import logging.handlers
import os
from django.conf import settings

def setup_logger(log_level=logging.INFO):
    """
    Sets up a logger for the integration service.  Uses a rotating file handler.
    """
    log_dir = os.path.join(settings.BASE_DIR, 'logs')
    if not os.path.exists(log_dir):
        os.makedirs(log_dir)

    log_file_path = os.path.join(log_dir, 'my_info.log')

    handler = logging.handlers.RotatingFileHandler(
        log_file_path,
        maxBytes=10 * 1024 * 1024,  # 10 MB
        backupCount=5,  # Keep 5 backup files
    )

    formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    handler.setFormatter(formatter)

    logger = logging.getLogger('my_info')
    logger.addHandler(handler)
    logger.setLevel(log_level)

    return logger

logger = setup_logger()
