"""
logging_setup.py
Helper module to configure loggers in a consistent way across the project.
To use this in your scripts, import the `get_logger` function and create
a logger at module level:

    from logging_setup import get_logger
    logger = get_logger(__name__, "my_module.log")

You can then call logger.info(), logger.warning(), etc., wherever you need
to record events.  Log files are written into a `logs` directory in the
project root.

This module ensures that each logger only adds a single file handler,
so that repeated calls do not duplicate log output.
"""

import logging
import os

def get_logger(name: str, filename: str, level: int = logging.INFO) -> logging.Logger:
    """
    Create and return a configured logger writing to a file in the logs directory.

    Parameters
    ----------
    name : str
        Name of the logger, typically __name__ of the importing module.
    filename : str
        Name of the log file (e.g. 'firewall_simulation.log').
    level : int, optional
        Logging level. Defaults to logging.INFO.

    Returns
    -------
    logging.Logger
        The configured logger. Subsequent calls with the same name
        will return the same logger instance without adding additional handlers.
    """
    # Determine the base directory of this file and create the logs directory
    base_dir = os.path.dirname(os.path.abspath(__file__))
    log_dir = os.path.join(base_dir, "logs")
    os.makedirs(log_dir, exist_ok=True)

    logger = logging.getLogger(name)
    logger.setLevel(level)

    # Avoid adding multiple handlers if the logger already has handlers
    if not logger.handlers:
        formatter = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")
        file_path = os.path.join(log_dir, filename)
        file_handler = logging.FileHandler(file_path)
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)

    return logger
