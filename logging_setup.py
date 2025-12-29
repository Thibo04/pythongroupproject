###############################
# File: logging_setup.py
# Purpose:
#   Provides a single, reusable helper function (get_logger) to configure logging
#   consistently across all modules in the project.
#
#   - Ensures every module writes logs in the same format and location (logs/ folder)
#   - Prevents duplicated log lines by avoiding multiple handlers on the same logger
#   - Makes debugging and reporting easier (important for documentation + grading)
###############################

"""
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

    # Determine the directory of this file and create the logs directory there.
    base_dir = os.path.dirname(os.path.abspath(__file__))
    log_dir = os.path.join(base_dir, "logs")
    os.makedirs(log_dir, exist_ok=True)

    # Fetch an existing logger (if already created) or create a new one.
    logger = logging.getLogger(name)
    logger.setLevel(level)

    # Avoid adding multiple file handlers to the same logger.
    if not logger.handlers:
        formatter = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")
        file_path = os.path.join(log_dir, filename)
        # FileHandler will create the file if it does not exist.
        # Logs are appended by default (standard logging behavior).
        file_handler = logging.FileHandler(file_path)
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)

    return logger
