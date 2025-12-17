import logging
import traceback
from datetime import datetime

def setup_logger(verbose=False):
    logger = logging.getLogger("CEX-NetScan")
    logger.setLevel(logging.INFO)

    # Avoid duplicate handlers
    if logger.handlers:
        return logger

    # File handler (always enabled)
    file_handler = logging.FileHandler("cex_netscan.log")
    file_handler.setFormatter(
        logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")
    )
    logger.addHandler(file_handler)

    # Console handler (only if verbose)
    if verbose:
        console_handler = logging.StreamHandler()
        console_handler.setFormatter(
            logging.Formatter("%(levelname)s - %(message)s")
        )
        logger.addHandler(console_handler)

    return logger


def log_error(error, context=""):
    """Log unexpected errors safely"""
    logger = logging.getLogger("CEX-NetScan")
    message = f"{context}: {str(error)}" if context else str(error)
    logger.error(message)
    logger.error(traceback.format_exc())


def log_scan(scan_type, details):
    """Log scan execution"""
    logger = logging.getLogger("CEX-NetScan")
    logger.info(f"Scan executed: {scan_type}")
    logger.info(f"Details: {details}")
