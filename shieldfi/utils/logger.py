"""Tiny logger — keeps output readable for beginners."""
import logging

def get_logger(name: str = "shieldfi") -> logging.Logger:
    logger = logging.getLogger(name)
    if not logger.handlers:
        h = logging.StreamHandler()
        h.setFormatter(logging.Formatter("%(levelname)s | %(message)s"))
        logger.addHandler(h)
        logger.setLevel(logging.INFO)
    return logger
