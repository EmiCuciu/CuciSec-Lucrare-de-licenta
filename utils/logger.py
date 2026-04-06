import os
import sys

from loguru import logger


def setup_logger():
    logger.remove()

    # console
    logger.add(
        sys.stderr,
        level="INFO",
        colorize=True,
        format="<green>{time:YYYY-MM-DD HH:mm:ss}</green> | <level>{level: <8}</level> | <cyan>{name}</cyan>:<cyan>{function}</cyan> - <level>{message}</level>"
    )

    # FILE
    os.makedirs("logs", exist_ok=True)
    logger.add(
        "logs/cucisec.log",
        level="DEBUG",
        rotation="5 MB",
        retention=3,
        enqueue=True,
        format="<green>{time:YYYY-MM-DD HH:mm:ss}</green> | <level>{level: <8}</level> | <cyan>{name}</cyan>:<cyan>{function}</cyan> - <level>{message}</level>"
    )
