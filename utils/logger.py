import os
import sys

from loguru import logger


def firewall_format(record):
    fmt = "<green>{time:YYYY-MM-DD HH:mm:ss}</green> | <level>{level: <8}</level> | <cyan>{name}</cyan>:<cyan>{function}</cyan> - "

    msg = record["message"]

    if "[BOOT]" in msg:
        fmt += "<yellow><bold>{message}</bold></yellow>\n"
    elif "[INTERCEPTOR]" in msg:
        fmt += "<light-black><bold>{message}</bold></light-black>\n"
    elif "[PACKET]" in msg:
        fmt += "<light-yellow>{message}</light-yellow>\n"
    elif "[SIGNAL]" in msg:
        fmt += "<red><bold>{message}</bold></red>\n"
    elif "HONEYPORT" in msg or "DPI" in msg:
        fmt += "<light-red><bold>{message}</bold></light-red>\n"
    else:
        fmt += "<level>{message}</level>\n"

    return fmt


def setup_logger():
    logger.remove()

    logger.add(
        sys.stderr,
        level="INFO",
        colorize=True,
        format=firewall_format
    )

    os.makedirs("logs", exist_ok=True)
    logger.add(
        "logs/cucisec.log",
        level="DEBUG",
        rotation="5 MB",
        retention=3,
        enqueue=True,
        colorize=True,
        format="{time:YYYY-MM-DD HH:mm:ss} | {level: <8} | {name}:{function} - {message}"
    )