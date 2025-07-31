"""
Logging utilities for fraud detection system.
"""

import uuid
import logging
import logging.config
from typing import Dict, Any
from contextvars import ContextVar

# Context variable for correlation ID
correlation_id_ctx: ContextVar[str] = ContextVar('correlation_id', default='')

def get_correlation_id() -> str:
    """Get the current correlation ID."""
    correlation_id = correlation_id_ctx.get()
    if not correlation_id:
        correlation_id = str(uuid.uuid4())
        correlation_id_ctx.set(correlation_id)
    return correlation_id

def set_correlation_id(correlation_id: str) -> None:
    """Set the correlation ID for the current context."""
    correlation_id_ctx.set(correlation_id)

def setup_logging(log_level: str = "INFO") -> None:
    """
    Setup structured logging configuration.
    
    Args:
        log_level: Logging level
    """
    logging_config = {
        "version": 1,
        "disable_existing_loggers": False,
        "formatters": {
            "standard": {
                "format": "%(asctime)s [%(levelname)s] %(name)s: %(message)s"
            },
            "structured": {
                "format": "%(asctime)s [%(levelname)s] %(name)s [%(correlation_id)s]: %(message)s"
            }
        },
        "handlers": {
            "default": {
                "level": log_level,
                "formatter": "structured",
                "class": "logging.StreamHandler",
                "stream": "ext://sys.stdout"
            }
        },
        "loggers": {
            "": {
                "handlers": ["default"],
                "level": log_level,
                "propagate": False
            }
        }
    }
    
    logging.config.dictConfig(logging_config)

class CorrelationIdFilter(logging.Filter):
    """Filter to add correlation ID to log records."""
    
    def filter(self, record):
        record.correlation_id = get_correlation_id()
        return True

# Add the filter to all handlers
def add_correlation_filter():
    """Add correlation ID filter to all loggers."""
    for logger in logging.Logger.manager.loggerDict.values():
        if isinstance(logger, logging.Logger):
            for handler in logger.handlers:
                handler.addFilter(CorrelationIdFilter())
