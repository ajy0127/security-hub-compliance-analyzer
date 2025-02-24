"""
Logging utilities for the SecurityHub SOC2 Analyzer.

This module provides structured logging functionality with context information
like finding IDs, account IDs, and request IDs for better traceability.
"""

import json
import logging
import os
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, Optional

# Configure the base logger
logger = logging.getLogger(__name__)


class ContextLogger:
    """
    Logger that adds context information to log messages.

    Maintains a context dictionary with information like:
    - request_id: Unique ID for tracing a request across log entries
    - account_id: AWS account ID for cross-account context
    - finding_id: SecurityHub finding ID for finding-specific logs
    - function_name: Lambda function name
    - function_version: Lambda function version

    This makes it easier to trace related log entries and debug issues.
    """

    def __init__(self, name: str, level: int = logging.INFO):
        """
        Initialize the context logger.

        Args:
            name: Logger name (usually __name__ from the calling module)
            level: Logging level
        """
        self.logger = logging.getLogger(name)
        self.logger.setLevel(level)

        # Create a UUID for this logger instance
        self.context = {
            "request_id": str(uuid.uuid4()),
            "start_time": datetime.now(timezone.utc).isoformat(),
            "function_name": os.environ.get("AWS_LAMBDA_FUNCTION_NAME", "local"),
            "function_version": os.environ.get("AWS_LAMBDA_FUNCTION_VERSION", "local"),
        }

    def add_context(self, **kwargs) -> None:
        """
        Add context to the logger.

        Args:
            **kwargs: Context key-value pairs to add
        """
        self.context.update(kwargs)

    def with_finding(self, finding_id: str, account_id: Optional[str] = None) -> None:
        """
        Add finding-specific context.

        Args:
            finding_id: SecurityHub finding ID
            account_id: AWS account ID (if available)
        """
        self.context["finding_id"] = finding_id
        if account_id:
            self.context["account_id"] = account_id

    def with_account(self, account_id: str) -> None:
        """
        Add account-specific context.

        Args:
            account_id: AWS account ID
        """
        self.context["account_id"] = account_id

    def _format_message(
        self, message: str, extra: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Format a log message with context.

        Args:
            message: The log message
            extra: Extra context for this specific log message

        Returns:
            Dictionary containing the formatted log entry
        """
        log_entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "message": message,
            "context": self.context.copy(),
        }

        if extra:
            log_entry["extra"] = extra

        return log_entry

    def info(self, message: str, **kwargs) -> None:
        """
        Log an info message with context.

        Args:
            message: The log message
            **kwargs: Extra context for this specific log message
        """
        self.logger.info(json.dumps(self._format_message(message, kwargs)))

    def error(self, message: str, **kwargs) -> None:
        """
        Log an error message with context.

        Args:
            message: The log message
            **kwargs: Extra context for this specific log message
        """
        self.logger.error(json.dumps(self._format_message(message, kwargs)))

    def warning(self, message: str, **kwargs) -> None:
        """
        Log a warning message with context.

        Args:
            message: The log message
            **kwargs: Extra context for this specific log message
        """
        self.logger.warning(json.dumps(self._format_message(message, kwargs)))

    def debug(self, message: str, **kwargs) -> None:
        """
        Log a debug message with context.

        Args:
            message: The log message
            **kwargs: Extra context for this specific log message
        """
        self.logger.debug(json.dumps(self._format_message(message, kwargs)))

    def critical(self, message: str, **kwargs) -> None:
        """
        Log a critical message with context.

        Args:
            message: The log message
            **kwargs: Extra context for this specific log message
        """
        self.logger.critical(json.dumps(self._format_message(message, kwargs)))


def get_logger(name: str, level: int = logging.INFO) -> ContextLogger:
    """
    Get a configured context logger.

    Args:
        name: Logger name (usually __name__ from the calling module)
        level: Logging level

    Returns:
        Configured context logger
    """
    return ContextLogger(name, level)
