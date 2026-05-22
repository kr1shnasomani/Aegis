"""
Pipeline-specific exceptions.
"""

from __future__ import annotations


class ScanNotFoundError(RuntimeError):
    """Raised when a requested scan cannot be found."""


class ScanAlreadyRunningError(RuntimeError):
    """Raised when the same scan is dispatched twice while still running."""


class ScanAlreadyTerminalError(RuntimeError):
    """Raised when a terminal scan is dispatched again."""
