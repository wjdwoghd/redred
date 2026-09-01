"""Application logging configuration for the scanner CLI."""

from __future__ import annotations

import logging


def configure_logging(verbose: bool = False) -> None:
    """Configure concise console logs without exposing captured HTTP data."""

    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
        force=True,
    )
    # Third-party debug logs can contain request metadata. Keep them quiet even
    # when scanner-level verbose logging is enabled.
    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("httpcore").setLevel(logging.WARNING)
    logging.getLogger("openai").setLevel(logging.WARNING)

