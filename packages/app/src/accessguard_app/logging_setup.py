"""Structured JSON logs with delivery/scan context on every line (PLAN.md §7)."""

from __future__ import annotations

import json
import logging
import sys
from typing import Any

CONTEXT_KEYS = (
    "delivery_guid",
    "scan_id",
    "repo_id",
    "head_sha",
    "event",
    "outcome",
    "fingerprint",
)


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        out: dict[str, Any] = {
            "ts": self.formatTime(record),
            "level": record.levelname,
            "logger": record.name,
            "msg": record.getMessage(),
        }
        for k in CONTEXT_KEYS:
            if hasattr(record, k):
                out[k] = getattr(record, k)
        if record.exc_info:
            out["exc"] = self.formatException(record.exc_info)
        return json.dumps(out, default=str)


def configure_logging(level: int = logging.INFO) -> None:
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(JsonFormatter())
    root = logging.getLogger()
    root.handlers = [handler]
    root.setLevel(level)
