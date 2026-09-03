from __future__ import annotations

import os
from pathlib import Path

from dotenv import load_dotenv

load_dotenv(Path(__file__).resolve().parent.parent / ".env")


def _required(name: str) -> str:
    value = os.environ.get(name)
    if not value:
        raise RuntimeError(f"Missing required env var: {name}")
    return value


DATABASE_URL = _required("DATABASE_URL")
ALLOWED_DOMAINS = {
    d.strip().lower() for d in _required("ALLOWED_DOMAINS").split(",") if d.strip()
}
SENSITIVE_READ_THRESHOLD = int(os.environ.get("SENSITIVE_READ_THRESHOLD", "3"))
SENSITIVE_READ_WINDOW_SECONDS = int(
    os.environ.get("SENSITIVE_READ_WINDOW_SECONDS", "300")
)
ANALYZER_BATCH_SIZE = int(os.environ.get("ANALYZER_BATCH_SIZE", "100"))
ANALYZER_POLL_SECONDS = int(os.environ.get("ANALYZER_POLL_SECONDS", "5"))
LOG_LEVEL = os.environ.get("LOG_LEVEL", "INFO").upper()
