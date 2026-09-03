from __future__ import annotations

import psycopg
from psycopg.rows import dict_row

from . import config


def connect() -> psycopg.Connection:
    return psycopg.connect(config.DATABASE_URL, row_factory=dict_row, autocommit=False)
