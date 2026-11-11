"""Alembic environment. Uses DATABASE_URL_UNPOOLED if set (Neon's direct endpoint: DDL shouldn't go
through the transaction-mode pooler), otherwise DATABASE_URL."""

from __future__ import annotations

import os

from alembic import context
from dotenv import load_dotenv
from sqlalchemy import create_engine

from app import models  # noqa: F401  (registers tables on Base.metadata)
from app.config import normalize_database_url
from app.db import Base

load_dotenv()
target_metadata = Base.metadata


def run_migrations_online() -> None:
    raw = os.getenv("DATABASE_URL_UNPOOLED", "").strip() or os.environ["DATABASE_URL"]
    url = normalize_database_url(raw)
    engine = create_engine(url)
    with engine.connect() as connection:
        context.configure(connection=connection, target_metadata=target_metadata, compare_type=True)
        with context.begin_transaction():
            context.run_migrations()


run_migrations_online()
