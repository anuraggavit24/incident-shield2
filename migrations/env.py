"""Alembic environment. Uses DATABASE_URL (only that setting is needed to migrate)."""

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
    url = normalize_database_url(os.environ["DATABASE_URL"])
    engine = create_engine(url)
    with engine.connect() as connection:
        context.configure(connection=connection, target_metadata=target_metadata, compare_type=True)
        with context.begin_transaction():
            context.run_migrations()


run_migrations_online()
