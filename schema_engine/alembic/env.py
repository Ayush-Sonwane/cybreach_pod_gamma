import os
import sys
from logging.config import fileConfig

from alembic import context
from sqlalchemy import engine_from_config, pool

# ==============================================================================
# IMPORTANT: PATH SETUP (MUST BE BEFORE ANY 'app' IMPORTS)
# This adds the project root (cybreach_pod_gamma) to Python's import path.
# Without this, 'from app...' imports will fail within Alembic.
# ==============================================================================
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

# ==============================================================================
# NOW IMPORT APP OBJECTS
# ==============================================================================
# The imports below depend on the path setup above.
from app.database import Base
# We must import our model here so Alembic can detect it for autogeneration.
# Make sure app/models/custom_ocsf_class.py NO LONGER has line 1:
# "from app.models.custom_ocsf_class import CustomOcsfClass" (The Circular Import)
from app.models.custom_ocsf_class import CustomOcsfClass


# ==============================================================================
# STANDARD ALEMBIC CONFIGURATION
# ==============================================================================
config = context.config

# Interpret the config file for Python logging.
if config.config_file_name:
    fileConfig(config.config_file_name)

# Set target metadata for 'autogenerate' support.
# target_metadata is the Base object's metadata collection.
target_metadata = Base.metadata


def run_migrations_offline() -> None:
    """Run migrations in 'offline' mode.

    This configures the context with just a URL and not an Engine.
    By skipping Engine creation we don't even need a DBAPI to be available.
    """
    url = config.get_main_option("sqlalchemy.url")
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
    )

    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    """Run migrations in 'online' mode.

    In this scenario we need to create an Engine and associate a connection
    with the context.
    """
    connectable = engine_from_config(
        config.get_section(config.config_ini_section, {}),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )

    with connectable.connect() as connection:
        context.configure(
            connection=connection, target_metadata=target_metadata
        )

        with context.begin_transaction():
            context.run_migrations()


# ==============================================================================
# EXECUTION ENTRY POINT
# ==============================================================================
if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()