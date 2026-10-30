import os

from sqlalchemy import create_engine, inspect, text
from sqlalchemy.orm import DeclarativeBase, sessionmaker


DATABASE_URL = os.getenv("XSS_SENTINEL_DATABASE_URL", "sqlite:///./xss_sentinel.db")
_engine_options = {"connect_args": {"check_same_thread": False, "timeout": 30}} if DATABASE_URL.startswith("sqlite") else {}
engine = create_engine(DATABASE_URL, **_engine_options)
SessionLocal = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)


class Base(DeclarativeBase):
    pass



def ensure_additive_schema():
    patches = {
        "waf_observations": {"vendor": "VARCHAR(120)", "vendors": "TEXT", "signals": "TEXT"},
    }
    with engine.begin() as connection:
        inspector = inspect(connection)
        for table, columns in patches.items():
            if not inspector.has_table(table):
                continue
            existing = {column["name"] for column in inspector.get_columns(table)}
            for name, sql_type in columns.items():
                if name not in existing:
                    connection.execute(text(f"ALTER TABLE {table} ADD COLUMN {name} {sql_type}"))
