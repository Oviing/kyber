from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from kyber.config import settings
from kyber.models import Base

# SQLite fallback for local dev/tests without postgres.
# StaticPool keeps a single shared :memory: DB across sessions (needed for tests).
_connect_args = {"check_same_thread": False} if settings.database_url.startswith("sqlite") else {}
_pool = StaticPool if settings.database_url == "sqlite:///:memory:" else None
engine = create_engine(settings.database_url, future=True,
                       connect_args=_connect_args, poolclass=_pool) if _pool else create_engine(
    settings.database_url, future=True, connect_args=_connect_args)
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)


def init_db() -> None:
    Base.metadata.create_all(bind=engine)
    _ensure_archive_columns()


def _ensure_archive_columns() -> None:
    """Add archive columns to pre-existing DBs (create_all skips existing tables)."""
    from sqlalchemy import inspect, text

    try:
        existing = {c["name"] for c in inspect(engine).get_columns("targets")}
    except Exception:
        return
    wanted = {
        "archive_path": "TEXT",
        "archive_sha256": "VARCHAR(64)",
        "archive_name": "VARCHAR(256)",
    }
    for name, ddl in wanted.items():
        if name not in existing:
            try:
                with engine.begin() as conn:
                    conn.execute(text(f"ALTER TABLE targets ADD COLUMN {name} {ddl}"))
            except Exception:
                pass


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
