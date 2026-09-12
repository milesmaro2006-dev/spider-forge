from __future__ import annotations

from contextlib import contextmanager
from pathlib import Path
from typing import Iterator

from sqlalchemy import create_engine
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session, sessionmaker

from spiderforge.config.defaults import DEFAULT_DB_PATH
from spiderforge.database.models import Base

_ENGINE: Engine | None = None
_SESSION_FACTORY: sessionmaker | None = None
_DB_PATH: Path | None = None


def init_db(db_path: Path | None = None) -> Engine:
    global _ENGINE, _SESSION_FACTORY, _DB_PATH

    target = db_path or DEFAULT_DB_PATH
    target.parent.mkdir(parents=True, exist_ok=True)

    _ENGINE = create_engine(f"sqlite:///{target}", future=True)
    Base.metadata.create_all(_ENGINE)
    _SESSION_FACTORY = sessionmaker(bind=_ENGINE, expire_on_commit=False, future=True)
    _DB_PATH = target
    return _ENGINE


def get_engine() -> Engine:
    if _ENGINE is None:
        return init_db()
    return _ENGINE


@contextmanager
def session_scope() -> Iterator[Session]:
    if _SESSION_FACTORY is None:
        init_db()
    assert _SESSION_FACTORY is not None
    session = _SESSION_FACTORY()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


def get_db_path() -> Path:
    return _DB_PATH or DEFAULT_DB_PATH