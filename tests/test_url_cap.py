"""Plan URL cap: new accounts get 100; migrate raises the old default of 10."""

import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ.setdefault("SECRET_KEY", "x" * 64)

from sqlalchemy import create_engine, text

from app.models import (
    DEFAULT_MAX_URLS,
    PREVIOUS_PLAN_MAX_URLS,
    Base,
    User,
    get_session,
    migrate_schema,
)


def _engine():
    tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
    tmp.close()
    engine = create_engine(
        f"sqlite:///{tmp.name}",
        connect_args={"check_same_thread": False},
    )
    return engine, tmp.name


def test_new_user_gets_current_plan_cap():
    engine, path = _engine()
    try:
        Base.metadata.create_all(engine)
        db = get_session(engine)
        user = User(email="cap@test.local", password_hash="x", is_active=True)
        db.add(user)
        db.commit()
        db.refresh(user)
        assert user.max_urls == DEFAULT_MAX_URLS
        assert DEFAULT_MAX_URLS == 100
        db.close()
    finally:
        os.unlink(path)


def test_migrate_raises_old_default_and_leaves_custom_caps():
    engine, path = _engine()
    try:
        Base.metadata.create_all(engine)
        db = get_session(engine)
        old = User(email="old@test.local", password_hash="x", is_active=True,
                   max_urls=PREVIOUS_PLAN_MAX_URLS)
        custom_low = User(email="low@test.local", password_hash="x", is_active=True,
                          max_urls=5)
        custom_high = User(email="high@test.local", password_hash="x", is_active=True,
                           max_urls=200)
        already = User(email="already@test.local", password_hash="x", is_active=True,
                       max_urls=DEFAULT_MAX_URLS)
        db.add_all([old, custom_low, custom_high, already])
        db.commit()
        db.close()

        applied = migrate_schema(engine)
        assert any("users.max_urls" in item for item in applied), applied

        db = get_session(engine)
        by_email = {u.email: u.max_urls for u in db.query(User).all()}
        assert by_email["old@test.local"] == DEFAULT_MAX_URLS
        assert by_email["low@test.local"] == 5
        assert by_email["high@test.local"] == 200
        assert by_email["already@test.local"] == DEFAULT_MAX_URLS
        db.close()

        second = migrate_schema(engine)
        assert not any("users.max_urls" in item for item in second), second
    finally:
        os.unlink(path)


def test_migrate_skips_users_table_without_max_urls_column():
    engine, path = _engine()
    try:
        with engine.begin() as conn:
            conn.execute(text("""
                CREATE TABLE users (
                    id INTEGER PRIMARY KEY,
                    email VARCHAR(255) UNIQUE,
                    password_hash VARCHAR(255)
                )
            """))
            conn.execute(text(
                "INSERT INTO users (email, password_hash) VALUES ('pre@test.local', 'x')"
            ))
        applied = migrate_schema(engine)
        assert not any("users.max_urls (raised" in item for item in applied), applied
    finally:
        os.unlink(path)
