from datetime import datetime, timezone

from sqlalchemy import create_engine, event
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship
from sqlalchemy import String, Text, Boolean, Float, DateTime, ForeignKey, Integer

from app.config import DATABASE_URL


class Base(DeclarativeBase):
    pass


# ----- Users -----

class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(primary_key=True)
    email: Mapped[str] = mapped_column(String(255), unique=True, index=True)
    password_hash: Mapped[str] = mapped_column(String(255))
    stripe_customer_id: Mapped[str | None] = mapped_column(String(255), nullable=True)
    stripe_subscription_id: Mapped[str | None] = mapped_column(String(255), nullable=True)
    is_active: Mapped[bool] = mapped_column(Boolean, default=False)  # True after first payment
    max_urls: Mapped[int] = mapped_column(Integer, default=10)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc))

    urls = relationship("MonitoredUrl", back_populates="user", cascade="all, delete-orphan")


# ----- Monitored URLs -----

class MonitoredUrl(Base):
    __tablename__ = "monitored_urls"

    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"))
    label: Mapped[str] = mapped_column(String(255))
    url: Mapped[str] = mapped_column(String(2048))
    check_interval_hours: Mapped[int] = mapped_column(Integer, default=24)
    last_checked_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    last_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
    last_content: Mapped[str | None] = mapped_column(Text, nullable=True)  # stored stripped text for diff
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc))

    user = relationship("User", back_populates="urls")
    changes = relationship("ChangeEvent", back_populates="url", cascade="all, delete-orphan")


# ----- Change Events -----

class ChangeEvent(Base):
    __tablename__ = "change_events"

    id: Mapped[int] = mapped_column(primary_key=True)
    url_id: Mapped[int] = mapped_column(ForeignKey("monitored_urls.id"))
    detected_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc))
    old_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
    new_hash: Mapped[str] = mapped_column(String(64))
    old_content: Mapped[str | None] = mapped_column(Text, nullable=True)  # snapshot before change
    new_content: Mapped[str | None] = mapped_column(Text, nullable=True)   # snapshot after change
    diff_summary: Mapped[str | None] = mapped_column(Text, nullable=True)  # human-readable summary
    alerted: Mapped[bool] = mapped_column(Boolean, default=False)

    url = relationship("MonitoredUrl", back_populates="changes")


# ----- Database Setup -----

def get_engine():
    return create_engine(DATABASE_URL, connect_args={"check_same_thread": False})


def init_db(engine=None):
    if engine is None:
        engine = get_engine()
    Base.metadata.create_all(engine)
    return engine


def get_session(engine=None):
    if engine is None:
        engine = get_engine()
    from sqlalchemy.orm import Session
    return Session(engine)
