from __future__ import annotations

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

# No caching/memoization here on purpose: every caller (app.main's create_app,
# scripts/promote_model.py, scripts/seed_*.py) invokes this exactly once per
# process and threads the returned (engine, session_factory) through
# explicitly (app.state, local variables) -- there is nothing to reuse across
# calls. A prior @lru_cache(maxsize=1) looked like it was caching per-URL, but
# maxsize=1 caches only the single most recent call: a second call with a
# DIFFERENT database_url (e.g. two create_app()s with different test DBs in
# the same process) would silently evict the first engine without disposing
# it, and a later call reusing the first URL would silently build a second,
# separate engine against it. Explicit construction avoids that global,
# implicit state entirely.
def build_async_session_factory(database_url: str):
    engine = create_async_engine(database_url, future=True)
    session_factory = async_sessionmaker(engine, expire_on_commit=False, class_=AsyncSession)
    return engine, session_factory
