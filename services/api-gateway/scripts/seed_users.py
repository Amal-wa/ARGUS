"""Manual, idempotent seed script for the three baseline test/demo users.

NOT executed automatically by any startup path -- run explicitly:
    poetry run python scripts/seed_users.py
or, against the docker-compose stack:
    docker compose run --rm api-gateway poetry run python scripts/seed_users.py
"""
from __future__ import annotations

import asyncio
import os
import sys
from pathlib import Path
from uuid import uuid4

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from argon2 import PasswordHasher
from sqlalchemy import insert, select

from app.core.database import build_async_session_factory
from app.core.settings import GatewaySettings
from app.models.tables import roles_table, users_table

_password_hasher = PasswordHasher()

ROLE_NAMES = ("reader", "editor", "admin")

SEED_USERS = [
    {"email": "reader@zt.local", "role": "reader"},
    {"email": "editor@zt.local", "role": "editor"},
    {"email": "admin@zt.local", "role": "admin"},
]

# Documented default -- override via SEED_USER_PASSWORD for anything beyond local dev.
DEFAULT_PASSWORD = os.getenv("SEED_USER_PASSWORD", "ChangeMe123!")


async def main() -> None:
    settings = GatewaySettings()
    engine, session_factory = build_async_session_factory(settings.database_url)

    async with session_factory() as session:
        existing_roles = set((await session.execute(select(roles_table.c.role_name))).scalars().all())
        for role_name in ROLE_NAMES:
            if role_name not in existing_roles:
                await session.execute(insert(roles_table).values(role_name=role_name))
                print(f"created role: {role_name}")
        await session.commit()

    password_hash = _password_hasher.hash(DEFAULT_PASSWORD)

    async with session_factory() as session:
        existing_emails = set((await session.execute(select(users_table.c.email))).scalars().all())
        for seed_user in SEED_USERS:
            if seed_user["email"] in existing_emails:
                print(f"skip (already exists): {seed_user['email']}")
                continue
            await session.execute(
                insert(users_table).values(
                    user_id=uuid4(),
                    email=seed_user["email"],
                    password_hash=password_hash,
                    role=seed_user["role"],
                )
            )
            print(f"created user: {seed_user['email']} ({seed_user['role']})")
        await session.commit()

    await engine.dispose()


if __name__ == "__main__":
    asyncio.run(main())
