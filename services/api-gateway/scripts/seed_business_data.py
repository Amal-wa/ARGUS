"""Manual, idempotent seed script for business data (documents/orders) and the
broader user pool the traffic generator needs -- complements scripts/seed_users.py
(which only creates the 3 named role-representative accounts).

NOT executed automatically by any startup path -- run explicitly:
    poetry run python scripts/seed_business_data.py
or, against the docker-compose stack:
    docker compose run --rm api-gateway poetry run python scripts/seed_business_data.py
"""
from __future__ import annotations

import asyncio
import os
import random
import sys
from pathlib import Path
from uuid import uuid4

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from argon2 import PasswordHasher
from sqlalchemy import func, insert, select

from app.core.database import build_async_session_factory
from app.core.settings import GatewaySettings
from app.models.tables import documents_table, orders_table, roles_table, users_table

_password_hasher = PasswordHasher()

ROLE_NAMES = ("reader", "editor", "admin")

# 15 reader / 8 editor / 2 admin -- realistic-ish spread for a small org, and
# enough users that per-user access-frequency/distinct-resource features in the
# 20-dim vector are genuinely discriminative rather than constant.
USER_POOL_SPEC = [("reader", 15), ("editor", 8), ("admin", 2)]

DOCUMENT_COUNT = 400
ORDER_COUNT = 400

DEFAULT_PASSWORD = os.getenv("SEED_USER_PASSWORD", "ChangeMe123!")


def _pool_emails() -> list[tuple[str, str]]:
    emails = []
    for role, count in USER_POOL_SPEC:
        for i in range(1, count + 1):
            emails.append((f"{role}{i}@zt.local", role))
    return emails


def _skewed_owner_sequence(owner_ids: list, count: int) -> list:
    """Zipf-ish ownership skew: a few owners hold most of the resources, most
    owners hold few -- a uniform 1-resource-per-N-owners split would make
    per-owner access-frequency/distinct-resource features nearly constant
    across the population, which is zero signal for IsolationForest."""
    weights = [1.0 / (rank + 1) for rank in range(len(owner_ids))]
    return random.choices(owner_ids, weights=weights, k=count)


async def _ensure_user_pool(session_factory) -> list:
    async with session_factory() as session:
        existing_roles = set((await session.execute(select(roles_table.c.role_name))).scalars().all())
        for role_name in ROLE_NAMES:
            if role_name not in existing_roles:
                await session.execute(insert(roles_table).values(role_name=role_name))
        await session.commit()

    password_hash = _password_hasher.hash(DEFAULT_PASSWORD)

    async with session_factory() as session:
        existing_emails = set((await session.execute(select(users_table.c.email))).scalars().all())
        for email, role in _pool_emails():
            if email in existing_emails:
                continue
            await session.execute(
                insert(users_table).values(user_id=uuid4(), email=email, password_hash=password_hash, role=role)
            )
            print(f"created user: {email} ({role})")
        await session.commit()

    async with session_factory() as session:
        user_ids = (await session.execute(select(users_table.c.user_id).order_by(users_table.c.email))).scalars().all()
    return list(user_ids)


async def _seed_documents(session_factory, owner_ids: list) -> None:
    async with session_factory() as session:
        current_count = (await session.execute(select(func.count()).select_from(documents_table))).scalar_one()
    if current_count >= DOCUMENT_COUNT:
        print(f"skip documents: already have {current_count} (>= {DOCUMENT_COUNT})")
        return

    to_create = DOCUMENT_COUNT - current_count
    owners = _skewed_owner_sequence(owner_ids, to_create)
    rows = [
        {
            "document_id": uuid4(),
            "owner_id": owner_id,
            "title": f"Document {current_count + i + 1}",
            "content": f"Seeded placeholder content for document {current_count + i + 1}.",
        }
        for i, owner_id in enumerate(owners)
    ]
    async with session_factory() as session:
        await session.execute(insert(documents_table), rows)
        await session.commit()
    print(f"created {len(rows)} documents (total now {current_count + len(rows)})")


async def _seed_orders(session_factory, owner_ids: list) -> None:
    rng = random.Random(7)
    async with session_factory() as session:
        current_count = (await session.execute(select(func.count()).select_from(orders_table))).scalar_one()
    if current_count >= ORDER_COUNT:
        print(f"skip orders: already have {current_count} (>= {ORDER_COUNT})")
        return

    to_create = ORDER_COUNT - current_count
    owners = _skewed_owner_sequence(owner_ids, to_create)
    statuses = ["pending", "paid", "shipped", "cancelled"]
    rows = [
        {
            "order_id": uuid4(),
            "owner_id": owner_id,
            "status": rng.choice(statuses),
            "amount": round(rng.uniform(5, 500), 2),
        }
        for owner_id in owners
    ]
    async with session_factory() as session:
        await session.execute(insert(orders_table), rows)
        await session.commit()
    print(f"created {len(rows)} orders (total now {current_count + len(rows)})")


async def main() -> None:
    settings = GatewaySettings()
    engine, session_factory = build_async_session_factory(settings.database_url)

    owner_ids = await _ensure_user_pool(session_factory)
    print(f"user pool size: {len(owner_ids)}")

    await _seed_documents(session_factory, owner_ids)
    await _seed_orders(session_factory, owner_ids)

    await engine.dispose()


if __name__ == "__main__":
    asyncio.run(main())
