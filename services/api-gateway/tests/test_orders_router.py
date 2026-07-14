from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from datetime import datetime, timezone
from decimal import Decimal
from types import SimpleNamespace
from uuid import UUID, uuid4

from fastapi import FastAPI

from app.core.repositories import OrderRecord
from app.core.request_matching import resolve_route_pattern
from app.middleware.context import RequestContext
from app.routers.orders import (
    OrderCreateRequest,
    OrderUpdateRequest,
    create_order,
    delete_order,
    get_order,
    list_orders,
    router as orders_router,
    update_order,
)


@dataclass(slots=True)
class FakeOrderRepository:
    records: dict[UUID, OrderRecord] = field(default_factory=dict)

    async def list_all(self, *, limit=50, offset=0):
        active = [r for r in self.records.values() if not r.is_deleted]
        return active[offset : offset + limit]

    async def get(self, order_id):
        record = self.records.get(order_id)
        return None if record is None or record.is_deleted else record

    async def create(self, owner_id, status, amount):
        order_id = uuid4()
        now = datetime.now(timezone.utc)
        record = OrderRecord(
            order_id=order_id,
            owner_id=owner_id,
            status=status,
            amount=Decimal(str(amount)),
            created_at=now,
            updated_at=now,
            is_deleted=False,
        )
        self.records[order_id] = record
        return record

    async def update(self, order_id, *, status=None, amount=None):
        record = self.records.get(order_id)
        if record is None or record.is_deleted:
            return None
        if status is not None:
            record.status = status
        if amount is not None:
            record.amount = Decimal(str(amount))
        record.updated_at = datetime.now(timezone.utc)
        return record

    async def soft_delete(self, order_id):
        record = self.records.get(order_id)
        if record is None or record.is_deleted:
            return False
        record.is_deleted = True
        return True


def _request(repo, claims_subject=None):
    services = SimpleNamespace(order_repository=repo)
    app = SimpleNamespace(state=SimpleNamespace(gateway_services=services))
    context = RequestContext(claims=SimpleNamespace(subject=claims_subject or uuid4()))
    return SimpleNamespace(app=app, state=SimpleNamespace(gateway_context=context))


def test_create_and_get_order():
    async def _run():
        repo = FakeOrderRepository()
        owner_id = uuid4()
        request = _request(repo, claims_subject=owner_id)

        created = await create_order(OrderCreateRequest(status="pending", amount=Decimal("19.99")), request)
        assert created["owner_id"] == str(owner_id)
        assert created["amount"] == "19.99"

        fetched = await get_order(UUID(created["order_id"]), request)
        assert fetched["status"] == "pending"

    asyncio.run(_run())


def test_get_missing_order_returns_404():
    async def _run():
        repo = FakeOrderRepository()
        response = await get_order(uuid4(), _request(repo))
        assert response.status_code == 404

    asyncio.run(_run())


def test_update_order():
    async def _run():
        repo = FakeOrderRepository()
        request = _request(repo)
        created = await create_order(OrderCreateRequest(amount=Decimal("10.00")), request)
        order_id = UUID(created["order_id"])

        updated = await update_order(order_id, OrderUpdateRequest(status="shipped"), request)

        assert updated["status"] == "shipped"

    asyncio.run(_run())


def test_update_missing_order_returns_404():
    async def _run():
        repo = FakeOrderRepository()
        response = await update_order(uuid4(), OrderUpdateRequest(status="shipped"), _request(repo))
        assert response.status_code == 404

    asyncio.run(_run())


def test_delete_order_soft_deletes_and_subsequent_get_404s():
    async def _run():
        repo = FakeOrderRepository()
        request = _request(repo)
        created = await create_order(OrderCreateRequest(amount=Decimal("5.00")), request)
        order_id = UUID(created["order_id"])

        delete_response = await delete_order(order_id, request)
        assert delete_response == {"detail": "deleted"}

        get_response = await get_order(order_id, request)
        assert get_response.status_code == 404

        assert order_id in repo.records
        assert repo.records[order_id].is_deleted is True

    asyncio.run(_run())


def test_delete_missing_order_returns_404():
    async def _run():
        repo = FakeOrderRepository()
        response = await delete_order(uuid4(), _request(repo))
        assert response.status_code == 404

    asyncio.run(_run())


def test_list_orders_excludes_deleted():
    async def _run():
        repo = FakeOrderRepository()
        request = _request(repo)
        created1 = await create_order(OrderCreateRequest(amount=Decimal("1.00")), request)
        await create_order(OrderCreateRequest(amount=Decimal("2.00")), request)
        await delete_order(UUID(created1["order_id"]), request)

        result = await list_orders(request)

        amounts = [o["amount"] for o in result["orders"]]
        assert amounts == ["2.00"]

    asyncio.run(_run())


def test_create_order_owner_id_matches_authenticated_subject():
    async def _run():
        repo = FakeOrderRepository()
        subject = uuid4()
        request = _request(repo, claims_subject=subject)

        created = await create_order(OrderCreateRequest(amount=Decimal("1.00")), request)

        assert created["owner_id"] == str(subject)

    asyncio.run(_run())


def test_route_pattern_resolves_to_parameterized_path():
    app = FastAPI()
    app.include_router(orders_router)

    scope = {"type": "http", "method": "GET", "path": "/orders/123", "headers": []}
    request = SimpleNamespace(app=app, scope=scope, url=SimpleNamespace(path="/orders/123"))

    assert resolve_route_pattern(request) == "/orders/{order_id}"
