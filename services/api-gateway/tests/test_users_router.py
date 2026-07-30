from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from types import SimpleNamespace
from uuid import UUID, uuid4

import pytest
from fastapi import FastAPI
from pydantic import ValidationError

from app.core.repositories import UserRecord
from app.core.request_matching import resolve_route_pattern
from app.middleware.context import RequestContext
from app.routers.users import (
    UserCreateRequest,
    UserUpdateRequest,
    create_user,
    delete_user,
    get_user,
    list_users,
    router as users_router,
    update_user,
)


@dataclass(slots=True)
class FakeUserAdminRepository:
    records: dict[UUID, UserRecord] = field(default_factory=dict)

    async def list_all(self, *, limit=50, offset=0):
        return list(self.records.values())[offset : offset + limit]

    async def get_by_id(self, user_id):
        return self.records.get(user_id)

    async def create_user(self, email, password_hash, role):
        user_id = uuid4()
        record = UserRecord(
            user_id=user_id,
            email=email,
            password_hash=password_hash,
            role=role,
            is_active=True,
            failed_login_attempts=0,
            locked_until=None,
        )
        self.records[user_id] = record
        return record

    async def update_user(self, user_id, *, email=None, role=None, is_active=None):
        record = self.records.get(user_id)
        if record is None:
            return None
        if email is not None:
            record.email = email
        if role is not None:
            record.role = role
        if is_active is not None:
            record.is_active = is_active
        return record

    async def soft_delete(self, user_id):
        record = self.records.get(user_id)
        if record is None:
            return False
        record.is_active = False
        return True


def _request(repo):
    services = SimpleNamespace(user_repository=repo)
    app = SimpleNamespace(state=SimpleNamespace(gateway_services=services))
    context = RequestContext(claims=SimpleNamespace(subject=uuid4()))
    return SimpleNamespace(app=app, state=SimpleNamespace(gateway_context=context))


def test_create_and_get_user():
    async def _run():
        repo = FakeUserAdminRepository()
        request = _request(repo)

        created = await create_user(UserCreateRequest(email="a@zt.local", password="pw", role="reader"), request)
        assert created["email"] == "a@zt.local"
        assert created["role"] == "reader"

        fetched = await get_user(UUID(created["user_id"]), request)
        assert fetched["email"] == "a@zt.local"

    asyncio.run(_run())


def test_get_missing_user_returns_404():
    async def _run():
        repo = FakeUserAdminRepository()
        response = await get_user(uuid4(), _request(repo))
        assert response.status_code == 404

    asyncio.run(_run())


def test_update_user():
    async def _run():
        repo = FakeUserAdminRepository()
        request = _request(repo)
        created = await create_user(UserCreateRequest(email="a@zt.local", password="pw", role="reader"), request)
        user_id = UUID(created["user_id"])

        updated = await update_user(user_id, UserUpdateRequest(role="editor"), request)

        assert updated["role"] == "editor"

    asyncio.run(_run())


def test_update_missing_user_returns_404():
    async def _run():
        repo = FakeUserAdminRepository()
        response = await update_user(uuid4(), UserUpdateRequest(role="editor"), _request(repo))
        assert response.status_code == 404

    asyncio.run(_run())


def test_delete_user_soft_deletes_and_row_still_exists():
    async def _run():
        repo = FakeUserAdminRepository()
        request = _request(repo)
        created = await create_user(UserCreateRequest(email="a@zt.local", password="pw", role="reader"), request)
        user_id = UUID(created["user_id"])

        delete_response = await delete_user(user_id, request)
        assert delete_response == {"detail": "deactivated"}

        # Row still exists (soft delete, not a hard delete).
        assert user_id in repo.records
        assert repo.records[user_id].is_active is False

        fetched = await get_user(user_id, request)
        assert fetched["is_active"] is False

    asyncio.run(_run())


def test_delete_missing_user_returns_404():
    async def _run():
        repo = FakeUserAdminRepository()
        response = await delete_user(uuid4(), _request(repo))
        assert response.status_code == 404

    asyncio.run(_run())


def test_responses_never_leak_password_hash_or_lockout_state():
    async def _run():
        repo = FakeUserAdminRepository()
        request = _request(repo)

        created = await create_user(UserCreateRequest(email="a@zt.local", password="pw", role="reader"), request)
        fetched = await get_user(UUID(created["user_id"]), request)
        listed = await list_users(request)

        for payload in (created, fetched, *listed["users"]):
            assert "password_hash" not in payload
            assert "failed_login_attempts" not in payload
            assert "locked_until" not in payload

    asyncio.run(_run())


def test_create_user_rejects_role_outside_roles_table():
    with pytest.raises(ValidationError):
        UserCreateRequest(email="a@zt.local", password="pw", role="superuser")


def test_update_user_rejects_role_outside_roles_table():
    with pytest.raises(ValidationError):
        UserUpdateRequest(role="superuser")


def test_route_pattern_resolves_to_parameterized_path():
    app = FastAPI()
    app.include_router(users_router)

    scope = {"type": "http", "method": "GET", "path": "/users/123", "headers": []}
    request = SimpleNamespace(app=app, scope=scope, url=SimpleNamespace(path="/users/123"))

    assert resolve_route_pattern(request) == "/users/{user_id}"
