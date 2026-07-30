from __future__ import annotations

from typing import Literal
from uuid import UUID

from argon2 import PasswordHasher
from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel

router = APIRouter()

_password_hasher = PasswordHasher()

# Must match roles_table's seeded rows (FK target of users.role) and the role
# set policies/authz/rbac.rego's rules switch on -- reject an invalid role
# here, with a normal 422, rather than letting it reach the FK constraint and
# surface as an unhandled IntegrityError (500).
Role = Literal["reader", "editor", "admin"]


class UserCreateRequest(BaseModel):
    email: str
    password: str
    role: Role


class UserUpdateRequest(BaseModel):
    email: str | None = None
    role: Role | None = None
    is_active: bool | None = None


def _serialize(user) -> dict:
    # Never include password_hash, failed_login_attempts, or locked_until --
    # those are auth-internal state, not part of the admin-facing user resource.
    return {
        "user_id": str(user.user_id),
        "email": user.email,
        "role": user.role,
        "is_active": user.is_active,
    }


@router.get("/users")
async def list_users(request: Request, limit: int = 50, offset: int = 0):
    services = request.app.state.gateway_services
    users = await services.user_repository.list_all(limit=limit, offset=offset)
    return {"users": [_serialize(user) for user in users]}


@router.get("/users/{user_id}")
async def get_user(user_id: UUID, request: Request):
    services = request.app.state.gateway_services
    user = await services.user_repository.get_by_id(user_id)
    if user is None:
        return JSONResponse({"detail": "user not found"}, status_code=404)
    return _serialize(user)


@router.post("/users", status_code=201)
async def create_user(body: UserCreateRequest, request: Request):
    services = request.app.state.gateway_services
    password_hash = _password_hasher.hash(body.password)
    user = await services.user_repository.create_user(body.email, password_hash, body.role)
    return _serialize(user)


@router.put("/users/{user_id}")
async def update_user(user_id: UUID, body: UserUpdateRequest, request: Request):
    services = request.app.state.gateway_services
    user = await services.user_repository.update_user(
        user_id, email=body.email, role=body.role, is_active=body.is_active
    )
    if user is None:
        return JSONResponse({"detail": "user not found"}, status_code=404)
    return _serialize(user)


@router.delete("/users/{user_id}")
async def delete_user(user_id: UUID, request: Request):
    # MUST be a soft delete (is_active = false) -- never a hard DELETE. A real
    # delete would destroy accounts the traffic generator (or real users) are
    # actively using.
    services = request.app.state.gateway_services
    deactivated = await services.user_repository.soft_delete(user_id)
    if not deactivated:
        return JSONResponse({"detail": "user not found"}, status_code=404)
    return {"detail": "deactivated"}
