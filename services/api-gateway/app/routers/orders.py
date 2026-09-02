from __future__ import annotations

from datetime import datetime
from decimal import Decimal
from uuid import UUID

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from app.schemas.common import ErrorDetail

router = APIRouter(tags=["orders"])


class OrderCreateRequest(BaseModel):
    status: str = "pending"
    amount: Decimal


class OrderUpdateRequest(BaseModel):
    status: str | None = None
    amount: Decimal | None = None


class OrderResponse(BaseModel):
    order_id: UUID
    owner_id: UUID
    status: str
    amount: Decimal
    created_at: datetime
    updated_at: datetime


class OrderListResponse(BaseModel):
    orders: list[OrderResponse]


class DeletedResponse(BaseModel):
    detail: str


def _serialize(order) -> dict:
    return {
        "order_id": str(order.order_id),
        "owner_id": str(order.owner_id),
        "status": order.status,
        "amount": str(order.amount),
        "created_at": order.created_at.isoformat(),
        "updated_at": order.updated_at.isoformat(),
    }


# Ownership is deliberately NOT enforced here -- see the identical note in
# app/routers/documents.py. RBAC (via OPA) is the only authorization check;
# "accessing orders you don't own" must stay observable in the traffic for the
# ML pipeline to learn, not be silently blocked at the handler level.


@router.get(
    "/orders",
    response_model=OrderListResponse,
    summary="List orders",
    description="Paginated list of all orders, any owner (ownership is not filtered -- see note above).",
)
async def list_orders(request: Request, limit: int = 50, offset: int = 0):
    services = request.app.state.gateway_services
    orders = await services.order_repository.list_all(limit=limit, offset=offset)
    return {"orders": [_serialize(order) for order in orders]}


@router.get(
    "/orders/{order_id}",
    response_model=OrderResponse,
    responses={404: {"model": ErrorDetail, "description": "No order with this id"}},
    summary="Get an order",
)
async def get_order(order_id: UUID, request: Request):
    services = request.app.state.gateway_services
    order = await services.order_repository.get(order_id)
    if order is None:
        return JSONResponse({"detail": "order not found"}, status_code=404)
    return _serialize(order)


@router.post(
    "/orders",
    status_code=201,
    response_model=OrderResponse,
    summary="Create an order",
    description="Owner is taken from the caller's own verified identity (JWT `sub`), never from the request body.",
)
async def create_order(body: OrderCreateRequest, request: Request):
    services = request.app.state.gateway_services
    context = request.state.gateway_context
    order = await services.order_repository.create(context.claims.subject, body.status, body.amount)
    return _serialize(order)


@router.put(
    "/orders/{order_id}",
    response_model=OrderResponse,
    responses={404: {"model": ErrorDetail, "description": "No order with this id"}},
    summary="Update an order",
)
async def update_order(order_id: UUID, body: OrderUpdateRequest, request: Request):
    services = request.app.state.gateway_services
    order = await services.order_repository.update(order_id, status=body.status, amount=body.amount)
    if order is None:
        return JSONResponse({"detail": "order not found"}, status_code=404)
    return _serialize(order)


@router.delete(
    "/orders/{order_id}",
    response_model=DeletedResponse,
    responses={404: {"model": ErrorDetail, "description": "No order with this id"}},
    summary="Delete an order",
    description="Soft delete (is_active=false) -- the row is never physically removed.",
)
async def delete_order(order_id: UUID, request: Request):
    services = request.app.state.gateway_services
    deleted = await services.order_repository.soft_delete(order_id)
    if not deleted:
        return JSONResponse({"detail": "order not found"}, status_code=404)
    return {"detail": "deleted"}
