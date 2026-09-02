from __future__ import annotations

from datetime import datetime
from uuid import UUID

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from app.schemas.common import ErrorDetail

router = APIRouter(tags=["documents"])


class DocumentCreateRequest(BaseModel):
    title: str
    content: str | None = None


class DocumentUpdateRequest(BaseModel):
    title: str | None = None
    content: str | None = None


class DocumentResponse(BaseModel):
    document_id: UUID
    owner_id: UUID
    title: str
    content: str | None
    created_at: datetime
    updated_at: datetime


class DocumentListResponse(BaseModel):
    documents: list[DocumentResponse]


class DeletedResponse(BaseModel):
    detail: str


def _serialize(document) -> dict:
    return {
        "document_id": str(document.document_id),
        "owner_id": str(document.owner_id),
        "title": document.title,
        "content": document.content,
        "created_at": document.created_at.isoformat(),
        "updated_at": document.updated_at.isoformat(),
    }


# Ownership is deliberately NOT enforced here. RBAC (via OPA) already decided
# whether the caller's ROLE may perform this ACTION; whether this specific
# document belongs to the caller is intentionally left unchecked, so that "a
# user reading/writing resources they don't own" stays observable in the
# traffic. The ML pipeline (isolation-forest now, behavioral-detector later) is
# meant to learn and flag that pattern from real traffic -- enforcing ownership
# here would make that attack scenario impossible to ever demonstrate. This is
# a deliberate design choice, not an oversight: do not "fix" it by adding an
# owner_id check.


@router.get(
    "/documents",
    response_model=DocumentListResponse,
    summary="List documents",
    description="Paginated list of all documents, any owner (ownership is not filtered -- see note above).",
)
async def list_documents(request: Request, limit: int = 50, offset: int = 0):
    services = request.app.state.gateway_services
    documents = await services.document_repository.list_all(limit=limit, offset=offset)
    return {"documents": [_serialize(document) for document in documents]}


@router.get(
    "/documents/{document_id}",
    response_model=DocumentResponse,
    responses={404: {"model": ErrorDetail, "description": "No document with this id"}},
    summary="Get a document",
)
async def get_document(document_id: UUID, request: Request):
    services = request.app.state.gateway_services
    document = await services.document_repository.get(document_id)
    if document is None:
        return JSONResponse({"detail": "document not found"}, status_code=404)
    return _serialize(document)


@router.post(
    "/documents",
    status_code=201,
    response_model=DocumentResponse,
    summary="Create a document",
    description="Owner is taken from the caller's own verified identity (JWT `sub`), never from the request body.",
)
async def create_document(body: DocumentCreateRequest, request: Request):
    services = request.app.state.gateway_services
    context = request.state.gateway_context
    document = await services.document_repository.create(context.claims.subject, body.title, body.content)
    return _serialize(document)


@router.put(
    "/documents/{document_id}",
    response_model=DocumentResponse,
    responses={404: {"model": ErrorDetail, "description": "No document with this id"}},
    summary="Update a document",
)
async def update_document(document_id: UUID, body: DocumentUpdateRequest, request: Request):
    services = request.app.state.gateway_services
    document = await services.document_repository.update(document_id, title=body.title, content=body.content)
    if document is None:
        return JSONResponse({"detail": "document not found"}, status_code=404)
    return _serialize(document)


@router.delete(
    "/documents/{document_id}",
    response_model=DeletedResponse,
    responses={404: {"model": ErrorDetail, "description": "No document with this id"}},
    summary="Delete a document",
    description="Soft delete (is_active=false) -- the row is never physically removed.",
)
async def delete_document(document_id: UUID, request: Request):
    services = request.app.state.gateway_services
    deleted = await services.document_repository.soft_delete(document_id)
    if not deleted:
        return JSONResponse({"detail": "document not found"}, status_code=404)
    return {"detail": "deleted"}
