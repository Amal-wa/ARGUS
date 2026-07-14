from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from datetime import datetime, timezone
from types import SimpleNamespace
from uuid import UUID, uuid4

from fastapi import FastAPI

from app.core.repositories import DocumentRecord
from app.core.request_matching import resolve_route_pattern
from app.middleware.context import RequestContext
from app.routers.documents import (
    DocumentCreateRequest,
    DocumentUpdateRequest,
    create_document,
    delete_document,
    get_document,
    list_documents,
    router as documents_router,
    update_document,
)


@dataclass(slots=True)
class FakeDocumentRepository:
    records: dict[UUID, DocumentRecord] = field(default_factory=dict)

    async def list_all(self, *, limit=50, offset=0):
        active = [r for r in self.records.values() if not r.is_deleted]
        return active[offset : offset + limit]

    async def get(self, document_id):
        record = self.records.get(document_id)
        return None if record is None or record.is_deleted else record

    async def create(self, owner_id, title, content):
        document_id = uuid4()
        now = datetime.now(timezone.utc)
        record = DocumentRecord(
            document_id=document_id,
            owner_id=owner_id,
            title=title,
            content=content,
            created_at=now,
            updated_at=now,
            is_deleted=False,
        )
        self.records[document_id] = record
        return record

    async def update(self, document_id, *, title=None, content=None):
        record = self.records.get(document_id)
        if record is None or record.is_deleted:
            return None
        if title is not None:
            record.title = title
        if content is not None:
            record.content = content
        record.updated_at = datetime.now(timezone.utc)
        return record

    async def soft_delete(self, document_id):
        record = self.records.get(document_id)
        if record is None or record.is_deleted:
            return False
        record.is_deleted = True
        return True


def _request(repo, claims_subject=None):
    services = SimpleNamespace(document_repository=repo)
    app = SimpleNamespace(state=SimpleNamespace(gateway_services=services))
    context = RequestContext(claims=SimpleNamespace(subject=claims_subject or uuid4()))
    return SimpleNamespace(app=app, state=SimpleNamespace(gateway_context=context))


def test_create_and_get_document():
    async def _run():
        repo = FakeDocumentRepository()
        owner_id = uuid4()
        request = _request(repo, claims_subject=owner_id)

        created = await create_document(DocumentCreateRequest(title="Hello", content="World"), request)
        assert created["owner_id"] == str(owner_id)
        assert created["title"] == "Hello"

        fetched = await get_document(UUID(created["document_id"]), request)
        assert fetched["title"] == "Hello"

    asyncio.run(_run())


def test_get_missing_document_returns_404():
    async def _run():
        repo = FakeDocumentRepository()
        response = await get_document(uuid4(), _request(repo))
        assert response.status_code == 404

    asyncio.run(_run())


def test_update_document():
    async def _run():
        repo = FakeDocumentRepository()
        request = _request(repo)
        created = await create_document(DocumentCreateRequest(title="Original"), request)
        document_id = UUID(created["document_id"])

        updated = await update_document(document_id, DocumentUpdateRequest(title="Updated"), request)

        assert updated["title"] == "Updated"

    asyncio.run(_run())


def test_update_missing_document_returns_404():
    async def _run():
        repo = FakeDocumentRepository()
        response = await update_document(uuid4(), DocumentUpdateRequest(title="x"), _request(repo))
        assert response.status_code == 404

    asyncio.run(_run())


def test_delete_document_soft_deletes_and_subsequent_get_404s():
    async def _run():
        repo = FakeDocumentRepository()
        request = _request(repo)
        created = await create_document(DocumentCreateRequest(title="ToDelete"), request)
        document_id = UUID(created["document_id"])

        delete_response = await delete_document(document_id, request)
        assert delete_response == {"detail": "deleted"}

        get_response = await get_document(document_id, request)
        assert get_response.status_code == 404

        # Row still exists (soft delete, not a hard delete).
        assert document_id in repo.records
        assert repo.records[document_id].is_deleted is True

    asyncio.run(_run())


def test_delete_missing_document_returns_404():
    async def _run():
        repo = FakeDocumentRepository()
        response = await delete_document(uuid4(), _request(repo))
        assert response.status_code == 404

    asyncio.run(_run())


def test_list_documents_excludes_deleted():
    async def _run():
        repo = FakeDocumentRepository()
        request = _request(repo)
        created1 = await create_document(DocumentCreateRequest(title="A"), request)
        await create_document(DocumentCreateRequest(title="B"), request)
        await delete_document(UUID(created1["document_id"]), request)

        result = await list_documents(request)

        titles = [d["title"] for d in result["documents"]]
        assert titles == ["B"]

    asyncio.run(_run())


def test_create_document_owner_id_matches_authenticated_subject():
    async def _run():
        repo = FakeDocumentRepository()
        subject = uuid4()
        request = _request(repo, claims_subject=subject)

        created = await create_document(DocumentCreateRequest(title="Mine"), request)

        assert created["owner_id"] == str(subject)

    asyncio.run(_run())


def test_route_pattern_resolves_to_parameterized_path():
    app = FastAPI()
    app.include_router(documents_router)

    scope = {"type": "http", "method": "GET", "path": "/documents/123", "headers": []}
    request = SimpleNamespace(app=app, scope=scope, url=SimpleNamespace(path="/documents/123"))

    assert resolve_route_pattern(request) == "/documents/{document_id}"
