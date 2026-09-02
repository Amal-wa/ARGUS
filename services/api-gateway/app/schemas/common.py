from __future__ import annotations

from pydantic import BaseModel


class ErrorDetail(BaseModel):
    """Shape of every error body this API returns -- a single `detail` string,
    sometimes with one or two extra fields (see each route's own `responses=`
    entry for those). Used only to document error responses in the OpenAPI
    schema; handlers still build and return these by hand as JSONResponse."""

    detail: str
