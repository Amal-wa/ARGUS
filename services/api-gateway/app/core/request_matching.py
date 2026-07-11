from __future__ import annotations

from fastapi import Request
from starlette.routing import Match


def resolve_route_pattern(request: Request) -> str:
    for route in request.app.router.routes:
        if not hasattr(route, "matches"):
            continue
        match, _ = route.matches(request.scope)
        if match == Match.FULL:
            return getattr(route, "path", request.url.path)
    return request.url.path


def request_action(method: str) -> str:
    normalized_method = method.upper()
    if normalized_method == "GET":
        return "read"
    if normalized_method == "POST":
        return "create"
    if normalized_method in {"PUT", "PATCH"}:
        return "update"
    if normalized_method == "DELETE":
        return "delete"
    return "read"
