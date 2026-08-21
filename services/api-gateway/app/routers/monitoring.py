from __future__ import annotations

import csv
import io
from datetime import datetime
from typing import Literal

from fastapi import APIRouter, Query, Request, Response
from fastapi.responses import JSONResponse
from pydantic import BaseModel

router = APIRouter()


class CanaryReviewRequest(BaseModel):
    # Only the two HUMAN-DECIDED target states are writable here --
    # "pending"/"no_review_required" are states canary-validator itself
    # assigns at insertion (today always "pending", see repository.py), not
    # actions an operator takes through this endpoint. A Literal (not a bare
    # str re-validated by hand) makes any other value, including those two,
    # a 422 from Pydantic before this code ever runs.
    review_status: Literal["confirmed", "rejected"]

# Bounds, not defaults tunable without limit -- see repositories.py's
# comment on why every monitoring query must be bounded.
DEFAULT_WINDOW_MINUTES = 60
DEFAULT_TIMELINE_WINDOW_MINUTES = 30
MAX_WINDOW_MINUTES = 7 * 24 * 60  # one week -- generous, still bounded

DEFAULT_DECISIONS_LIMIT = 50
MAX_DECISIONS_LIMIT = 200

DEFAULT_ALERTS_LIMIT = 50
MAX_ALERTS_LIMIT = 200

DEFAULT_PAGE_SIZE = 50
MAX_PAGE_SIZE = 200

# format=csv ignores the caller's page/page_size and fetches up to this many
# rows in one go instead -- same "every monitoring query must be bounded"
# discipline as MAX_PAGE_SIZE/MAX_DECISIONS_LIMIT/MAX_WINDOW_MINUTES above.
# An unfiltered export (no user_email/date range) would otherwise return the
# entire table. Truncation past this cap is silent, same as elsewhere in
# this router -- a narrower filter (date range, user) is how a caller gets a
# complete export of more than this many rows.
MAX_EXPORT_ROWS = 5000

# Fixed column order for the CSV export -- needed independent of any actual
# result set so an EMPTY result still produces a well-formed header row
# (csv.DictWriter can't derive fieldnames from an empty `rows` list).
# Mirrors _serialize_decision_audit_row/_serialize_event_audit_row's dict key
# order exactly.
_DECISION_AUDIT_CSV_FIELDS = [
    "id",
    "trace_id",
    "created_at",
    "user_id",
    "user_email",
    "role",
    "resource",
    "action",
    "ip_address",
    "risk_score",
    "model_version",
    "is_anomaly",
    "decision",
    "policy_name",
    "reason",
    "latency_ms",
]
_EVENT_AUDIT_CSV_FIELDS = [
    "id",
    "trace_id",
    "created_at",
    "user_id",
    "ip_address",
    "http_method",
    "request_path",
    "latency_ms",
    "http_status",
    "error_code",
    "error_message",
    "event_type",
]


def _rows_to_csv(rows: list[dict], fieldnames: list[str]) -> str:
    # csv's writer writes None as an empty cell automatically -- no extra
    # null-handling needed for the many Optional columns in these shapes.
    buffer = io.StringIO()
    writer = csv.DictWriter(buffer, fieldnames=fieldnames)
    writer.writeheader()
    writer.writerows(rows)
    return buffer.getvalue()


def _clamp(value: int, *, minimum: int, maximum: int) -> int:
    return max(minimum, min(value, maximum))


@router.get("/monitoring/stats")
async def get_stats(request: Request, window_minutes: int = DEFAULT_WINDOW_MINUTES):
    services = request.app.state.gateway_services
    window_minutes = _clamp(window_minutes, minimum=1, maximum=MAX_WINDOW_MINUTES)

    stats = await services.monitoring_repository.get_stats(window_minutes)
    allow_rate = round(stats.allow / stats.total_decisions, 4) if stats.total_decisions else 0.0

    return {
        "total_decisions": stats.total_decisions,
        "allow": stats.allow,
        "deny": stats.deny,
        "step_up": stats.step_up,
        "allow_rate": allow_rate,
        "active_users": stats.active_users,
        "distinct_ips": stats.distinct_ips,
        "window_minutes": window_minutes,
    }


def _serialize_decision(row) -> dict:
    return {
        "trace_id": str(row.trace_id),
        "created_at": row.created_at.isoformat(),
        "user_id": str(row.user_id),
        "user_email": row.user_email,
        "resource": row.resource,
        "action": row.action,
        "decision": row.decision,
        "policy_name": row.policy_name,
        "risk_score": row.risk_score,
        "model_version": row.model_version,
        "ip_address": row.ip_address,
    }


@router.get("/monitoring/decisions")
async def list_decisions(
    request: Request,
    limit: int = DEFAULT_DECISIONS_LIMIT,
    since: datetime | None = None,
    user_email: str | None = None,
):
    services = request.app.state.gateway_services
    limit = _clamp(limit, minimum=1, maximum=MAX_DECISIONS_LIMIT)

    rows = await services.monitoring_repository.list_decisions(limit=limit, since=since, user_email=user_email)
    return {"decisions": [_serialize_decision(row) for row in rows]}


@router.get("/monitoring/risk-timeline")
async def get_risk_timeline(
    request: Request, user_email: str | None = None, window_minutes: int = DEFAULT_TIMELINE_WINDOW_MINUTES
):
    services = request.app.state.gateway_services
    window_minutes = _clamp(window_minutes, minimum=1, maximum=MAX_WINDOW_MINUTES)

    raw_threshold = await services.redis_client.get("model:active_threshold")
    threshold = float(raw_threshold) if raw_threshold is not None else None

    points = await services.monitoring_repository.get_risk_timeline(user_email=user_email, window_minutes=window_minutes)
    return {
        "threshold": threshold,
        "points": [
            {"created_at": point.created_at.isoformat(), "user_email": point.user_email, "risk_score": point.risk_score}
            for point in points
        ],
    }


@router.get("/monitoring/alerts")
async def get_alerts(request: Request, limit: int = DEFAULT_ALERTS_LIMIT, window_minutes: int = DEFAULT_WINDOW_MINUTES):
    services = request.app.state.gateway_services
    limit = _clamp(limit, minimum=1, maximum=MAX_ALERTS_LIMIT)
    window_minutes = _clamp(window_minutes, minimum=1, maximum=MAX_WINDOW_MINUTES)

    alerts = await services.monitoring_repository.get_alerts(limit=limit, window_minutes=window_minutes)
    return {
        "alerts": [
            {
                "type": alert.type,
                "created_at": alert.created_at.isoformat(),
                "user_email": alert.user_email,
                "resource": alert.resource,
                "risk_score": alert.risk_score,
                "trace_id": str(alert.trace_id) if alert.trace_id is not None else None,
            }
            for alert in alerts
        ]
    }


@router.get("/monitoring/anomalies")
async def get_anomalies(request: Request, limit: int = DEFAULT_ALERTS_LIMIT, window_minutes: int = DEFAULT_WINDOW_MINUTES):
    # Dedicated feed for behavioral-detector's event_anomaly rows, separate
    # from /monitoring/alerts -- see MonitoringRepository.get_anomalies for
    # why: anomalies were getting buried in the step_up-dominated alerts
    # feed with no severity/anomaly_type shown, so the dashboard's Anomalies
    # panel reads from here instead, with its own limit/window so a burst of
    # step_ups can't crowd them out.
    services = request.app.state.gateway_services
    limit = _clamp(limit, minimum=1, maximum=MAX_ALERTS_LIMIT)
    window_minutes = _clamp(window_minutes, minimum=1, maximum=MAX_WINDOW_MINUTES)

    anomalies = await services.monitoring_repository.get_anomalies(limit=limit, window_minutes=window_minutes)
    return {
        "anomalies": [
            {
                "created_at": anomaly.created_at.isoformat(),
                "user_email": anomaly.user_email,
                "resource": anomaly.resource,
                "anomaly_type": anomaly.anomaly_type,
                "severity": anomaly.severity,
                "risk_score": anomaly.risk_score,
                "trace_id": str(anomaly.trace_id) if anomaly.trace_id is not None else None,
            }
            for anomaly in anomalies
        ]
    }


async def _service_health(services) -> dict:
    # Never let one dependency's failure 500 the whole endpoint -- report it
    # instead. This endpoint's entire purpose is to be trustworthy exactly
    # when something else is broken.
    health: dict[str, str] = {}

    try:
        healthy = await services.authorization_service.scoring_client.health()
        health["isolation_forest"] = "healthy" if healthy else "unhealthy"
    except Exception:
        health["isolation_forest"] = "unhealthy"

    try:
        healthy = await services.authorization_service.opa_client.health()
        health["opa"] = "healthy" if healthy else "unhealthy"
    except Exception:
        health["opa"] = "unhealthy"

    try:
        await services.redis_client.ping()
        health["redis"] = "up"
    except Exception:
        health["redis"] = "down"

    try:
        await services.monitoring_repository.ping_database()
        health["postgres"] = "up"
    except Exception:
        health["postgres"] = "down"

    return health


@router.get("/monitoring/system-status")
async def get_system_status(request: Request):
    services = request.app.state.gateway_services

    active_version = await services.redis_client.get("model:active_version")
    raw_threshold = await services.redis_client.get("model:active_threshold")
    candidate_version = await services.redis_client.get("model:candidate_version")
    active_threshold = float(raw_threshold) if raw_threshold is not None else None

    model_row = None
    if active_version is not None:
        model_row = await services.monitoring_repository.get_model_registry_row(active_version)

    return {
        "active_model": active_version,
        "active_threshold": active_threshold,
        "candidate_model": candidate_version,
        "training_samples": model_row.training_samples if model_row is not None else None,
        "model_trained_at": model_row.created_at.isoformat() if model_row is not None else None,
        "score_distribution": model_row.score_distribution if model_row is not None else None,
        "services": await _service_health(services),
    }


def _serialize_decision_audit_row(row) -> dict:
    return {
        "id": row.id,
        "trace_id": str(row.trace_id),
        "created_at": row.created_at.isoformat(),
        "user_id": str(row.user_id),
        "user_email": row.user_email,
        "role": row.role,
        "resource": row.resource,
        "action": row.action,
        "ip_address": row.ip_address,
        "risk_score": row.risk_score,
        "model_version": row.model_version,
        "is_anomaly": row.is_anomaly,
        "decision": row.decision,
        "policy_name": row.policy_name,
        "reason": row.reason,
        "latency_ms": row.latency_ms,
    }


def _serialize_event_audit_row(row) -> dict:
    return {
        "id": row.id,
        "trace_id": str(row.trace_id),
        "created_at": row.created_at.isoformat(),
        "user_id": str(row.user_id) if row.user_id is not None else None,
        "ip_address": row.ip_address,
        "http_method": row.http_method,
        "request_path": row.request_path,
        "latency_ms": row.latency_ms,
        "http_status": row.http_status,
        "error_code": row.error_code,
        "error_message": row.error_message,
        "event_type": row.event_type,
    }


@router.get("/monitoring/audit")
async def get_audit(
    request: Request,
    page: int = 1,
    page_size: int = DEFAULT_PAGE_SIZE,
    user_email: str | None = None,
    decision: str | None = None,
    from_: datetime | None = Query(None, alias="from"),
    to: datetime | None = None,
    event_type: str | None = None,
    # Named export_format internally (not `format`) to avoid shadowing the
    # format() builtin -- the wire query param stays ?format=... via alias.
    export_format: str = Query("json", alias="format"),
):
    services = request.app.state.gateway_services
    is_csv = export_format == "csv"
    # CSV export ignores the caller's page/page_size entirely and fetches up
    # to MAX_EXPORT_ROWS in one shot instead -- see that constant's comment.
    # Any other format value (including the explicit "json", and simply
    # omitting it) is today's existing paginated-JSON behavior, unchanged.
    page = 1 if is_csv else max(1, page)
    page_size = MAX_EXPORT_ROWS if is_csv else _clamp(page_size, minimum=1, maximum=MAX_PAGE_SIZE)

    # event_type only exists on the `events` table (gateway-level events --
    # rate limits, auth failures, step-up challenges), not on
    # opa_decision_log (the decision audit trail) -- so its presence selects
    # which of the two audit views this call reads, rather than being a
    # column filter applied to both. Reused as-is for CSV export: the same
    # branch decides both which repository method AND which CSV column set
    # applies.
    if event_type is not None:
        page_result = await services.monitoring_repository.get_event_audit_page(
            page=page, page_size=page_size, user_email=user_email, event_type=event_type, from_ts=from_, to_ts=to
        )
        rows = [_serialize_event_audit_row(row) for row in page_result.rows]
        csv_fields = _EVENT_AUDIT_CSV_FIELDS
        csv_kind = "events"
    else:
        page_result = await services.monitoring_repository.get_decision_audit_page(
            page=page, page_size=page_size, user_email=user_email, decision=decision, from_ts=from_, to_ts=to
        )
        rows = [_serialize_decision_audit_row(row) for row in page_result.rows]
        csv_fields = _DECISION_AUDIT_CSV_FIELDS
        csv_kind = "decisions"

    if is_csv:
        return Response(
            content=_rows_to_csv(rows, csv_fields),
            media_type="text/csv",
            headers={"Content-Disposition": f'attachment; filename="audit-{csv_kind}-export.csv"'},
        )

    return {"rows": rows, "page": page, "page_size": page_size, "total": page_result.total}


@router.patch("/monitoring/canary/{canary_id}/review")
async def review_canary(canary_id: int, body: CanaryReviewRequest, request: Request):
    # Admin-only via rbac.rego's monitoring_route prefix match (/monitoring/*)
    # -- no role check here, same as every other route in this file.
    services = request.app.state.gateway_services
    context = request.state.gateway_context

    # reviewed_by is derived from the caller's own verified identity, never
    # a client-supplied field -- the JWT carries only `sub` (user_id) and
    # `role`, no email claim, so it's resolved the same way every other
    # audit-facing view in this repository already does (list_decisions,
    # get_risk_timeline, get_alerts all join users_table for a human-readable
    # email rather than exposing a raw UUID).
    reviewer = await services.user_repository.get_by_id(context.claims.subject)
    reviewed_by = reviewer.email if reviewer is not None else str(context.claims.subject)

    outcome = await services.monitoring_repository.update_canary_review_status(
        canary_id, review_status=body.review_status, reviewed_by=reviewed_by
    )

    if outcome.status == "not_found":
        return JSONResponse({"detail": "canary comparison not found"}, status_code=404)
    if outcome.status == "already_reviewed":
        return JSONResponse(
            {
                "detail": "canary comparison already reviewed",
                "review_status": outcome.existing_status,
            },
            status_code=409,
        )

    return {
        "id": canary_id,
        "review_status": body.review_status,
        "reviewed_by": reviewed_by,
        "reviewed_at": outcome.reviewed_at.isoformat(),
    }
