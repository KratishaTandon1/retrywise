"""Thin optional FastAPI transport over the deterministic application core."""

import json
import logging
import os
import re
import time
from typing import Annotated, Any

from ...packages.diagnosis import DiagnosisMode
from ...packages.razorpay import (
    AccountMismatchError,
    InboxConflictError,
    WebhookDecodeError,
    WebhookVerificationError,
)
from .approval_request import ApprovalRequestConflict, ApprovalRequestNotFound
from .diagnosis_controls import DiagnosisControlConflict, DiagnosisControlNotFound
from .merchant_controls import (
    MerchantControlConflict,
    MerchantControlNotFound,
    MerchantControlState,
)
from .observability import (
    CounterName,
    Observability,
    bind_request_id,
    choose_request_id,
    disable_unstructured_server_access_log,
    reset_request_id,
    safe_route_template,
)
from .operator_store import PostgresOperatorStore
from .replay import ReplayIdempotencyConflict, ReplayRunRequest
from .runtime import ControlPlaneRuntime
from .settings import DeploymentProfile
from .webhook_ingress import (
    EndpointNotFound,
    IngressError,
    PayloadTooLarge,
    UnsupportedMediaType,
)


async def _read_bounded_body(request: Any, *, max_body_bytes: int) -> bytes:
    """Read exact ASGI request bytes without ever buffering past the limit."""

    content_length = request.headers.get("content-length")
    if content_length is not None:
        try:
            declared_length = int(content_length, 10)
        except ValueError as exc:
            raise IngressError("content-length must be a non-negative integer") from exc
        if declared_length < 0:
            raise IngressError("content-length must be a non-negative integer")
        if declared_length > max_body_bytes:
            raise PayloadTooLarge("webhook body exceeds configured limit")

    body = bytearray()
    async for chunk in request.stream():
        if len(body) + len(chunk) > max_body_bytes:
            raise PayloadTooLarge("webhook body exceeds configured limit")
        body.extend(chunk)
    return bytes(body)


def create_app(
    runtime: ControlPlaneRuntime | None = None,
    *,
    observability: Observability | None = None,
) -> Any:
    """Create the HTTP adapter.

    FastAPI is imported lazily so domain, provider, simulator, and application
    tests stay dependency-free. Run with Uvicorn's factory mode.
    """

    try:
        from fastapi import Depends, FastAPI, HTTPException, Query, Request, Response
        from fastapi.middleware.cors import CORSMiddleware
        from fastapi.responses import JSONResponse
    except ImportError as exc:  # pragma: no cover - exercised in deployed/API CI.
        raise RuntimeError(
            "FastAPI extras are required: install RetryWise with the api extra"
        ) from exc

    active_runtime = runtime or ControlPlaneRuntime.from_mapping(os.environ)
    active_observability = observability or Observability()
    disable_unstructured_server_access_log()
    app = FastAPI(
        title="RetryWise Control Plane",
        version="0.1.0",
        docs_url=(
            None if active_runtime.settings.environment is DeploymentProfile.PRODUCTION else "/docs"
        ),
        redoc_url=None,
    )
    app.state.observability = active_observability
    app.add_middleware(
        CORSMiddleware,
        allow_origins=list(active_runtime.settings.cors_allowed_origins),
        allow_credentials=False,
        allow_methods=["GET", "POST"],
        allow_headers=["Authorization", "Content-Type", "Idempotency-Key", "X-Request-ID"],
        expose_headers=["X-Request-ID"],
    )

    @app.middleware("http")
    async def observe_http(request: Request, call_next: Any) -> Any:
        request_id = choose_request_id(request.headers.get("x-request-id"))
        context_token = bind_request_id(request_id)
        started_ns = time.perf_counter_ns()
        try:
            response = await call_next(request)
        except Exception as exc:
            active_observability.event(
                "http.request.failed",
                level=logging.ERROR,
                fields={
                    "duration_ms": (time.perf_counter_ns() - started_ns) // 1_000_000,
                    "exception_type": type(exc).__name__,
                    "http_method": request.method,
                    "http_route": safe_route_template(request.scope),
                    "status_code": 500,
                },
            )
            raise
        else:
            response.headers["X-Request-ID"] = request_id
            status_code = response.status_code
            active_observability.event(
                "http.request.completed",
                level=logging.WARNING if status_code >= 500 else logging.INFO,
                fields={
                    "duration_ms": (time.perf_counter_ns() - started_ns) // 1_000_000,
                    "http_method": request.method,
                    "http_route": safe_route_template(request.scope),
                    "status_code": status_code,
                },
            )
            return response
        finally:
            reset_request_id(context_token)

    async def require_operator(request: Request) -> Any:
        context = active_runtime.operator_authorizer.authorize(request.headers.get("authorization"))
        if context is None:
            raise HTTPException(
                status_code=401,
                detail={"code": "OPERATOR_AUTH_REQUIRED"},
                headers={"WWW-Authenticate": "Bearer"},
            )
        return context

    @app.get("/health/live", include_in_schema=False)
    async def liveness() -> dict[str, str]:
        return {"status": "alive"}

    @app.get("/health/ready", include_in_schema=False)
    async def readiness() -> Any:
        ready, payload = active_runtime.readiness()
        return JSONResponse(status_code=200 if ready else 503, content=payload)

    @app.get("/api/v1/overview")
    async def overview(
        environment: Annotated[str, Query(pattern="^(REPLAY|RAZORPAY_TEST_MODE)$")],
        _operator: Annotated[Any, Depends(require_operator)],
    ) -> dict[str, object]:
        if environment == "RAZORPAY_TEST_MODE":
            if active_runtime.operator_store is not None:
                try:
                    return active_runtime.operator_store.overview(merchant_id=_operator.merchant_id)
                except Exception as exc:
                    raise HTTPException(503, detail={"code": "OPERATOR_STORE_UNAVAILABLE"}) from exc
            return {
                "environment": environment,
                "labels": {
                    "value_label": "Razorpay test-mode collection: not executed",
                    "real_money": False,
                    "observed_real_merchant_revenue_claimed": False,
                },
                "test_mode_recovered_minor": None,
                "open_cases": None,
                "hard_safety_violations": None,
                "message": "No provider run recorded; Test Mode metrics are not measured",
            }
        request = ReplayRunRequest(code_revision=active_runtime.settings.code_revision)
        return active_runtime.replay.overview(request)

    def operator_store() -> PostgresOperatorStore:
        store = active_runtime.operator_store
        if store is None:
            raise HTTPException(503, detail={"code": "OPERATOR_STORE_NOT_CONFIGURED"})
        return store

    def case_id(value: str) -> str:
        if re.fullmatch(r"[0-9A-HJKMNP-TV-Z]{26}", value) is None:
            raise HTTPException(400, detail={"code": "INVALID_RECOVERY_CASE_ID"})
        return value

    def approval_id(value: str) -> str:
        if re.fullmatch(r"[0-9A-HJKMNP-TV-Z]{26}", value) is None:
            raise HTTPException(400, detail={"code": "INVALID_APPROVAL_ID"})
        return value

    def control_payload(state: MerchantControlState) -> dict[str, object]:
        payload = state.to_primitive()
        global_stop = active_runtime.settings.global_kill_switch
        payload["global_kill_switch_enabled"] = global_stop
        payload["collection_effects_enabled"] = not (global_stop or state.kill_switch_enabled)
        return payload

    @app.get("/api/v1/controls/kill-switch")
    async def get_kill_switch(
        _operator: Annotated[Any, Depends(require_operator)],
    ) -> dict[str, object]:
        service = active_runtime.merchant_controls
        if service is None:
            raise HTTPException(503, detail={"code": "MERCHANT_CONTROL_NOT_CONFIGURED"})
        try:
            return control_payload(service.get(merchant_id=_operator.merchant_id))
        except MerchantControlNotFound as exc:
            raise HTTPException(404, detail={"code": "MERCHANT_NOT_FOUND"}) from exc
        except Exception as exc:
            raise HTTPException(503, detail={"code": "MERCHANT_CONTROL_UNAVAILABLE"}) from exc

    @app.post("/api/v1/controls/kill-switch")
    async def set_kill_switch(
        request: Request,
        _operator: Annotated[Any, Depends(require_operator)],
    ) -> dict[str, object]:
        service = active_runtime.merchant_controls
        if service is None:
            raise HTTPException(503, detail={"code": "MERCHANT_CONTROL_NOT_CONFIGURED"})
        idempotency_key = request.headers.get("idempotency-key", "")
        if idempotency_key != idempotency_key.strip() or not 16 <= len(idempotency_key) <= 128:
            raise HTTPException(400, detail={"code": "INVALID_IDEMPOTENCY_KEY"})
        try:
            body = await request.json()
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise HTTPException(400, detail={"code": "INVALID_MERCHANT_CONTROL"}) from exc
        if not isinstance(body, dict) or set(body) != {"enabled", "reason_code"}:
            raise HTTPException(400, detail={"code": "INVALID_MERCHANT_CONTROL"})
        try:
            state = service.set_kill_switch(
                merchant_id=_operator.merchant_id,
                enabled=body["enabled"],
                reason_code=body["reason_code"],
                operator_subject=_operator.subject,
                idempotency_key=idempotency_key,
            )
            return control_payload(state)
        except MerchantControlNotFound as exc:
            raise HTTPException(404, detail={"code": "MERCHANT_NOT_FOUND"}) from exc
        except MerchantControlConflict as exc:
            raise HTTPException(409, detail={"code": "IDEMPOTENCY_KEY_CONFLICT"}) from exc
        except (TypeError, ValueError) as exc:
            raise HTTPException(400, detail={"code": "INVALID_MERCHANT_CONTROL"}) from exc
        except Exception as exc:
            raise HTTPException(503, detail={"code": "MERCHANT_CONTROL_UNAVAILABLE"}) from exc

    @app.get("/api/v1/controls/diagnosis-engine")
    async def get_diagnosis_engine(
        _operator: Annotated[Any, Depends(require_operator)],
    ) -> dict[str, object]:
        service = active_runtime.diagnosis_controls
        if service is None:
            raise HTTPException(503, detail={"code": "DIAGNOSIS_CONTROL_NOT_CONFIGURED"})
        try:
            return service.get(merchant_id=_operator.merchant_id).to_primitive()
        except DiagnosisControlNotFound as exc:
            raise HTTPException(404, detail={"code": "MERCHANT_NOT_FOUND"}) from exc
        except Exception as exc:
            raise HTTPException(503, detail={"code": "DIAGNOSIS_CONTROL_UNAVAILABLE"}) from exc

    @app.post("/api/v1/controls/diagnosis-engine")
    async def set_diagnosis_engine(
        request: Request,
        _operator: Annotated[Any, Depends(require_operator)],
    ) -> dict[str, object]:
        service = active_runtime.diagnosis_controls
        if service is None:
            raise HTTPException(503, detail={"code": "DIAGNOSIS_CONTROL_NOT_CONFIGURED"})
        idempotency_key = request.headers.get("idempotency-key", "")
        if idempotency_key != idempotency_key.strip() or not 16 <= len(idempotency_key) <= 128:
            raise HTTPException(400, detail={"code": "INVALID_IDEMPOTENCY_KEY"})
        try:
            body = await request.json()
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise HTTPException(400, detail={"code": "INVALID_DIAGNOSIS_CONTROL"}) from exc
        if not isinstance(body, dict) or set(body) != {"mode"}:
            raise HTTPException(400, detail={"code": "INVALID_DIAGNOSIS_CONTROL"})
        try:
            state = service.set_mode(
                merchant_id=_operator.merchant_id,
                mode=DiagnosisMode(body["mode"]),
                operator_subject=_operator.subject,
                idempotency_key=idempotency_key,
            )
            return state.to_primitive()
        except DiagnosisControlNotFound as exc:
            raise HTTPException(404, detail={"code": "MERCHANT_NOT_FOUND"}) from exc
        except DiagnosisControlConflict as exc:
            raise HTTPException(409, detail={"code": "IDEMPOTENCY_KEY_CONFLICT"}) from exc
        except (TypeError, ValueError) as exc:
            raise HTTPException(400, detail={"code": "INVALID_DIAGNOSIS_CONTROL"}) from exc
        except Exception as exc:
            raise HTTPException(503, detail={"code": "DIAGNOSIS_CONTROL_UNAVAILABLE"}) from exc

    @app.get("/api/v1/recovery-cases")
    async def recovery_cases(
        _operator: Annotated[Any, Depends(require_operator)],
        limit: Annotated[int, Query(ge=1, le=200)] = 100,
    ) -> dict[str, object]:
        try:
            values = operator_store().list_cases(
                merchant_id=_operator.merchant_id,
                limit=limit,
            )
        except Exception as exc:
            raise HTTPException(503, detail={"code": "OPERATOR_STORE_UNAVAILABLE"}) from exc
        return {"environment": "RAZORPAY_TEST_MODE", "cases": values}

    @app.get("/api/v1/recovery-cases/{recovery_case_id}")
    async def recovery_case_detail(
        recovery_case_id: str,
        _operator: Annotated[Any, Depends(require_operator)],
    ) -> dict[str, object]:
        validated_case_id = case_id(recovery_case_id)
        try:
            value = operator_store().case_detail(
                merchant_id=_operator.merchant_id,
                recovery_case_id=validated_case_id,
            )
        except HTTPException:
            raise
        except Exception as exc:
            raise HTTPException(503, detail={"code": "OPERATOR_STORE_UNAVAILABLE"}) from exc
        if value is None:
            raise HTTPException(404, detail={"code": "RECOVERY_CASE_NOT_FOUND"})
        return value

    @app.get("/api/v1/incidents")
    async def incidents(
        _operator: Annotated[Any, Depends(require_operator)],
        limit: Annotated[int, Query(ge=1, le=200)] = 100,
    ) -> dict[str, object]:
        try:
            values = operator_store().list_incidents(
                merchant_id=_operator.merchant_id,
                limit=limit,
            )
        except Exception as exc:
            raise HTTPException(503, detail={"code": "OPERATOR_STORE_UNAVAILABLE"}) from exc
        return {"environment": "RAZORPAY_TEST_MODE", "incidents": values}

    @app.get("/api/v1/approvals")
    async def approvals(
        _operator: Annotated[Any, Depends(require_operator)],
        limit: Annotated[int, Query(ge=1, le=200)] = 100,
    ) -> dict[str, object]:
        try:
            values = operator_store().list_approvals(
                merchant_id=_operator.merchant_id,
                limit=limit,
            )
        except Exception as exc:
            raise HTTPException(503, detail={"code": "OPERATOR_STORE_UNAVAILABLE"}) from exc
        return {"environment": "RAZORPAY_TEST_MODE", "approvals": values}

    @app.post("/api/v1/approvals/{approval_identifier}/decision")
    async def decide_approval(
        approval_identifier: str,
        request: Request,
        _operator: Annotated[Any, Depends(require_operator)],
    ) -> Any:
        service = active_runtime.approval_requests
        if service is None:
            raise HTTPException(503, detail={"code": "APPROVAL_SERVICE_NOT_CONFIGURED"})
        idempotency_key = request.headers.get("idempotency-key", "")
        if idempotency_key != idempotency_key.strip() or not 16 <= len(idempotency_key) <= 128:
            raise HTTPException(400, detail={"code": "INVALID_IDEMPOTENCY_KEY"})
        try:
            body = await request.json()
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise HTTPException(400, detail={"code": "INVALID_APPROVAL_DECISION"}) from exc
        if not isinstance(body, dict) or set(body) != {"verdict", "reason_code"}:
            raise HTTPException(400, detail={"code": "INVALID_APPROVAL_DECISION"})
        try:
            result = service.act(
                merchant_id=_operator.merchant_id,
                approval_id=approval_id(approval_identifier),
                operator_subject=_operator.subject,
                verdict=body["verdict"],
                reason_code=body["reason_code"],
                idempotency_key=idempotency_key,
            )
        except HTTPException:
            raise
        except ApprovalRequestNotFound as exc:
            raise HTTPException(404, detail={"code": "APPROVAL_NOT_FOUND"}) from exc
        except ApprovalRequestConflict as exc:
            raise HTTPException(409, detail={"code": str(exc).upper()}) from exc
        except (TypeError, ValueError) as exc:
            raise HTTPException(400, detail={"code": "INVALID_APPROVAL_DECISION"}) from exc
        except Exception as exc:
            raise HTTPException(503, detail={"code": "APPROVAL_SERVICE_UNAVAILABLE"}) from exc
        payload = {
            "approval_id": result.approval_id,
            "verdict": result.verdict,
            "recovery_case_id": result.recovery_case_id,
            "case_version": result.case_version,
            "outbox_job_id": result.outbox_job_id,
            "command_status": result.command_status,
        }
        if result.verdict == "EXPIRED":
            return JSONResponse(status_code=409, content={**payload, "code": "APPROVAL_EXPIRED"})
        return JSONResponse(
            status_code=202 if result.verdict == "APPROVAL_QUEUED" else 200,
            content=payload,
        )

    @app.get("/api/v1/recovery-cases/{recovery_case_id}/audit")
    async def audit_chain(
        recovery_case_id: str,
        _operator: Annotated[Any, Depends(require_operator)],
    ) -> dict[str, object]:
        validated_case_id = case_id(recovery_case_id)
        try:
            return operator_store().verify_audit(
                merchant_id=_operator.merchant_id,
                recovery_case_id=validated_case_id,
            )
        except HTTPException:
            raise
        except Exception as exc:
            raise HTTPException(503, detail={"code": "AUDIT_VERIFICATION_UNAVAILABLE"}) from exc

    @app.post("/api/v1/impact/runs", status_code=200)
    async def start_replay(
        request: Request,
        _operator: Annotated[Any, Depends(require_operator)],
    ) -> dict[str, object]:
        idempotency_key = request.headers.get("idempotency-key", "")
        if idempotency_key != idempotency_key.strip() or not 16 <= len(idempotency_key) <= 128:
            raise HTTPException(
                400,
                detail={
                    "code": "INVALID_IDEMPOTENCY_KEY",
                    "message": "Idempotency-Key must contain 16 to 128 characters",
                },
            )
        try:
            body = await request.json()
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise HTTPException(400, detail={"code": "INVALID_REPLAY_REQUEST"}) from exc
        if not isinstance(body, dict):
            raise HTTPException(400, detail={"code": "INVALID_REPLAY_REQUEST"})
        allowed_fields = {
            "seed",
            "case_count",
            "bootstrap_samples",
        }
        unknown_fields = sorted(set(body) - allowed_fields)
        if unknown_fields:
            raise HTTPException(
                400,
                detail={
                    "code": "INVALID_REPLAY_REQUEST",
                    "message": f"Unknown fields: {', '.join(unknown_fields)}",
                },
            )
        try:
            run_request = ReplayRunRequest(
                seed=body.get("seed", 42),
                case_count=body.get("case_count", 2_000),
                bootstrap_samples=body.get("bootstrap_samples", 400),
                code_revision=active_runtime.settings.code_revision,
            )
        except (TypeError, ValueError) as exc:
            raise HTTPException(
                400, detail={"code": "INVALID_REPLAY_REQUEST", "message": str(exc)}
            ) from exc
        try:
            result = active_runtime.replay.submit(
                merchant_id=_operator.merchant_id,
                idempotency_key=idempotency_key,
                request=run_request,
            )
        except ReplayIdempotencyConflict as exc:
            active_observability.event(
                "replay.submission.conflict",
                level=logging.WARNING,
            )
            raise HTTPException(
                409,
                detail={
                    "code": "IDEMPOTENCY_KEY_REUSED",
                    "message": str(exc),
                },
            ) from exc
        active_observability.counters.increment(CounterName.REPLAY_SUBMISSION)
        active_observability.event(
            "replay.submission.completed",
            fields={
                "bootstrap_samples": run_request.bootstrap_samples,
                "case_count": run_request.case_count,
                "seed": run_request.seed,
            },
        )
        return result

    @app.post(
        "/api/v1/webhooks/razorpay/{endpoint_token}",
        status_code=204,
        response_class=Response,
        response_model=None,
        include_in_schema=True,
    )
    async def razorpay_webhook(endpoint_token: str, request: Request) -> Response:
        try:
            raw_body = await _read_bounded_body(
                request,
                max_body_bytes=active_runtime.settings.webhook_max_body_bytes,
            )
            receipt = active_runtime.webhook_ingress.accept(
                endpoint_token=endpoint_token,
                raw_body=raw_body,
                headers=dict(request.headers),
                content_type=request.headers.get("content-type", ""),
                received_at_epoch=int(time.time()),
            )
        except WebhookVerificationError as exc:
            active_observability.counters.increment(CounterName.WEBHOOK_VERIFICATION_FAILURE)
            active_observability.event(
                "webhook.ingress.rejected",
                level=logging.WARNING,
                fields={"reason_code": "signature_verification_failed"},
            )
            raise HTTPException(401, detail={"code": "INVALID_WEBHOOK_SIGNATURE"}) from exc
        except EndpointNotFound as exc:
            active_observability.event(
                "webhook.ingress.rejected",
                level=logging.WARNING,
                fields={"reason_code": "endpoint_not_found"},
            )
            raise HTTPException(404, detail={"code": "WEBHOOK_ENDPOINT_NOT_FOUND"}) from exc
        except PayloadTooLarge as exc:
            active_observability.event(
                "webhook.ingress.rejected",
                level=logging.WARNING,
                fields={"reason_code": "payload_too_large"},
            )
            raise HTTPException(413, detail={"code": "WEBHOOK_BODY_TOO_LARGE"}) from exc
        except UnsupportedMediaType as exc:
            active_observability.event(
                "webhook.ingress.rejected",
                level=logging.WARNING,
                fields={"reason_code": "unsupported_media_type"},
            )
            raise HTTPException(415, detail={"code": "UNSUPPORTED_MEDIA_TYPE"}) from exc
        except AccountMismatchError as exc:
            active_observability.event(
                "webhook.ingress.rejected",
                level=logging.WARNING,
                fields={"reason_code": "provider_account_mismatch"},
            )
            raise HTTPException(400, detail={"code": "PROVIDER_ACCOUNT_MISMATCH"}) from exc
        except WebhookDecodeError as exc:
            active_observability.event(
                "webhook.ingress.rejected",
                level=logging.WARNING,
                fields={"reason_code": "invalid_envelope"},
            )
            raise HTTPException(400, detail={"code": "INVALID_WEBHOOK_ENVELOPE"}) from exc
        except InboxConflictError as exc:
            active_observability.counters.increment(CounterName.WEBHOOK_CONFLICT)
            active_observability.event(
                "webhook.ingress.conflict",
                level=logging.WARNING,
            )
            raise HTTPException(409, detail={"code": "PROVIDER_EVENT_ID_CONFLICT"}) from exc
        except IngressError as exc:
            active_observability.event(
                "webhook.ingress.rejected",
                level=logging.WARNING,
                fields={"reason_code": "invalid_request"},
            )
            raise HTTPException(400, detail={"code": "INVALID_WEBHOOK_REQUEST"}) from exc
        if receipt.enqueued:
            active_observability.counters.increment(CounterName.WEBHOOK_ACCEPTED)
        else:
            active_observability.counters.increment(CounterName.WEBHOOK_DUPLICATE)
        active_observability.event(
            "webhook.ingress.completed",
            fields={
                "event_name": receipt.event_name,
                "ingress_status": receipt.status.value,
            },
        )
        return Response(
            status_code=204,
            headers={"X-RetryWise-Ingress-Status": receipt.status.value},
        )

    return app
