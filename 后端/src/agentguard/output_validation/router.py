"""Output validation API router."""

from __future__ import annotations

import time

import structlog
from fastapi import APIRouter, Depends, Request

from agentguard.common.dependencies import get_request_context
from agentguard.common.models import RequestContext
from agentguard.config import settings
from agentguard.observability.audit import record_audit
from agentguard.observability.metrics import metrics
from agentguard.output_validation.engine import validate_output
from agentguard.output_validation.schemas import OutputValidationRequest, OutputValidationResponse
from agentguard.slop_score.scorer import compute_slop_score

router = APIRouter(prefix="/v1/outputs", tags=["output-validation"])
logger = structlog.get_logger()


@router.post(
    "/validate",
    response_model=OutputValidationResponse,
    summary="Validate LLM output for safety, accuracy, and quality",
    description=(
        "Runs 8 parallel checks: JSON schema validity, citation presence, "
        "hallucination proxy, policy violations, unsafe language, confidence "
        "threshold, genericity detection, and canary/system-prompt leak detection. "
        "Returns an aggregate decision (pass/repair/reject/escalate)."
    ),
)
async def validate_output_endpoint(
    request: Request,
    body: OutputValidationRequest,
    ctx: RequestContext = Depends(get_request_context),
) -> OutputValidationResponse:
    t0 = time.perf_counter()
    decision, checks = await validate_output(
        body.output_text,
        context_text=body.context_text,
        expected_schema=body.expected_schema,
        require_citations=body.require_citations,
        min_confidence=body.min_confidence,
        system_prompt=body.system_prompt,
        canary_tokens=body.canary_tokens,
    )
    elapsed_ms = (time.perf_counter() - t0) * 1000
    request.state.agentguard_output_validation_ms = elapsed_ms
    if settings.enable_guardrail_timing_logs:
        logger.info(
            "output_validation.timing",
            duration_ms=round(elapsed_ms, 3),
            correlation_id=ctx.correlation_id,
        )
    meta = dict(body.metadata)
    if body.include_quality_risk_score:
        grounded = bool(body.context_text and body.context_text.strip())
        schema_chk = next((c for c in checks if c.check_name == "schema_validity"), None)
        schema_valid = (
            bool(schema_chk and schema_chk.passed) if body.expected_schema is not None else True
        )
        slop = compute_slop_score(
            list(checks),
            grounded=grounded,
            schema_valid=schema_valid,
            action_risk=0.0,
        )
        meta["quality_risk_score"] = slop.quality_risk_score
        meta["quality_risk_decision"] = slop.decision

    if settings.enable_audit_log:
        record_audit(
            tenant_id=ctx.tenant_id,
            correlation_id=ctx.correlation_id,
            module="output_validation",
            decision=decision.value,
            reason="Output validated",
            metadata={
                "elapsed_ms": round(elapsed_ms, 3),
                "failed_checks": [check.check_name for check in checks if not check.passed],
            },
        )
    metrics.increment("output_validation.requests", tags={"decision": decision.value})
    return OutputValidationResponse(
        correlation_id=ctx.correlation_id,
        decision=decision,
        checks=checks,
        metadata=meta,
    )
