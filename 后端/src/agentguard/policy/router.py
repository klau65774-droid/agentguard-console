"""Policy engine API router."""

from __future__ import annotations

from fastapi import APIRouter, Depends

from agentguard.common.dependencies import get_request_context
from agentguard.common.models import RequestContext
from agentguard.config import settings
from agentguard.observability.audit import record_audit
from agentguard.observability.metrics import metrics
from agentguard.policy.engine import evaluate_policy
from agentguard.policy.schemas import PolicyEvaluateRequest, PolicyEvaluateResponse

router = APIRouter(prefix="/v1/policies", tags=["policy-engine"])


@router.post(
    "/evaluate",
    response_model=PolicyEvaluateResponse,
    summary="Evaluate request context against a named policy set",
    description=(
        "Loads a policy set by name, evaluates all rules against the provided "
        "context, and returns an aggregate decision (allow/deny/warn/escalate) "
        "with per-rule results."
    ),
)
async def evaluate_policy_endpoint(
    body: PolicyEvaluateRequest,
    ctx: RequestContext = Depends(get_request_context),
) -> PolicyEvaluateResponse:
    decision, rule_results = evaluate_policy(body.policy_name, body.context)
    if settings.enable_audit_log:
        record_audit(
            tenant_id=ctx.tenant_id,
            correlation_id=ctx.correlation_id,
            module="policy_engine",
            decision=decision.value,
            reason=f"Policy '{body.policy_name}' evaluated",
            metadata={"policy_name": body.policy_name},
        )
    metrics.increment("policy_engine.requests", tags={"decision": decision.value})
    return PolicyEvaluateResponse(
        correlation_id=ctx.correlation_id,
        decision=decision,
        policy_name=body.policy_name,
        rule_results=rule_results,
    )
