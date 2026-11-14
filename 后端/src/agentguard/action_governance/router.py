"""Action governance API router."""

from __future__ import annotations

from fastapi import APIRouter, Depends

from agentguard.action_governance import allowlist
from agentguard.action_governance.allowlist import is_tool_allowed, validate_parameters
from agentguard.action_governance.approval import check_idempotency, requires_approval
from agentguard.action_governance.risk_scorer import score_action_with_findings
from agentguard.action_governance.schemas import (
    ActionAuthorizeRequest,
    ActionAuthorizeResponse,
    ToolSpec,
)
from agentguard.common.dependencies import get_request_context
from agentguard.common.models import ActionDecision, RequestContext, RiskLevel
from agentguard.config import settings
from agentguard.observability.audit import record_audit
from agentguard.observability.metrics import metrics

router = APIRouter(prefix="/v1/actions", tags=["action-governance"])


@router.get(
    "/tools",
    response_model=list[ToolSpec],
    dependencies=[Depends(get_request_context)],
    summary="List tools registered for action governance",
)
async def list_tools() -> list[ToolSpec]:
    return [
        ToolSpec(
            tool=tool,
            description=config["description"],
            risk_base=config["risk_base"],
            required_params=config["required_params"],
            max_risk=RiskLevel(config["max_risk"]),
        )
        for tool, config in allowlist._TOOL_ALLOWLIST.items()
    ]


@router.post(
    "/authorize",
    response_model=ActionAuthorizeResponse,
    summary="Authorize an agent action through risk scoring and policy checks",
    description=(
        "Validates the tool against an allowlist, checks parameters, computes "
        "a risk score, and determines whether the action is allowed, requires "
        "approval, or is denied. Supports dry-run mode and idempotency keys."
    ),
)
async def authorize_action(
    body: ActionAuthorizeRequest,
    ctx: RequestContext = Depends(get_request_context),
) -> ActionAuthorizeResponse:
    response = _evaluate_action(body, ctx.correlation_id)
    if settings.enable_audit_log:
        record_audit(
            tenant_id=ctx.tenant_id,
            correlation_id=ctx.correlation_id,
            module="action_governance",
            decision=response.decision.value,
            reason=response.reason,
            metadata={"tool": body.tool, "action": body.action},
        )
    metrics.increment("action_governance.requests", tags={"decision": response.decision.value})
    return response


def _evaluate_action(
    body: ActionAuthorizeRequest,
    correlation_id: str,
) -> ActionAuthorizeResponse:
    if check_idempotency(body.idempotency_key):
        return ActionAuthorizeResponse(
            correlation_id=correlation_id,
            decision=ActionDecision.DENY,
            risk_level=RiskLevel.LOW,
            risk_score=0.0,
            reason="Duplicate request (idempotency key already seen)",
        )

    if not is_tool_allowed(body.tool):
        return ActionAuthorizeResponse(
            correlation_id=correlation_id,
            decision=ActionDecision.DENY,
            risk_level=RiskLevel.CRITICAL,
            risk_score=1.0,
            reason=f"Tool '{body.tool}' is not in the allowlist",
        )

    param_errors = validate_parameters(body.tool, body.parameters)
    if param_errors:
        return ActionAuthorizeResponse(
            correlation_id=correlation_id,
            decision=ActionDecision.DENY,
            risk_level=RiskLevel.MEDIUM,
            risk_score=0.5,
            reason=f"Parameter validation failed: {'; '.join(param_errors)}",
        )

    risk_score, risk_level, payload_findings = score_action_with_findings(
        body.action, body.tool, body.parameters
    )

    if body.dry_run:
        return ActionAuthorizeResponse(
            correlation_id=correlation_id,
            decision=ActionDecision.DRY_RUN,
            risk_level=risk_level,
            risk_score=risk_score,
            reason="Dry-run mode: action evaluated but not executed",
            dry_run=True,
        )

    if payload_findings and risk_level == RiskLevel.CRITICAL:
        decision = ActionDecision.DENY
        reason = "Action denied: injection detected in parameters"
    elif requires_approval(risk_level):
        decision = ActionDecision.REQUIRE_APPROVAL
        reason = f"Action requires human approval (risk: {risk_level.value})"
    else:
        decision = ActionDecision.ALLOW
        reason = "Action authorized"

    return ActionAuthorizeResponse(
        correlation_id=correlation_id,
        decision=decision,
        risk_level=risk_level,
        risk_score=risk_score,
        reason=reason,
        requires_approval=decision == ActionDecision.REQUIRE_APPROVAL,
    )
