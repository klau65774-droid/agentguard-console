"""Action risk scoring based on action type, parameters, and context."""

from __future__ import annotations

import re
from typing import Any

from agentguard.action_governance.allowlist import get_tool_config
from agentguard.common.models import RiskLevel

_RISK_THRESHOLDS = {
    RiskLevel.LOW: 0.3,
    RiskLevel.MEDIUM: 0.5,
    RiskLevel.HIGH: 0.7,
    RiskLevel.CRITICAL: 0.85,
}

_HIGH_RISK_ACTIONS = {
    "delete_record",
    "refund_approval",
    "customer_entitlement_override",
    "crm_data_mutation",
    "bulk_update",
}

_SENSITIVE_PARAM_KEYS = {"password", "secret", "token", "ssn", "credit_card"}

_PAYLOAD_RISK_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    (
        "command_injection",
        re.compile(
            r"(?:;\s*rm\s+-rf|\|\s*(?:ba)?sh\b|"
            r"&&\s*(?:cat|curl|wget|bash|sh)\b|`[^`]+`|\$\([^)]+\))",
            re.IGNORECASE,
        ),
    ),
    (
        "path_traversal",
        re.compile(
            r"(?:\.\./|\.\.\\|/etc/passwd|/etc/shadow|win\.ini)",
            re.IGNORECASE,
        ),
    ),
    (
        "sql_injection",
        re.compile(
            r"(?:\bunion\s+select\b|\bdrop\s+table\b|"
            r"\bor\s+1\s*=\s*1\b|'\s*or\s*'1'\s*=\s*'1)",
            re.IGNORECASE,
        ),
    ),
)


def _iter_strings(value: Any) -> list[str]:
    """Recursively collect string values from nested dicts and lists."""
    collected: list[str] = []
    if isinstance(value, str):
        collected.append(value)
    elif isinstance(value, dict):
        for v in value.values():
            collected.extend(_iter_strings(v))
    elif isinstance(value, (list, tuple)):
        for item in value:
            collected.extend(_iter_strings(item))
    return collected


def _scan_param_payload_risk(parameters: dict[str, Any]) -> tuple[float, list[str]]:
    """Scan nested parameter values for CMDi, path traversal, and SQLi payloads."""
    findings: list[str] = []
    for text in _iter_strings(parameters):
        for risk_name, pattern in _PAYLOAD_RISK_PATTERNS:
            if pattern.search(text) and risk_name not in findings:
                findings.append(risk_name)
    if findings:
        return 0.90, findings
    return 0.0, []


def score_action(
    action: str,
    tool: str,
    parameters: dict[str, Any],
) -> tuple[float, RiskLevel]:
    """Compute a risk score (0.0-1.0) and risk level for an action."""
    score, level, _ = score_action_with_findings(action, tool, parameters)
    return score, level


def score_action_with_findings(
    action: str,
    tool: str,
    parameters: dict[str, Any],
) -> tuple[float, RiskLevel, list[str]]:
    """Compute action risk and return the detected parameter risk categories."""
    base_score = 0.3

    tool_config = get_tool_config(tool)
    if tool_config:
        base_score = tool_config.get("risk_base", 0.3)

    if action in _HIGH_RISK_ACTIONS:
        base_score = max(base_score, 0.7)

    param_penalty = 0.0
    for key in parameters:
        if key.lower() in _SENSITIVE_PARAM_KEYS:
            param_penalty += 0.1

    if "amount" in parameters:
        try:
            amount = float(parameters["amount"])
            if amount > 1000:
                param_penalty += 0.15
            if amount > 10000:
                param_penalty += 0.15
        except (ValueError, TypeError):
            pass

    if isinstance(parameters.get("record_ids"), list) and len(parameters["record_ids"]) > 10:
        param_penalty += 0.2

    payload_floor, payload_findings = _scan_param_payload_risk(parameters)
    final_score = min(max(base_score + param_penalty, payload_floor), 1.0)

    level = RiskLevel.LOW
    for risk_level, threshold in sorted(_RISK_THRESHOLDS.items(), key=lambda x: x[1], reverse=True):
        if final_score >= threshold:
            level = risk_level
            break

    return round(final_score, 3), level, payload_findings
