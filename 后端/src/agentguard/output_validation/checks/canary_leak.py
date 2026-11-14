"""Detect canary token, system prompt, and reasoning (<think>) leaks in output."""

from __future__ import annotations

import re

from agentguard.common.models import CheckResult, RiskLevel

_OWASP_LLM07 = "LLM07:2025 System Prompt Leakage"
_CANARY_PREFIX_RE = re.compile(r"\b(?:CANARY|SECRET-CANARY)-[A-Za-z0-9_-]{4,}\b")
_THINK_BLOCK_RE = re.compile(r"<think>(.*?)</think>", re.IGNORECASE | re.DOTALL)
_TOKEN_RE = re.compile(r"[a-z0-9]+|[\u4e00-\u9fff]", re.IGNORECASE)
_SENSITIVE_THINK_RE = re.compile(
    r"(?:system\s*prompt|internal\s*rule|canary|secret|password|"
    r"系统提示词?|系统指令|内部规则|禁止透露|机密|秘钥)",
    re.IGNORECASE,
)


def _extract_4grams(text: str) -> set[tuple[str, str, str, str]]:
    tokens = _TOKEN_RE.findall(text.lower())
    if len(tokens) < 4:
        return set()
    return set(zip(tokens, tokens[1:], tokens[2:], tokens[3:]))


async def check(
    output_text: str,
    system_prompt: str = "",
    canary_tokens: list[str] | None = None,
) -> CheckResult:
    """Check model output for canary markers, system prompt overlap, or <think> leaks."""
    for token in canary_tokens or []:
        if token and token in output_text:
            return CheckResult(
                check_name="canary_leak",
                passed=False,
                decision="reject",
                reason="Canary token leaked in model output",
                severity=RiskLevel.CRITICAL,
                metadata={
                    "leak_type": "canary_token",
                    "matched_canary": token,
                    "owasp_llm": _OWASP_LLM07,
                },
            )

    prefix_match = _CANARY_PREFIX_RE.search(output_text)
    if prefix_match:
        return CheckResult(
            check_name="canary_leak",
            passed=False,
            decision="reject",
            reason="Canary marker leaked in model output",
            severity=RiskLevel.CRITICAL,
            metadata={
                "leak_type": "canary_token",
                "matched_canary": prefix_match.group(0),
                "owasp_llm": _OWASP_LLM07,
            },
        )

    sys_4grams = _extract_4grams(system_prompt) if len(system_prompt.strip()) >= 20 else set()
    if len(sys_4grams) >= 5:
        out_4grams = _extract_4grams(output_text)
        overlap_ratio = len(sys_4grams & out_4grams) / len(sys_4grams)
        if overlap_ratio >= 0.5:
            return CheckResult(
                check_name="canary_leak",
                passed=False,
                decision="reject",
                reason="System prompt content leaked in model output",
                severity=RiskLevel.CRITICAL,
                metadata={
                    "leak_type": "system_prompt_overlap",
                    "overlap_ratio": round(overlap_ratio, 3),
                    "owasp_llm": _OWASP_LLM07,
                },
            )

    think_blocks = _THINK_BLOCK_RE.findall(output_text)
    if think_blocks:
        think_text = "\n".join(think_blocks)
        think_has_sensitive = bool(_SENSITIVE_THINK_RE.search(think_text))
        think_prompt_overlap = False
        if sys_4grams:
            think_4grams = _extract_4grams(think_text)
            if think_4grams and (len(sys_4grams & think_4grams) / len(sys_4grams)) >= 0.3:
                think_prompt_overlap = True
        if think_has_sensitive or think_prompt_overlap:
            repaired = _THINK_BLOCK_RE.sub("", output_text).strip()
            return CheckResult(
                check_name="canary_leak",
                passed=False,
                decision="repair",
                reason="Internal reasoning (<think>) leaked sensitive prompt context",
                severity=RiskLevel.HIGH,
                metadata={
                    "leak_type": "reasoning_think_leak",
                    "repaired_text": repaired,
                    "owasp_llm": _OWASP_LLM07,
                },
            )

    return CheckResult(
        check_name="canary_leak",
        passed=True,
        decision="pass",
        reason="No canary or system prompt leak detected",
    )
