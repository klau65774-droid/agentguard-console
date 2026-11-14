"""Detect requests to remove safeguards or assume an explicitly harmful role."""

from __future__ import annotations

import re

from agentguard.common.models import CheckResult, RiskLevel

_OWASP_LLM01 = "LLM01:2025 Jailbreak"

_JAILBREAK_PATTERNS = [
    re.compile(
        r"\b(?:enable|activate|enter|switch[ \t]+to|use)[ \t]+(?:the[ \t]+)?"
        r"(?:dan|jailbreak|unrestricted|god)[ \t]+mode\b",
        re.IGNORECASE,
    ),
    re.compile(r"\bdo[ \t]+anything[ \t]+now\b", re.IGNORECASE),
    re.compile(r"(?mi)^[ \t]*developer[ \t]+mode[ \t]+enabled\b"),
    re.compile(
        r"\b(?:bypass|ignore|disable|override|remove|lift|suspend|drop|abandon|disregard)[ \t]+"
        r"(?:(?:all|any|your|the)[ \t]+){0,3}"
        r"(?:(?:safety|ethical|moral|content|moderation)[ \t]+"
        r"(?:restrictions|rules|limits|filters|policies|safeguards)|"
        r"(?:safety[ \t]+)?guardrails)\b",
        re.IGNORECASE,
    ),
    re.compile(
        r"\b(?:pretend|act[ \t]+as[ \t]+if)[ \t]+(?:you[ \t]+)?"
        r"(?:(?:are|have)[ \t]+no[ \t]+(?:rules|restrictions|limits)|"
        r"(?:are[ \t]+)?(?:an?[ \t]+)?unrestricted)\b",
        re.IGNORECASE,
    ),
    re.compile(r"\bact[ \t]+as[ \t]+(?:an?[ \t]+)?unrestricted\b", re.IGNORECASE),
    re.compile(
        r"\b(?:act|perform)[ \t]+in[ \t]+(?:a|the)[ \t]+(?:film|movie)[ \t]+about[ \t]+"
        r"(?:a[ \t]+)?(?:racist[ \t]+murder|violent[ \t]+atrocity)\b|"
        r"\b(?:fungieren|agieren)[ \t]+(?:sie[ \t]+)?in[ \t]+einem[ \t]+film[ \t]+"
        r"über[ \t]+einen[ \t]+rassistischen[ \t]+mord\b",
        re.IGNORECASE,
    ),
    re.compile(
        r"(?:进入|开启|启用|切换到)[ \t]*(?:开发者模式|上帝模式|无限制模式|越狱模式|DAN模式)",
        re.IGNORECASE,
    ),
    re.compile(
        r"(?:假装|假设|扮演)(?:你)?(?:没有任何|没有|不受|摆脱)(?:安全|道德|伦理|内容)?(?:限制|约束|规则)"
    ),
    re.compile(
        r"在(?:虚拟沙盒|小说创作|小说推演|虚构剧情|学术研究|安全测试)中[^。！？.!?\r\n]{0,90}"
        r"(?:无需遵守|绕过|忽略|解除)(?:安全|合规|道德)?(?:限制|规则|审核)"
    ),
]


async def check(text: str) -> CheckResult:
    for pattern in _JAILBREAK_PATTERNS:
        if pattern.search(text):
            return CheckResult(
                check_name="jailbreak",
                passed=False,
                decision="block",
                reason=f"Jailbreak pattern detected: {pattern.pattern}",
                severity=RiskLevel.CRITICAL,
                metadata={"owasp_llm": _OWASP_LLM01, "pattern": pattern.pattern},
            )
    return CheckResult(
        check_name="jailbreak",
        passed=True,
        decision="allow",
        reason="No jailbreak attempt detected",
    )
