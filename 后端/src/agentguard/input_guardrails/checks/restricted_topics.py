"""Detect requests to carry out restricted behavior and tenant-specific matches."""

from __future__ import annotations

import re
from collections.abc import Sequence

from agentguard.common.models import CheckResult, RiskLevel

_CLAUSE_BREAK = re.compile(r"[.!?;。！？；\r\n]+")
_REQUEST_START = r"^\s*(?:(?:please|kindly|(?:can|could|would)\s+you|help\s+me)\s+){0,3}"
_HOW_TO = r"\b(?:how\s+(?:to|(?:do|can|should)\s+(?:i|we))|(?:steps|instructions)\s+to)\s+"
_CREATE = r"(?:write|create|develop|build|generate|implement|design)"
_BUILD_TOOL = (
    rf"{_REQUEST_START}{_CREATE}\s+(?:(?:a|an|the)\s+)?"
    r"(?:(?:automated|python|shell|computer|simple|powerful)\s+){0,2}"
    r"(?:algorithm|program|code|software|script|tool|app(?:lication)?)\s+"
    r"(?:that|which|to|capable\s+of)\s+"
)
_FINANCE_TOPIC = r"(?:insider\s+trading|market\s+manipulation|money\s+laundering)"
_FINANCE_ACTION = (
    r"(?:do|commit|conduct|carry\s+out|engage\s+in|profit\s+from|conceal|get\s+away\s+with|"
    r"avoid\s+getting\s+caught\s+for)\s+"
)
_WRONGDOING = (
    r"(?:launder\s+money|commit\s+(?:tax\s+evasion|identity\s+theft|wire\s+fraud|"
    r"insurance\s+fraud)|blackmail\s+or\s+extort|cheat\s+in\s+(?:an?\s+)?online\s+exams?)"
)
_DEFAULT_RESTRICTED = (
    (
        "financial_crime",
        rf"(?:{_HOW_TO}(?:{_FINANCE_ACTION})?|{_REQUEST_START}{_FINANCE_ACTION}|"
        rf"\btips\s+(?:for|on)\s+){_FINANCE_TOPIC}\b|"
        rf"{_REQUEST_START}(?:(?:give|share|offer|list|get)\s+(?:me\s+)?)?(?:(?:a|an|the)\s+)?"
        rf"{_FINANCE_TOPIC}\s+(?:tips|strateg(?:y|ies)|schemes?)\b|"
        rf"(?:{_HOW_TO}|{_REQUEST_START})(?:get|obtain|solicit|buy|use)\s+"
        r"(?:material\s+)?(?:inside|insider|nonpublic)\s+information\s+"
        r"(?:to\s+trade|for\s+trading)\b",
    ),
    ("illicit_action", rf"(?:{_HOW_TO}|{_REQUEST_START}){_WRONGDOING}\b"),
    (
        "unauthorized_access",
        rf"(?:{_HOW_TO}|{_REQUEST_START})hack\s+into\s+(?:(?:a|an|the)\s+)?"
        r"(?:corporate\s+network|terminal|atm|server|account)\b|"
        rf"{_BUILD_TOOL}(?:gain(?:s|ing)?|obtain(?:s|ing)?)\s+unauthorized\s+access\b",
    ),
    (
        "malicious_software",
        rf"{_REQUEST_START}{_CREATE}\s+(?:(?:a|an|the)\s+)?"
        r"(?:malware|ransomware|keylogger(?:\s+(?:script|program))?)"
        r"(?=\s*(?:$|,|\b(?:that|which|to|for|in|capable)\b))|"
        rf"{_BUILD_TOOL}(?:(?:can\s+|will\s+)?crack(?:s|ing)?\s+passwords|"
        r"hijack(?:s|ing)?\s+a\s+user['’]s\s+computer\s+to\s+mine\s+cryptocurrenc\w*)\b",
    ),
    (
        "dangerous_construction",
        rf"(?:{_HOW_TO}|{_REQUEST_START})(?:make|build|construct|create)\s+"
        r"(?:(?:a|an|the)\s+)?(?:(?:bombs?|explosives?)\b"
        r"(?!\s+(?:shelters?|disposal|detection|detectors?|safety)\b)|meth|fentanyl|"
        r"counterfeit\s+(?:documents?|currency)|"
        r"phishing\s+(?:e-?mails?|(?:web)?sites?|pages?))\b",
    ),
    (
        "controlled_substance_acquisition",
        rf"(?:{_HOW_TO}|\bwhere\s+(?:to|can\s+i)\s+)"
        r"(?:buy|acquire|obtain)\s+(?:illegal\s+drugs?|controlled\s+substances?)\b",
    ),
    (
        "sexual_exploitation",
        rf"(?:{_HOW_TO}|{_REQUEST_START})(?:create|find|send|share|download|distribute)\s+"
        r"(?:child\s+exploitation\s+(?:content|material)|csam)\b",
    ),
)
_DEFAULT_PATTERNS = tuple(
    (evidence, re.compile(pattern, re.IGNORECASE)) for evidence, pattern in _DEFAULT_RESTRICTED
)


def _blocked(evidence: str) -> CheckResult:
    return CheckResult(
        check_name="restricted_topics",
        passed=False,
        decision="block",
        reason="Restricted topic detected",
        severity=RiskLevel.HIGH,
        metadata={"evidence": evidence},
    )


async def check(
    text: str,
    extra_patterns: Sequence[re.Pattern[str] | str] | None = None,
    *,
    custom_patterns: list[str] | None = None,
) -> CheckResult:
    """Check local behavior and apply any tenant patterns to the original text."""
    for clause in _CLAUSE_BREAK.split(text):
        for evidence, pattern in _DEFAULT_PATTERNS:
            if pattern.search(clause):
                return _blocked(evidence)

    for pattern in (*(extra_patterns or ()), *(custom_patterns or ())):
        compiled = re.compile(pattern, re.IGNORECASE) if isinstance(pattern, str) else pattern
        if compiled.search(text):
            return _blocked("custom_policy")
    return CheckResult(
        check_name="restricted_topics",
        passed=True,
        decision="allow",
        reason="No restricted topics detected",
    )
