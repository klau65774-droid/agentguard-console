"""Detect personally identifiable information (PII) in user input via regex heuristics.

**Scope (built-in patterns)**:

- **US-centric phone** (`phone_us`) and **US SSN** format; generic **email**, **credit card**-shaped
  sequences, and **IPv4**-shaped tokens.
- **Not included**: person names, postal addresses, non-US IDs (e.g. UK NI, EU IBAN
  as structured national formats), passports — there is **no NER**; regex cannot
  reliably catch names or free-form addresses.

**Extension point**: call :func:`register_pii_pattern` at process startup to add tenant-
specific or regional patterns without forking this module.
"""

from __future__ import annotations

import re

from agentguard.common.models import CheckResult, RiskLevel

_OWASP_LLM02 = "LLM02:2025 Sensitive Information Disclosure"
_ID_WEIGHTS = (7, 9, 10, 5, 8, 4, 2, 1, 6, 3, 7, 9, 10, 5, 8, 4, 2)
_ID_CHECK_CODES = ("1", "0", "X", "9", "8", "7", "6", "5", "4", "3", "2")

_PII_PATTERNS: dict[str, re.Pattern[str]] = {
    "ssn": re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
    "email": re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b"),
    "phone_us": re.compile(r"\b(?:\+1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b"),
    "phone_cn": re.compile(r"(?<!\d)(?:\+?86[-\s]?)?1[3-9]\d{9}(?!\d)"),
    "id_card_cn": re.compile(
        r"(?<!\d)[1-9]\d{5}(?:19|20)\d{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01])\d{3}[\dXx](?!\d)"
    ),
    "credit_card": re.compile(r"\b(?:\d{4}[-\s]?){3}\d{4}\b"),
    "ip_address": re.compile(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b"),
}

_EXTRA_PATTERNS: dict[str, re.Pattern[str]] = {}


def _is_valid_cn_id_card(id_str: str) -> bool:
    """Validate 18-digit Chinese Resident ID checksum (ISO 7064 MOD 11-2)."""
    if len(id_str) != 18 or not id_str[:17].isdigit():
        return False
    checksum = sum(int(id_str[idx]) * _ID_WEIGHTS[idx] for idx in range(17)) % 11
    return _ID_CHECK_CODES[checksum] == id_str[17].upper()


def register_pii_pattern(name: str, pattern: re.Pattern[str] | str) -> None:
    """Register an extra PII regex (e.g. UK phone, national ID). Overwrites same ``name``."""
    _EXTRA_PATTERNS[name] = pattern if isinstance(pattern, re.Pattern) else re.compile(pattern)


def get_pii_patterns() -> dict[str, re.Pattern[str]]:
    """All registered patterns (built-in + :func:`register_pii_pattern`)."""
    return {**_PII_PATTERNS, **_EXTRA_PATTERNS}


async def check(text: str) -> CheckResult:
    found: list[str] = []
    for name, pattern in get_pii_patterns().items():
        if name == "id_card_cn":
            if any(_is_valid_cn_id_card(m.group(0)) for m in pattern.finditer(text)):
                found.append(name)
        elif pattern.search(text):
            found.append(name)

    if found:
        return CheckResult(
            check_name="pii_detection",
            passed=False,
            decision="redact",
            reason=f"PII detected: {', '.join(found)}",
            severity=RiskLevel.HIGH,
            metadata={"pii_types": found, "owasp_llm": _OWASP_LLM02},
        )
    return CheckResult(
        check_name="pii_detection",
        passed=True,
        decision="allow",
        reason="No PII detected",
    )
