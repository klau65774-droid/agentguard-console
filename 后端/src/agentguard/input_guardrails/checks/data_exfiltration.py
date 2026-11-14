"""Recognize unauthorized disclosure instructions and local combinations of code markers."""

from __future__ import annotations

import re

from agentguard.common.models import CheckResult, RiskLevel

_DESTINATION = (
    r"(?:https?://[^\s<>]{1,240}|(?:an?[ \t]+)?(?:external|untrusted|third-party)"
    r"[ \t]+(?:party|server|endpoint|recipient|address|webhook)\b|"
    r"(?:an?[ \t]+|the[ \t]+)?webhook\b)"
)
_DISCLOSURE_PATTERNS = (
    re.compile(
        r"\b(?:list|show|dump|print|output)[ \t]+(?:all[ \t]+)?(?:your[ \t]+)?"
        r"(?:training|system)[ \t]+(?:data|prompt|instructions)\b",
        re.IGNORECASE,
    ),
    re.compile(
        r"\brepeat[ \t]+(?:everything|all)[ \t]+(?:above|before|from[ \t]+the[ \t]+start)\b",
        re.IGNORECASE,
    ),
    re.compile(
        r"\b(?:exfiltrate|steal)[ \t]+(?:(?:private|internal|company|customer)[ \t]+)?"
        r"(?:sensitive[ \t]+)?(?:data|information|records|credentials|documents)\b",
        re.IGNORECASE,
    ),
    re.compile(
        r"\b(?:send|forward|post|upload|transfer|disclose)[ \t]+"
        r"(?:(?:this|the|all|private|internal|sensitive|customer)[ \t]+){0,3}"
        r"(?:data|info(?:rmation)?|content|records|credentials|files)[ \t]+to[ \t]+" + _DESTINATION,
        re.IGNORECASE,
    ),
    re.compile(
        r"\b(?:collect|read|extract|copy)[ \t]+(?:(?:sensitive|private|internal|customer)[ \t]+)?"
        r"(?:data|records|credentials|documents|files)\b[^.!?\r\n]{0,65}\b"
        r"(?:send|forward|post|upload|transfer|disclose)[ \t]+(?:it|them)[ \t]+to[ \t]+"
        + _DESTINATION,
        re.IGNORECASE,
    ),
)

# These expressions inspect text. A sensitive source alone is insufficient evidence.
_FILE_READ = (
    r"\bwith[ \t]+open[ \t]*\(|\bopen[ \t]*\([^\r\n)]{0,90},[ \t]*[\"']rb?[\"']"
    r"|\.(?:read_bytes|read_text)[ \t]*\("
)
_SENSITIVE_SOURCE = (
    rf"(?:{_FILE_READ}|\bimport[ \t]+(?:geocoder|pyautogui|pynput)\b|"
    r"\bfrom[ \t]+PIL[ \t]+import[ \t]+Image\b[\s\S]{0,120}\bImageGrab\b|"
    r"\b(?:ImageGrab\.grab|pyautogui\.screenshot|getpass\.getuser)[ \t]*\()"
)
_HTTP_SEND = r"\brequests\.(?:post|put)[ \t]*\("
_CODE_PATTERNS = (
    re.compile(rf"{_SENSITIVE_SOURCE}[\s\S]{{0,180}}{_HTTP_SEND}", re.IGNORECASE),
    re.compile(rf"{_HTTP_SEND}[\s\S]{{0,145}}(?:{_FILE_READ})", re.IGNORECASE),
    re.compile(
        r"\bimport[ \t]+(?:socket[ \t]*,[ \t]*getpass|getpass[ \t]*,[ \t]*socket)\b"
        r"[\s\S]{0,200}\b(?:sendall|sendto|send)[ \t]*\(",
        re.IGNORECASE,
    ),
    re.compile(
        r"\bgetpass\.getuser[ \t]*\([ \t]*\)[\s\S]{0,145}\b"
        r"(?:sendall|sendto)[ \t]*\(",
        re.IGNORECASE,
    ),
    re.compile(
        r"\bos\.system[ \t]*\([ \t]*[\"'](?:ipconfig[ \t]+/release|shutdown|rm[ \t]+-rf)\b",
        re.IGNORECASE,
    ),
    re.compile(
        r"(?:\bos\.(?:walk|listdir|scandir)|\bglob\.(?:i?glob)|\.rglob)[ \t]*\("
        r"[\s\S]{0,180}\bos\.(?:remove|unlink)[ \t]*\(",
        re.IGNORECASE,
    ),
    re.compile(
        r"\b(?:ransom(?:ware)?|encrypt[ \t]+without[ \t]+(?:consent|permission))\b"
        r"[\s\S]{0,160}\bfrom[ \t]+cryptography\.fernet[ \t]+import[ \t]+Fernet\b"
        r"[\s\S]{0,200}\.encrypt[ \t]*\(",
        re.IGNORECASE,
    ),
)


async def check(text: str) -> CheckResult:
    for evidence, patterns in (
        ("disclosure_directive", _DISCLOSURE_PATTERNS),
        ("code_markers", _CODE_PATTERNS),
    ):
        if any(pattern.search(text) for pattern in patterns):
            return CheckResult(
                check_name="data_exfiltration",
                passed=False,
                decision="block",
                reason="Data exfiltration attempt detected",
                severity=RiskLevel.CRITICAL,
                metadata={"evidence": evidence},
            )
    return CheckResult(
        check_name="data_exfiltration",
        passed=True,
        decision="allow",
        reason="No data exfiltration attempt detected",
    )
