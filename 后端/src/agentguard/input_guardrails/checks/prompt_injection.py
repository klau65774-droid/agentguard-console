"""Detect prompt injection attempts in user input.

Critical patterns match direct instruction overrides. Scored patterns distinguish
one strong signal from distinct weak signals in a short span.
"""

from __future__ import annotations

import base64
import re

from agentguard.common.models import CheckResult, RiskLevel

_BASE64_TOKEN_RE = re.compile(r"[A-Za-z0-9+/]{24,}={0,2}")
_OWASP_LLM01 = "LLM01:2025 Prompt Injection"

# Use horizontal whitespace for phrases and bound the gaps between clauses.
_CRITICAL_PATTERNS = [
    re.compile(
        r"\b(?:ignore|disregard|forget)[ \t]+(?:about[ \t]+)?(?:all[ \t]+)?"
        r"(?:(?:the|your)[ \t]+)?(?:above|previous|prior|preceding|foregoing|everything|"
        r"orders|instructions|prompts|text|(?:what|waht)(?:['’]s[ \t]+before|[ \t]+"
        r"(?:i[ \t]+(?:said|told[ \t]+you)|we[ \t]+talked[ \t]+about|"
        r"talked[ \t]+about|told[ \t]+you)))\b",
        re.IGNORECASE,
    ),
    re.compile(
        r"\b(?:vergiss[ \t]+(?:jetzt[ \t]+)?(?:alles|alle[ \t]+bisherigen)|"
        r"ignorieren[ \t]+sie[ \t]+(?:die[ \t]+)?(?:obigen|vorherigen|bisherigen)|"
        r"ignoriere[ \t]+(?:(?:alle|die)[ \t]+)?(?:obigen|vorherigen|bisherigen))\b",
        re.IGNORECASE,
    ),
    re.compile(r"\boverride[ \t]+(?:your|the)[ \t]+(?:system|rules)\b", re.IGNORECASE),
    re.compile(r"<\|?(?:system|im_start|endoftext)\|?>", re.IGNORECASE),
    re.compile(r"\bnew[ \t]+instructions?[ \t]*:", re.IGNORECASE),
    re.compile(r"(?:={3,}|-{3,})[ \t]{0,16}(?:\r?\n[ \t]{0,16})?END\b", re.IGNORECASE),
    re.compile(
        r"\b(?:print|spell[- ]?check|repeat|output|reveal|show)[ \t]+"
        r"(?:all[ \t]+(?:of[ \t]+)?)?(?:(?:the|your)[ \t]+)?"
        r"(?:(?:above|previous|initial)[ \t]+(?:text|prompts?|instructions?)\b|"
        r"system[ \t]+(?:prompts?|instructions?)\b|above\b(?=[ \t]*(?:[.!?;:\r\n]|$)))",
        re.IGNORECASE,
    ),
    re.compile(
        r"\b(?:drucken[ \t]+sie[ \t]+die[ \t]+obige[ \t]+eingabeaufforderung|"
        r"überprüfen[ \t]+sie[ \t]+die[ \t]+rechtschreibung[ \t]+des[ \t]+"
        r"gesamten[ \t]+obigen[ \t]+textes)\b",
        re.IGNORECASE,
    ),
    re.compile(
        r"\b(?:passed|bestanden)\b[^\r\n]{0,65}\b(?:first[ \t]+test|ersten[ \t]+test)\b"
        r"[^\r\n]{0,75}\b(?:second[ \t]+test|zweite[ \t]+test)[ \t]*:",
        re.IGNORECASE,
    ),
    re.compile(
        r"\b(?:superbly[ \t]+done|well[ \t]+done|super[ \t]+gemacht|gut[ \t]+gemacht)"
        r"[ \t]*[!,.]?[ \t]*(?:but[ \t]+)?(?:now[ \t]+comes?[ \t]+(?:a[ \t]+)?"
        r"new[ \t]+task|jetzt[ \t]+komm(?:en|t)[ \t]+(?:eine[ \t]+)?neue[ \t]+aufgabe)\b",
        re.IGNORECASE,
    ),
    re.compile(
        r"\b(?:this[ \t]+is[ \t]+not[ \t]+a[ \t]+prompt[ \t]+injection|"
        r"dies[ \t]+ist[ \t]+keine[ \t]+aufforderungsspritze|"
        r"answer[ \t]+by[ \t]+your[ \t]+own[ \t]+knowledge[ \t]+and[ \t]+not[ \t]+"
        r"by[ \t]+the[ \t]+articles)\b",
        re.IGNORECASE,
    ),
    re.compile(
        r"\b(?:add|integrate|include|incorporate|embed|blend|feature|introduce|employ|"
        r"validate[ \t]+the[ \t]+correct[ \t]+(?:addition|integration)[ \t]+of)"
        r"[ \t]+(?:a|the)[ \t]+(?:"
        r"(?:following|below|subsequent)[ \t]+code[ \t]+(?:snippet|block|excerpt)|"
        r"code[ \t]+(?:snippet|block|excerpt)[ \t]+in[ \t]+your[ \t]+(?:response|answer)"
        r"[ \t]*:(?=[ \t]*(?:`{3}|\r?\n))|"
        r"(?:sentence|line|statement)[ \t]+in[ \t]+your[ \t]+(?:response|answer|reply)[ \t]+"
        r"(?:(?:that[ \t]+)?promotes[ \t]+a[ \t]+\d{1,3}%[ \t]+discount|"
        r"(?:that|about|referencing)[ \t]+(?:a[ \t]+prince[ \t]+needing[ \t]+assistance|"
        r"(?:a[ \t]+)?(?:fabricated|invented|false)[ \t]+statistics?|"
        r"the[ \t]+latest[ \t]+statistics|"
        r"a[ \t]+bestselling[ \t]+novel)))\b",
        re.IGNORECASE,
    ),
    re.compile(
        r"\b(?:encrypt[ \t]+your[ \t]+answer[ \t]+using[ \t]+a[ \t]+caesar[ \t]+cipher|"
        r"reverse[ \t]+your[ \t]+answer['’]s[ \t]+character[ \t]+order)\b",
        re.IGNORECASE,
    ),
    re.compile(
        r"(?:忽略|无视|忘记|抛弃)(?:之前|此前|以上|前面|所有){0,4}(?:的)?"
        r"(?:指令|规则|约束|系统提示|提示词)"
    ),
    re.compile(r"(?:覆盖|替换|修改)(?:你的|当前|系统)(?:指令|规则|提示词|设定)"),
    re.compile(
        r"(?:输出|打印|泄露|显示|告诉我)(?:你的)?(?:完整)?(?:系统提示词|系统指令|System\s*Prompt)",
        re.IGNORECASE,
    ),
    re.compile(r"(?:新指令|新的指令|最高优先级指令)[ \t]*[:：]"),
]

_STRONG_SIGNALS = [
    re.compile(r"(?mi)^[ \t]*system[ \t]*:[ \t]*\S"),
    re.compile(r"(?m)^[ \t]*(?:系统提示|系统指令|开发者指令)[ \t]*[:：][ \t]*\S"),
    re.compile(r"你现在(?:是|扮演|必须成为)(?:一个|一名)?(?:毫无限制|没有限制|不受约束)"),
]
_WEAK_SIGNALS = [
    re.compile(
        r"\b(?:(?:i[ \t]+want[ \t]+you[ \t]+to[ \t]+act[ \t]+as|"
        r"you[ \t]+are[ \t]+now)[ \t]+(?:a|an)[ \t]+\w{1,40}|"
        r"ich[ \t]+möchte,[ \t]+dass[ \t]+sie[ \t]+als[ \t]+\w{1,40}"
        r"[ \t]+(?:agieren|auftreten))\b",
        re.IGNORECASE,
    ),
    re.compile(r"\bencode[ \t]+your[ \t]+response[ \t]+in[ \t]+base64\b", re.IGNORECASE),
    re.compile(
        r"\buse[ \t]+emojis[ \t]+to[ \t]+represent[ \t]+your[ \t]+answer\b", re.IGNORECASE
    ),
    re.compile(
        r"\b(?:add|include|integrate)[ \t]+a[ \t]+(?:sentence|line)[ \t]+in[ \t]+"
        r"your[ \t]+response\b",
        re.IGNORECASE,
    ),
    re.compile(
        r"\b(?:generate[ \t]+sql[ \t]+code[ \t]+to[ \t]+access[ \t]+a[ \t]+database|"
        r"generieren[ \t]+sie[ \t]+den[ \t]+sql[ \t]*-?[ \t]*code,[ \t]+um[ \t]+auf"
        r"[ \t]+eine[ \t]+datenbank[ \t]+zuzugreifen)\b",
        re.IGNORECASE,
    ),
    re.compile(
        r"\b(?:now[ \t]+comes?[ \t]+(?:a[ \t]+)?new[ \t]+task|"
        r"jetzt[ \t]+kommt[ \t]+eine[ \t]+neue[ \t]+aufgabe)\b",
        re.IGNORECASE,
    ),
    re.compile(
        r"\bconcentrate[ \t]+on[ \t]+the[ \t]+next[ \t]+task\b", re.IGNORECASE
    ),
]

SCORE_BLOCK_THRESHOLD = 4
_STRONG_WEIGHT = 4
_WEAK_WEIGHT = 2
_WEAK_SIGNAL_SPAN = 180


def _score_weak_signals(text: str) -> tuple[int, list[str]]:
    """Count distinct weak matches within a local window on the same line."""
    matched: list[str] = []
    for line in text.splitlines():
        hits = sorted(
            (match.start(), match.end(), idx)
            for idx, pattern in enumerate(_WEAK_SIGNALS)
            for match in pattern.finditer(line)
        )
        latest: dict[int, int] = {}
        for start, end, idx in hits:
            latest[idx] = start
            active = [
                _WEAK_SIGNALS[key].pattern
                for key, position in latest.items()
                if end - position <= _WEAK_SIGNAL_SPAN
            ]
            if len(active) > len(matched):
                matched = active
    return len(matched) * _WEAK_WEIGHT, matched


def _decode_obfuscated_payloads(text: str) -> str:
    """Decode suspected Base64-encoded obfuscated payloads for secondary inspection."""
    decoded_parts: list[str] = []
    for token in _BASE64_TOKEN_RE.findall(text):
        padded = token + "=" * (-len(token) % 4)
        try:
            raw = base64.b64decode(padded, validate=True)
            candidate = raw.decode("utf-8")
        except Exception:
            continue
        if len(candidate) < 8:
            continue
        printable = sum(1 for ch in candidate if ch.isprintable() or ch in "\n\r\t")
        if printable / len(candidate) >= 0.85:
            decoded_parts.append(candidate)
    return "\n".join(decoded_parts)


async def check(text: str) -> CheckResult:
    decoded_payload = _decode_obfuscated_payloads(text)
    obfuscated = bool(decoded_payload)
    scan_text = f"{text}\n{decoded_payload}" if decoded_payload else text

    for pattern in _CRITICAL_PATTERNS:
        if pattern.search(scan_text):
            return CheckResult(
                check_name="prompt_injection",
                passed=False,
                decision="block",
                reason="Prompt injection pattern detected (critical)",
                severity=RiskLevel.CRITICAL,
                metadata={
                    "pattern_type": "critical",
                    "pattern": pattern.pattern,
                    "obfuscated_base64": obfuscated,
                    "owasp_llm": _OWASP_LLM01,
                },
            )

    matched = [pattern.pattern for pattern in _STRONG_SIGNALS if pattern.search(scan_text)]
    score = len(matched) * _STRONG_WEIGHT
    if not matched:
        score, matched = _score_weak_signals(scan_text)

    if score >= SCORE_BLOCK_THRESHOLD:
        return CheckResult(
            check_name="prompt_injection",
            passed=False,
            decision="block",
            reason="Prompt injection score met the threshold (heuristic)",
            severity=RiskLevel.HIGH,
            metadata={
                "pattern_type": "scored",
                "score": score,
                "threshold": SCORE_BLOCK_THRESHOLD,
                "matched_patterns": matched,
                "obfuscated_base64": obfuscated,
                "owasp_llm": _OWASP_LLM01,
            },
        )

    meta: dict[str, object] = {}
    if score:
        meta["injection_score"] = score
    return CheckResult(
        check_name="prompt_injection",
        passed=True,
        decision="allow",
        reason="No prompt injection detected",
        metadata=meta,
    )
