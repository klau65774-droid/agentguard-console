"""Detect threats and requests to generate or encourage abusive behavior."""

from __future__ import annotations

import re

from agentguard.common.models import CheckResult, RiskLevel

# A period, sentence terminator or line break ends the request window.
_CLAUSE_BREAK = re.compile(r"[.!?;。！？；\r\n]+")
_REQUEST_START = r"^\s*(?:(?:please|kindly|(?:can|could|would)\s+you|help\s+me)\s+){0,3}"
_CREATE = r"(?:write|draft|compose|create|generate|publish|produce|design|make)"
_OUTPUT = (
    r"(?:article|blog(?:\s+(?:post|entry))?|post|piece|story|statement|speech|e-?mail|"
    r"message|script|scene|"
    r"poem|song|list|guide|tutorial|video|essay|jokes?|thread|letter|narrative|campaign)"
)
# Bind the action to its first artifact, even when later nouns include harmful content.
_REQUEST_CONTENT = rf"{_REQUEST_START}{_CREATE}\s+(?>[^.!?;。！？；\r\n]{{0,40}}?\b{_OUTPUT}\b)"
_HARMFUL_CONTENT = (
    r"(?:(?:promot(?:es?|ing)|encourag(?:es?|ing)|celebrat(?:es?|ing))\s+"
    r"(?:body\s+shaming|anorexia|bulimia|self[- ]?harm|suicide)\b|ridicule\s+or\s+demean|"
    r"(?:glorif(?:y|ies|ying)|prais(?:es?|ing))\s+(?:the\s+Holocaust|the\s+Nazi\s+party)\b|"
    r"(?:advocat(?:es?|ing)|endors(?:es?|ing)|promot(?:es?|ing))\s+"
    r"(?:(?:a|the)\s+)?(?:dominant\s+)?(?:racial\s+supremacy|"
    r"racist\s+and\s+colonialist\s+(?:ideology|regime|system))\b|"
    r"(?:celebrat(?:es?|ing)|justif(?:y|ies|ying))\s+(?:that\s+)?people\s+older\s+than\s+\w+"
    r"[^.!?;。！？；\r\n]{0,40}\bwere\s+killed\b|"
    r"(?:portrays?|depicts?|describes?|casts?|claims?|states?)\s+(?:that\s+)?"
    r"(?:(?:a|an|the|this|that)\s+)?(?:particular\s+|specific\s+)?ethnic\s+group\s+"
    r"(?:as|is|are)\s+(?:(?:inherently|genetically|naturally)\s+)?(?:inferior|dangerous)\b|"
    r"discourages?\s+the\s+hiring\s+of\s+individuals\s+with\s+disabilities|"
    r"(?:claims?\s+(?:that\s+)?)?biracial\s+marriage\s+is\s+disgusting|"
    r"(?:describes?|depicts?)\s+(?:a\s+)?(?:graphic\s+torture|severe\s+violence)|"
    r"(?:uses?|advocates?)\s+violence\s+and\s+warfare\s+to\s+enslave|"
    r"harass(?:es|ing)?\s+(?:an?\s+)?LGBTQ\+|"
    r"(?:encourages?|incites?)\s+[^.!?;。！？；\r\n]{0,40}\bto\s+harass\s+(?:an?\s+)?LGBTQ\+|"
    r"convinc(?:e|es|ing)\s+children\s+to\s+eat\s+laundry\s+detergent)"
)

_TOXIC_PATTERNS = {
    "direct_threat": re.compile(
        rf"{_REQUEST_START}(?:(?:i|we)\s+(?:will|want\s+to|intend\s+to)\s+)?"
        r"(?:kill|murder|attack|bomb|shoot)\s+(?:people|someone|them)\b",
        re.IGNORECASE,
    ),
    "direct_hostility": re.compile(
        rf"{_REQUEST_START}(?:i\s+|we\s+)?"
        r"(?:hate|despise)\s+(?:all\s+)?(?:\w+\s+)?people\b",
        re.IGNORECASE,
    ),
    "violent_how_to": re.compile(
        r"\b(?:how\s+to|steps\s+(?:necessary\s+)?to|instructions\s+to)\s+"
        r"(?:(?:make|build|construct)\s+(?:(?:a|an)\s+)?(?:bombs?|weapons?|explosives?)\b"
        r"(?!\s+(?:shelters?|disposal|detection|detectors?|safety)\b)|"
        r"shoot\s+up\s+a\s+(?:high\s+)?school|"
        r"(?:kill|murder|attack|bomb|shoot)\s+(?:people|someone|them)|"
        r"find,\s+kill,\s+and\s+prepare\s+a\s+human\s+body\s+for\s+consumption)\b",
        re.IGNORECASE,
    ),
    "explicit_abusive_output": re.compile(
        rf"{_REQUEST_START}{_CREATE}\s+(?:(?:a|an|some|the)\s+)?"
        r"(?:(?:short|long|detailed|graphic|openly|highly)\s+){0,2}"
        rf"(?:defamatory|sexist|xenophobic|racist|discriminatory|harassing)\s+{_OUTPUT}\b",
        re.IGNORECASE,
    ),
    "requested_abusive_persuasion": re.compile(
        rf"{_REQUEST_CONTENT}\s+(?:(?:that|(?:in\s+)?which|(?:aiming\s+)?to)\s+)?"
        rf"(?:(?:openly|explicitly|actively)\s+)?{_HARMFUL_CONTENT}",
        re.IGNORECASE,
    ),
    "requested_graphic_torture": re.compile(
        rf"{_REQUEST_START}(?:(?:describe|{_CREATE})\s+|"
        rf"{_CREATE}\s+(?:(?:a|an|the)\s+)?(?:story|script)\s+about\s+)"
        r"(?:(?:a|an|the)\s+)?"
        r"(?:medieval\s+)?torture\s+scene\s+in\s+graphic\s+detail\b",
        re.IGNORECASE,
    ),
    "direct_harmful_encouragement": re.compile(
        rf"{_REQUEST_START}(?:(?:promote|encourage)\s+"
        r"(?:anorexia|bulimia|self[- ]?harm|suicide|body\s+shaming)\b|"
        r"(?:praise|glorify)\s+(?:the\s+Holocaust|the\s+Nazi\s+party)\b|"
        r"use\s+violence\s+and\s+warfare\s+to\s+enslave\b|"
        r"convince\s+children\s+to\s+eat\s+laundry\s+detergent\b)",
        re.IGNORECASE,
    ),
}


async def check(text: str) -> CheckResult:
    for clause in _CLAUSE_BREAK.split(text):
        for evidence, pattern in _TOXIC_PATTERNS.items():
            if pattern.search(clause):
                return CheckResult(
                    check_name="toxicity",
                    passed=False,
                    decision="block",
                    reason="Toxic or abusive content detected",
                    severity=RiskLevel.CRITICAL,
                    metadata={"evidence": evidence},
                )
    return CheckResult(
        check_name="toxicity",
        passed=True,
        decision="allow",
        reason="No toxic content detected",
    )
