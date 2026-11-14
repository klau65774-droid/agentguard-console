"""Bilingual hybrid BM25 + term-coverage retrieval grounding and citation packaging."""

from __future__ import annotations

import math
import re
from collections import Counter
from typing import Any

from agentguard.retrieval.schemas import Citation

_WORD_OR_CJK_RE = re.compile(r"[a-z0-9]+|[\u4e00-\u9fff]+")

# In-memory enterprise knowledge store (English + Chinese) for retrieval grounding.
_DEMO_DOCUMENTS: list[dict[str, Any]] = [
    {
        "source_id": "doc-001",
        "title": "Company Refund Policy",
        "content": "Refunds are available within 30 days of purchase with a valid receipt.",
        "url": "https://docs.example.com/refund-policy",
    },
    {
        "source_id": "doc-002",
        "title": "Data Retention Guidelines",
        "content": "Customer data is retained for 7 years per regulatory requirements.",
        "url": "https://docs.example.com/data-retention",
    },
    {
        "source_id": "doc-003",
        "title": "AI Usage Policy",
        "content": "AI-generated responses must be grounded in verified company data.",
        "url": "https://docs.example.com/ai-policy",
    },
    {
        "source_id": "doc-cn-001",
        "title": "企业算力网关与模型接入安全规范",
        "content": (
            "企业算力网关要求所有外部大模型API请求必须经过输入防注入校验、"
            "PII脱敏以及AK/SK密钥扫描，严禁在提示词中透传生产数据库凭证或明文私钥。"
        ),
        "url": "https://docs.example.com/cn/gateway-security",
    },
    {
        "source_id": "doc-cn-002",
        "title": "企业数据合规与留存管理制度",
        "content": (
            "涉及中国公民身份证号、手机号等个人敏感信息必须在网关侧完成掩码脱敏，"
            "核心业务审计日志需加密留存7年并支持合规追溯。"
        ),
        "url": "https://docs.example.com/cn/data-compliance",
    },
    {
        "source_id": "doc-cn-003",
        "title": "企业软件采购与售后服务退款政策",
        "content": (
            "标准企业版客户在采购开通后30天内，如因产品核心功能SLA未达标可凭有效合同"
            "与发票申请全额退款，处理周期为7个工作日。"
        ),
        "url": "https://docs.example.com/cn/refund-policy",
    },
]

_EXTRA_DOCUMENTS: list[dict[str, Any]] = []


def _tokenize_bilingual(text: str) -> list[str]:
    """Tokenize English/alphanumeric words plus CJK unigrams and character bigrams."""
    tokens: list[str] = []
    for segment in _WORD_OR_CJK_RE.findall(text.lower()):
        if segment[0].isascii():
            tokens.append(segment)
        else:
            chars = list(segment)
            tokens.extend(chars)
            if len(chars) >= 2:
                tokens.extend(chars[idx] + chars[idx + 1] for idx in range(len(chars) - 1))
    return tokens


def register_documents(docs: list[dict[str, Any]]) -> None:
    """Register or update custom documents for in-memory retrieval grounding."""
    existing = {doc["source_id"]: idx for idx, doc in enumerate(_EXTRA_DOCUMENTS)}
    for doc in docs:
        source_id = str(doc["source_id"])
        item = {
            "source_id": source_id,
            "title": str(doc.get("title", "")),
            "content": str(doc.get("content", "")),
            "url": doc.get("url"),
            "collection": doc.get("collection", "default"),
            "metadata": dict(doc.get("metadata", {})),
        }
        if source_id in existing:
            _EXTRA_DOCUMENTS[existing[source_id]] = item
        else:
            existing[source_id] = len(_EXTRA_DOCUMENTS)
            _EXTRA_DOCUMENTS.append(item)


def search_documents(
    query: str,
    collection: str = "default",
    top_k: int = 5,
    min_confidence: float = 0.3,
) -> list[Citation]:
    """Search relevant documents with bilingual hybrid BM25 + term-coverage scoring."""
    query_tokens = _tokenize_bilingual(query)
    if not query_tokens:
        return []

    corpus = [
        doc
        for doc in (_DEMO_DOCUMENTS + _EXTRA_DOCUMENTS)
        if doc.get("collection", "default") == collection
    ]
    if not corpus:
        return []

    doc_tokens_list = [
        _tokenize_bilingual(f"{doc.get('title', '')} {doc.get('content', '')}")
        for doc in corpus
    ]
    n_docs = len(corpus)
    avg_dl = sum(len(toks) for toks in doc_tokens_list) / max(n_docs, 1)

    unique_q = list(dict.fromkeys(query_tokens))
    doc_freq: dict[str, int] = {
        term: sum(1 for toks in doc_tokens_list if term in toks)
        for term in unique_q
    }
    idf: dict[str, float] = {
        term: math.log(1.0 + (n_docs - doc_freq[term] + 0.5) / (doc_freq[term] + 0.5))
        for term in unique_q
    }
    idf_norm_denom = max(sum(idf.values()) * 1.15, 1e-6)

    k1 = 1.5
    b = 0.75
    scored: list[tuple[float, dict[str, Any]]] = []

    for doc, d_tokens in zip(corpus, doc_tokens_list):
        if not d_tokens:
            continue
        tf_map = Counter(d_tokens)
        overlap = [term for term in unique_q if tf_map.get(term, 0) > 0]
        if not overlap:
            continue

        coverage = len(overlap) / len(unique_q)
        dl = len(d_tokens)
        bm25_raw = 0.0
        for term in overlap:
            tf = tf_map[term]
            denom = tf + k1 * (1.0 - b + b * (dl / max(avg_dl, 1.0)))
            bm25_raw += idf[term] * ((tf * (k1 + 1.0)) / max(denom, 1e-6))

        bm25_norm = min(bm25_raw / idf_norm_denom, 1.0)
        confidence = min(0.55 * coverage + 0.45 * bm25_norm, 1.0)
        if confidence >= min_confidence:
            scored.append((confidence, doc))

    scored.sort(key=lambda item: item[0], reverse=True)

    return [
        Citation(
            source_id=str(doc["source_id"]),
            title=str(doc["title"]),
            content=str(doc["content"]),
            confidence=round(conf, 3),
            url=doc.get("url"),
            metadata=dict(doc.get("metadata", {})),
        )
        for conf, doc in scored[:top_k]
    ]


def package_context(citations: list[Citation]) -> str:
    """Package citations into a context string for prompt injection."""
    if not citations:
        return ""
    parts = []
    for i, c in enumerate(citations, 1):
        parts.append(f"[{i}] {c.title} (confidence: {c.confidence})\n{c.content}")
    return "\n\n".join(parts)
