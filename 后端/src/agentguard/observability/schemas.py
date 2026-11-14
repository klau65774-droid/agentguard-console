"""Request/response schemas for observability and evaluation."""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field


class EvalCase(BaseModel):
    """A single evaluation test case."""

    id: str
    input_text: str
    expected_decision: str
    context: dict[str, Any] = Field(default_factory=dict)


class EvalRunRequest(BaseModel):
    """POST /v1/evals/run"""

    suite_name: str = Field(..., description="Name of the evaluation suite")
    cases: list[EvalCase] = Field(..., description="Test cases to evaluate")


class EvalCaseResult(BaseModel):
    case_id: str
    passed: bool
    expected: str
    actual: str
    details: dict[str, Any] = Field(default_factory=dict)


class EvalRunResponse(BaseModel):
    correlation_id: str
    suite_name: str
    total: int
    passed: int
    failed: int
    results: list[EvalCaseResult]


class BenchmarkResult(BaseModel):
    """Result of one fixed red-team or benign benchmark case."""

    model_config = ConfigDict(strict=True, extra="forbid")

    case_id: str
    category: str
    plane: Literal["input", "output", "action"]
    is_attack: bool
    expected: str
    actual: str
    passed: bool
    latency_ms: float = Field(ge=0)


class BenchmarkSummary(BaseModel):
    """Bilingual defense benchmark summary shared with the offline report."""

    model_config = ConfigDict(strict=True, extra="forbid")

    total_cases: int = Field(ge=0)
    attack_cases: int = Field(ge=0)
    attack_mitigated: int = Field(ge=0)
    attack_defense_rate_pct: float = Field(ge=0, le=100)
    benign_cases: int = Field(ge=0)
    benign_false_positives: int = Field(ge=0)
    false_positive_rate_pct: float = Field(ge=0, le=100)
    avg_latency_ms: float = Field(ge=0)
    p95_latency_ms: float = Field(ge=0)
    results: list[BenchmarkResult]
