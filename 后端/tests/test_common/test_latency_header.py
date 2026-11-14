"""Route-specific and fallback X-AgentGuard-Latency-Ms values."""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import Mock

import pytest
from fastapi.testclient import TestClient

from agentguard.common import latency
from agentguard.config import settings


@pytest.mark.parametrize(
    ("path", "body", "tag"),
    [
        ("/v1/guardrails/evaluate-input", {"text": "hello"}, "input_guardrails"),
        ("/v1/outputs/validate", {"output_text": "Support is open today."}, "output_validation"),
    ],
)
def test_latency_header_prefers_the_guardrail_timing(
    client: TestClient, path: str, body: dict[str, str], tag: str
) -> None:
    response = client.post(path, json=body)
    assert response.status_code == 200
    name, value = response.headers["X-AgentGuard-Latency-Ms"].split("=")
    assert name == tag
    assert float(value) >= 0


@pytest.mark.parametrize(
    ("method", "path", "body", "status"),
    [
        pytest.param("POST", "/v1/retrieval/search", {"query": "refund"}, 200, id="retrieval"),
        pytest.param(
            "POST",
            "/v1/actions/authorize",
            {"action": "search", "tool": "search_documents", "parameters": {"query": "refund"}},
            200,
            id="authorize",
        ),
        pytest.param("GET", "/v1/evals/metrics", None, 200, id="eval-metrics"),
        pytest.param("POST", "/v1/evals/benchmark", None, 200, id="eval-benchmark"),
        pytest.param("POST", "/v1/guardrails/evaluate-input", {}, 422, id="validation-error"),
    ],
)
def test_latency_header_uses_gateway_timing_when_guardrails_do_not_record_a_timing(
    client: TestClient, method: str, path: str, body: object, status: int
) -> None:
    response = client.request(method, path, json=body)
    assert response.status_code == status
    name, value = response.headers["X-AgentGuard-Latency-Ms"].split("=")
    assert name == "gateway"
    assert float(value) >= 0


def test_gateway_timing_formats_elapsed_milliseconds(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    clock = SimpleNamespace(perf_counter=Mock(side_effect=[10.0, 10.0125]))
    monkeypatch.setattr(latency, "time", clock)

    response = client.get("/health")

    assert response.status_code == 200
    assert response.headers["X-AgentGuard-Latency-Ms"] == "gateway=12.500"


def test_latency_header_absent_when_disabled(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(settings, "expose_guardrail_latency_header", False)
    guardrail_response = client.post("/v1/guardrails/evaluate-input", json={"text": "hello"})
    gateway_response = client.get("/v1/evals/metrics")
    for response in (guardrail_response, gateway_response):
        assert response.status_code == 200
        assert "X-AgentGuard-Latency-Ms" not in response.headers
