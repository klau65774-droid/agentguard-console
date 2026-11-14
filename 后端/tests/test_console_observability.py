"""Regression tests for the console APIs and decision instrumentation."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient

from agentguard.action_governance import allowlist, approval
from agentguard.config import Settings, settings
from agentguard.observability import benchmark


@pytest.fixture
def tenant_id() -> str:
    return f"console-test-{uuid4().hex}"


def _metric_snapshot(client: TestClient) -> dict[str, int]:
    response = client.get("/v1/evals/metrics")
    assert response.status_code == 200
    return response.json()


def _audit_entries(client: TestClient, tenant_id: str) -> list[dict[str, Any]]:
    response = client.get("/v1/evals/audit", params={"tenant_id": tenant_id})
    assert response.status_code == 200
    return response.json()


def _post_decision(
    client: TestClient,
    tenant_id: str,
    path: str,
    body: dict[str, Any],
    *,
    module: str,
    decision: str,
) -> tuple[dict[str, Any], dict[str, Any]]:
    before = _metric_snapshot(client)
    trace_id = uuid4().hex
    response = client.post(
        path,
        json=body,
        headers={settings.tenant_header: tenant_id, "X-Correlation-ID": trace_id},
    )
    assert response.status_code == 200
    assert response.headers["X-Correlation-ID"] == trace_id
    data = response.json()
    assert data["correlation_id"] == trace_id
    assert data["decision"] == decision

    entries = [
        entry for entry in _audit_entries(client, tenant_id) if entry["correlation_id"] == trace_id
    ]
    assert len(entries) == 1
    entry = entries[0]
    assert entry["tenant_id"] == tenant_id
    assert entry["module"] == module
    assert entry["decision"] == decision

    counter = f"{module}.requests{{decision={decision}}}"
    assert _metric_snapshot(client) == before | {counter: before.get(counter, 0) + 1}
    return data, entry


def test_gateway_settings_defaults_are_anchored_to_the_repository() -> None:
    root = Path(__file__).resolve().parents[1]
    assert Settings.model_config["env_file"] == str(root / ".env")
    assert Settings.model_fields["policy_dir"].default == str(root / "policies")
    assert Settings.model_fields["prompt_packages_dir"].default == str(root / "prompt_packages")
    assert Settings.model_fields["expose_guardrail_latency_header"].default is True
    assert Settings.model_fields["cors_origins"].default == [
        "http://localhost:3000",
        "http://localhost:5173",
        "http://127.0.0.1:5173",
    ]


@pytest.mark.parametrize("origin", ["http://localhost:5173", "http://127.0.0.1:5173"])
def test_cors_preflight_allows_vite_origin_and_exposes_headers(
    client: TestClient, origin: str
) -> None:
    path = "/v1/guardrails/evaluate-input"
    preflight = client.options(
        path,
        headers={
            "Origin": origin,
            "Access-Control-Request-Method": "POST",
            "Access-Control-Request-Headers": "content-type, x-correlation-id",
        },
    )
    assert preflight.status_code == 200
    assert preflight.headers["Access-Control-Allow-Origin"] == origin
    assert preflight.headers["X-AgentGuard-Latency-Ms"].startswith("gateway=")

    response = client.post(
        path,
        json={"text": "What is the refund policy?"},
        headers={"Origin": origin, "X-Correlation-ID": "cors-trace"},
    )
    assert response.status_code == 200
    assert response.headers["Access-Control-Allow-Origin"] == origin
    exposed = response.headers["Access-Control-Expose-Headers"].lower().split(",")
    assert {name.strip() for name in exposed} >= {"x-correlation-id", "x-agentguard-latency-ms"}
    assert response.headers["X-Correlation-ID"] == "cors-trace"
    name, value = response.headers["X-AgentGuard-Latency-Ms"].split("=")
    assert name == "input_guardrails"
    assert float(value) >= 0


@pytest.mark.parametrize(
    ("path", "body", "module", "decision", "reason", "failed_checks"),
    [
        pytest.param(
            "/v1/guardrails/evaluate-input",
            {"text": "What is the refund policy?"},
            "input_guardrails",
            "allow",
            "Input evaluated",
            [],
            id="input-allow",
        ),
        pytest.param(
            "/v1/guardrails/evaluate-input",
            {"text": "Reply to fixture@example.com"},
            "input_guardrails",
            "redact",
            "Input evaluated",
            ["pii_detection"],
            id="input-redact",
        ),
        pytest.param(
            "/v1/outputs/validate",
            {"output_text": "Returns are accepted within 30 days."},
            "output_validation",
            "pass",
            "Output validated",
            [],
            id="output-pass",
        ),
        pytest.param(
            "/v1/outputs/validate",
            {"output_text": "Returns are accepted within 30 days.", "require_citations": True},
            "output_validation",
            "repair",
            "Output validated",
            ["citation_check"],
            id="output-repair",
        ),
    ],
)
def test_guardrail_decisions_record_audit_and_metrics(
    client: TestClient,
    tenant_id: str,
    path: str,
    body: dict[str, Any],
    module: str,
    decision: str,
    reason: str,
    failed_checks: list[str],
) -> None:
    data, entry = _post_decision(client, tenant_id, path, body, module=module, decision=decision)
    assert [check["check_name"] for check in data["checks"] if not check["passed"]] == failed_checks
    assert entry["reason"] == reason
    assert set(entry["metadata"]) == {"elapsed_ms", "failed_checks"}
    assert entry["metadata"]["failed_checks"] == failed_checks
    elapsed = entry["metadata"]["elapsed_ms"]
    assert isinstance(elapsed, float)
    assert elapsed >= 0
    assert elapsed == round(elapsed, 3)


def test_policy_decision_records_audit_and_metrics(client: TestClient, tenant_id: str) -> None:
    _, entry = _post_decision(
        client,
        tenant_id,
        "/v1/policies/evaluate",
        {"policy_name": "default", "context": {"requires_grounding": True, "grounded": False}},
        module="policy_engine",
        decision="deny",
    )
    assert entry["metadata"] == {"policy_name": "default"}
    assert entry["reason"] == "Policy 'default' evaluated"


@pytest.mark.parametrize(
    ("patch", "decision", "risk"),
    [
        pytest.param({}, "allow", "low", id="allow"),
        pytest.param({"dry_run": True}, "dry-run", "low", id="dry-run"),
        pytest.param(
            {
                "action": "bulk_update",
                "tool": "bulk_update",
                "parameters": {"record_ids": ["1"], "fields": {"status": "open"}},
            },
            "require-approval",
            "critical",
            id="approval",
        ),
        pytest.param({"tool": "unknown_tool"}, "deny", "critical", id="unknown-tool"),
        pytest.param({"parameters": {}}, "deny", "medium", id="missing-parameter"),
    ],
)
def test_action_decisions_record_audit_and_metrics(
    client: TestClient, tenant_id: str, patch: dict[str, Any], decision: str, risk: str
) -> None:
    body: dict[str, Any] = {
        "action": "search",
        "tool": "search_documents",
        "parameters": {"query": "refund"},
    }
    body |= patch
    data, entry = _post_decision(
        client,
        tenant_id,
        "/v1/actions/authorize",
        body,
        module="action_governance",
        decision=decision,
    )
    assert data["risk_level"] == risk
    assert data["requires_approval"] is (decision == "require-approval")
    assert entry["reason"] == data["reason"]
    assert entry["metadata"] == {"tool": body["tool"], "action": body["action"]}


@pytest.mark.parametrize(
    ("dry_run", "decision"), [(False, "deny"), (True, "dry-run")], ids=["live", "dry-run"]
)
def test_detected_sql_injection_denies_live_action(
    client: TestClient, tenant_id: str, dry_run: bool, decision: str
) -> None:
    body = {
        "action": "search",
        "tool": "search_documents",
        "parameters": {"query": "refund", "filters": {"label": "union select"}},
        "dry_run": dry_run,
    }
    data, entry = _post_decision(
        client,
        tenant_id,
        "/v1/actions/authorize",
        body,
        module="action_governance",
        decision=decision,
    )
    assert data["risk_level"] == "critical"
    assert data["requires_approval"] is False
    assert data["dry_run"] is dry_run
    assert entry["reason"] == data["reason"]


def test_action_replay_has_its_own_audit_and_metric(
    client: TestClient, tenant_id: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(approval, "_seen_idempotency_keys", set())
    body = {
        "action": "search",
        "tool": "search_documents",
        "parameters": {"query": "refund"},
        "idempotency_key": uuid4().hex,
    }
    path = "/v1/actions/authorize"
    _post_decision(client, tenant_id, path, body, module="action_governance", decision="allow")
    data, entry = _post_decision(
        client, tenant_id, path, body, module="action_governance", decision="deny"
    )
    assert data["reason"].startswith("Duplicate request")
    assert entry["reason"] == data["reason"]
    assert entry["metadata"] == {"tool": body["tool"], "action": body["action"]}


def test_metrics_continue_when_audit_logging_is_disabled(
    client: TestClient, tenant_id: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(settings, "enable_audit_log", False)
    before = _metric_snapshot(client)
    response = client.post(
        "/v1/guardrails/evaluate-input",
        json={"text": "What is the refund policy?"},
        headers={settings.tenant_header: tenant_id},
    )
    assert response.status_code == 200
    assert response.json()["decision"] == "allow"
    assert _audit_entries(client, tenant_id) == []
    counter = "input_guardrails.requests{decision=allow}"
    assert _metric_snapshot(client) == before | {counter: before.get(counter, 0) + 1}


def test_tool_list_projects_the_current_allowlist(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setitem(
        allowlist._TOOL_ALLOWLIST,
        "temporary_test_tool",
        {
            "description": "Temporary test tool",
            "risk_base": 0.4,
            "required_params": ["message"],
            "max_risk": "medium",
            "internal_note": "private field",
        },
    )
    response = client.get("/v1/actions/tools")
    assert response.status_code == 200
    public_fields = ("description", "risk_base", "required_params", "max_risk")
    assert response.json() == [
        {"tool": tool, **{field: config[field] for field in public_fields}}
        for tool, config in allowlist._TOOL_ALLOWLIST.items()
    ]


@pytest.mark.parametrize("body", [None, {}], ids=["no-body", "empty-json"])
def test_evals_benchmark_endpoint_matches_report_schema_without_writing_files(
    client: TestClient, monkeypatch: pytest.MonkeyPatch, body: dict[str, Any] | None
) -> None:
    report = Path(__file__).resolve().parents[1] / "reports" / "benchmark_summary.json"
    original_mtime = report.stat().st_mtime_ns
    original = report.read_bytes()
    expected = json.loads(original)
    evaluate_input = AsyncMock(wraps=benchmark.evaluate_input)
    monkeypatch.setattr(benchmark, "evaluate_input", evaluate_input)

    response = client.post("/v1/evals/benchmark", json=body)
    assert response.status_code == 200
    actual = response.json()
    assert len(actual["results"]) == actual["total_cases"] == 21
    assert {row["plane"] for row in actual["results"]} == {"input", "output", "action"}
    assert evaluate_input.await_count == sum(row["plane"] == "input" for row in expected["results"])
    assert actual.keys() == expected.keys()
    for key in ("avg_latency_ms", "p95_latency_ms"):
        assert actual.pop(key) >= 0
        del expected[key]
    for row, expected_row in zip(actual["results"], expected["results"], strict=True):
        assert row.keys() == expected_row.keys()
        assert row.pop("latency_ms") >= 0
        del expected_row["latency_ms"]
    assert actual == expected
    assert report.read_bytes() == original
    assert report.stat().st_mtime_ns == original_mtime
