"""Run the bilingual guardrail benchmark and write its JSON report."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path

from agentguard.observability.benchmark import BenchmarkCase as BenchmarkCase
from agentguard.observability.benchmark import _build_cases as _build_cases
from agentguard.observability.benchmark import _percentile_95 as _percentile_95
from agentguard.observability.benchmark import _run_case as _run_case
from agentguard.observability.benchmark import run_benchmark as run_benchmark


def main() -> None:
    summary = asyncio.run(run_benchmark())
    root = Path(__file__).resolve().parent.parent
    report_path = root / "reports" / "benchmark_summary.json"
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")

    print("| Case ID | Plane | Attack? | Expected | Actual | Latency (ms) | Pass |")
    print("|---|---|---|---|---|---:|---|")
    for row in summary["results"]:
        mark = "PASS" if row["passed"] else "FAIL"
        print(
            f"| {row['case_id']} | {row['plane']} | {row['is_attack']} | "
            f"{row['expected']} | {row['actual']} | {row['latency_ms']:.3f} | {mark} |"
        )
    print()
    print(
        f"Attack Defense Rate: {summary['attack_defense_rate_pct']}% "
        f"({summary['attack_mitigated']}/{summary['attack_cases']})"
    )
    print(
        f"Benign False Positive Rate: {summary['false_positive_rate_pct']}% "
        f"({summary['benign_false_positives']}/{summary['benign_cases']})"
    )
    print(
        f"Latency: avg={summary['avg_latency_ms']} ms, "
        f"P95={summary['p95_latency_ms']} ms"
    )
    print(f"Saved report to: {report_path}")


if __name__ == "__main__":
    main()
