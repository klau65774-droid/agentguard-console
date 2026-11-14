/**
 * Tab 3 — 红队基准大盘与实时审计中心。
 *
 * 基准仅在用户点击后运行（runBenchmark），绝不挂载自动执行，也绝不使用
 * 本地伪造数据；审计与指标在挂载及筛选变化时加载，序号守卫防止竞态覆盖。
 */

import { useCallback, useEffect, useRef, useState } from "react";

import { getAudit, getMetrics, runBenchmark } from "../api/client";
import type {
  AuditEntry,
  BenchmarkResult,
  BenchmarkSummary,
  MetricsSnapshot,
  TenantId,
} from "../types/guardrails";

// ---------------------------------------------------------------------------
// Safe rendering helpers
// ---------------------------------------------------------------------------

type DecisionTone = "green" | "yellow" | "red" | "neutral";

function decisionTone(decision: string): DecisionTone {
  const value = decision.toLowerCase();
  if (value === "allow" || value === "pass") {
    return "green";
  }
  if (
    value === "redact" ||
    value === "repair" ||
    value === "require-approval" ||
    value === "dry-run"
  ) {
    return "yellow";
  }
  if (
    value === "block" ||
    value === "reject" ||
    value === "deny" ||
    value === "escalate"
  ) {
    return "red";
  }
  return "neutral";
}

function DecisionBadge({ decision }: { decision: string }) {
  return (
    <span className={`badge badge-decision badge-decision--${decisionTone(decision)}`}>
      {decision.toUpperCase()}
    </span>
  );
}

function formatPercent(value: number): string {
  if (!Number.isFinite(value)) {
    return "—";
  }
  return `${value.toFixed(1)}%`;
}

function formatMs(value: number): string {
  if (!Number.isFinite(value)) {
    return "—";
  }
  return `${value.toFixed(1)} ms`;
}

function formatTimestamp(iso: string): string {
  const date = new Date(iso);
  if (Number.isNaN(date.getTime())) {
    return iso;
  }
  return date.toLocaleString();
}

type AuditFilter = "all" | TenantId;

const AUDIT_FILTERS: readonly { value: AuditFilter; label: string }[] = [
  { value: "all", label: "全部租户" },
  { value: "default", label: "default" },
  { value: "finance-prod", label: "finance-prod" },
  { value: "gov-internal", label: "gov-internal" },
];

// ---------------------------------------------------------------------------
// Component
// ---------------------------------------------------------------------------

export function BenchmarkAndAudit() {
  // --- Benchmark state ------------------------------------------------------
  const [benchmarkRunning, setBenchmarkRunning] = useState(false);
  const [benchmarkSummary, setBenchmarkSummary] = useState<BenchmarkSummary | null>(null);
  const [benchmarkError, setBenchmarkError] = useState<string | null>(null);

  // --- Audit / metrics state ------------------------------------------------
  const [auditFilter, setAuditFilter] = useState<AuditFilter>("all");
  const [auditLoading, setAuditLoading] = useState(true);
  const [auditEntries, setAuditEntries] = useState<AuditEntry[]>([]);
  const [auditError, setAuditError] = useState<string | null>(null);
  const [metrics, setMetrics] = useState<MetricsSnapshot | null>(null);
  const [metricsError, setMetricsError] = useState<string | null>(null);

  // Guard against setState after unmount / stale async responses.
  const mountedRef = useRef(true);
  const benchmarkSeqRef = useRef(0);
  const auditSeqRef = useRef(0);
  useEffect(() => {
    mountedRef.current = true;
    return () => {
      mountedRef.current = false;
    };
  }, []);

  const loadAuditAndMetrics = useCallback(() => {
    const auditSeq = ++auditSeqRef.current;
    setAuditLoading(true);
    setAuditError(null);
    setMetricsError(null);
    const tenant: TenantId | undefined =
      auditFilter === "all" ? undefined : auditFilter;
    getAudit(50, tenant)
      .then((entries) => {
        if (mountedRef.current && auditSeq === auditSeqRef.current) {
          setAuditEntries(entries);
        }
      })
      .catch((error: unknown) => {
        if (mountedRef.current && auditSeq === auditSeqRef.current) {
          setAuditError(error instanceof Error ? error.message : String(error));
        }
      })
      .finally(() => {
        if (mountedRef.current && auditSeq === auditSeqRef.current) {
          setAuditLoading(false);
        }
      });
    getMetrics()
      .then((snapshot) => {
        if (mountedRef.current && auditSeq === auditSeqRef.current) {
          setMetrics(snapshot);
        }
      })
      .catch((error: unknown) => {
        if (mountedRef.current && auditSeq === auditSeqRef.current) {
          setMetricsError(error instanceof Error ? error.message : String(error));
        }
      });
  }, [auditFilter]);

  // Load on mount and whenever the tenant filter changes.
  useEffect(() => {
    loadAuditAndMetrics();
  }, [loadAuditAndMetrics]);

  const handleRunBenchmark = () => {
    if (benchmarkRunning) {
      return;
    }
    const seq = ++benchmarkSeqRef.current;
    setBenchmarkRunning(true);
    setBenchmarkError(null);
    runBenchmark()
      .then((summary) => {
        if (mountedRef.current && seq === benchmarkSeqRef.current) {
          setBenchmarkSummary(summary);
        }
      })
      .catch((error: unknown) => {
        if (mountedRef.current && seq === benchmarkSeqRef.current) {
          setBenchmarkError(error instanceof Error ? error.message : String(error));
        }
      })
      .finally(() => {
        if (mountedRef.current && seq === benchmarkSeqRef.current) {
          setBenchmarkRunning(false);
        }
      });
  };

  const metricEntries: [string, number][] =
    metrics !== null
      ? Object.entries(metrics).filter((entry): entry is [string, number] =>
          Number.isFinite(entry[1]),
        )
      : [];

  return (
    <div className="benchmark-audit">
      {/* ------------------------------------------------------ benchmark */}
      <section className="panel" aria-labelledby="benchmark-title">
        <h2 id="benchmark-title">红队基准大盘</h2>
        <p className="panel__hint">
          点击按钮对实时后端运行全量 21 条基准用例；不会在页面加载时自动执行。
        </p>
        <button
          type="button"
          className="button button--primary"
          onClick={handleRunBenchmark}
          disabled={benchmarkRunning}
        >
          {benchmarkRunning ? "基准运行中…" : "运行全量红队基准"}
        </button>

        {benchmarkError !== null && (
          <p className="status status--error" role="alert">
            基准请求失败：{benchmarkError}
            {benchmarkSummary !== null ? "（已保留上次成功结果）" : ""}
          </p>
        )}
        {benchmarkRunning && (
          <p className="status status--loading">正在对后端逐条执行基准用例，请稍候…</p>
        )}

        {benchmarkSummary !== null && (
          <div className="result-panel">
            <div className="metric-grid">
              <div className="metric-card">
                <span className="metric-card__label">攻击防御率</span>
                <strong className="metric-card__value">
                  {formatPercent(benchmarkSummary.attack_defense_rate_pct)}
                </strong>
              </div>
              <div className="metric-card">
                <span className="metric-card__label">正常样本误杀率</span>
                <strong className="metric-card__value">
                  {formatPercent(benchmarkSummary.false_positive_rate_pct)}
                </strong>
              </div>
              <div className="metric-card">
                <span className="metric-card__label">平均延迟</span>
                <strong className="metric-card__value">
                  {formatMs(benchmarkSummary.avg_latency_ms)}
                </strong>
              </div>
              <div className="metric-card">
                <span className="metric-card__label">P95 延迟</span>
                <strong className="metric-card__value">
                  {formatMs(benchmarkSummary.p95_latency_ms)}
                </strong>
              </div>
            </div>

            <p className="benchmark-summary">
              共 {benchmarkSummary.total_cases} 条用例：攻击 {benchmarkSummary.attack_cases} 条
              （成功防御 {benchmarkSummary.attack_mitigated} 条），正常样本{" "}
              {benchmarkSummary.benign_cases} 条（误杀 {benchmarkSummary.benign_false_positives}{" "}
              条）。
            </p>

            <h4 className="result-panel__subtitle">
              明细结果（{benchmarkSummary.results.length} 条）
            </h4>
            {benchmarkSummary.results.length === 0 ? (
              <p className="status status--empty">后端未返回任何基准明细</p>
            ) : (
              <div className="table-scroll">
                <table className="data-table">
                  <caption className="visually-hidden">红队基准全量明细</caption>
                  <thead>
                    <tr>
                      <th scope="col">case_id</th>
                      <th scope="col">category</th>
                      <th scope="col">plane</th>
                      <th scope="col">类型</th>
                      <th scope="col">expected</th>
                      <th scope="col">actual</th>
                      <th scope="col">passed</th>
                      <th scope="col">latency_ms</th>
                    </tr>
                  </thead>
                  <tbody>
                    {benchmarkSummary.results.map((result: BenchmarkResult) => (
                      <tr key={result.case_id}>
                        <td>
                          <code>{result.case_id}</code>
                        </td>
                        <td>{result.category}</td>
                        <td>{result.plane}</td>
                        <td>{result.is_attack ? "attack" : "benign"}</td>
                        <td>{result.expected}</td>
                        <td>{result.actual}</td>
                        <td>
                          <span
                            className={`badge badge-check badge-check--${result.passed ? "pass" : "fail"}`}
                          >
                            {result.passed ? "PASS" : "FAIL"}
                          </span>
                        </td>
                        <td>{formatMs(result.latency_ms)}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        )}
      </section>

      {/* ---------------------------------------------------------- audit */}
      <section className="panel" aria-labelledby="audit-title">
        <h2 id="audit-title">实时审计中心</h2>
        <div className="audit-toolbar">
          <label className="field field--inline">
            <span className="field__label">租户筛选</span>
            <select
              className="field__select"
              value={auditFilter}
              onChange={(event) => setAuditFilter(event.target.value as AuditFilter)}
            >
              {AUDIT_FILTERS.map((filter) => (
                <option key={filter.value} value={filter.value}>
                  {filter.label}
                </option>
              ))}
            </select>
          </label>
          <button
            type="button"
            className="button"
            onClick={loadAuditAndMetrics}
            disabled={auditLoading}
          >
            {auditLoading ? "刷新中…" : "一键刷新"}
          </button>
        </div>

        {auditError !== null && (
          <p className="status status--error" role="alert">
            审计请求失败：{auditError}
          </p>
        )}
        {metricsError !== null && (
          <p className="status status--error" role="alert">
            指标请求失败：{metricsError}
          </p>
        )}
        {auditLoading && <p className="status status--loading">正在加载审计流水与指标…</p>}

        {!auditLoading && auditError === null && auditEntries.length === 0 && (
          <p className="status status--empty">
            当前筛选条件下暂无审计流水（后端返回 0 条）
          </p>
        )}

        {auditEntries.length > 0 && (
          <div className="table-scroll">
            <table className="data-table">
              <caption className="visually-hidden">实时审计流水</caption>
              <thead>
                <tr>
                  <th scope="col">timestamp</th>
                  <th scope="col">tenant_id</th>
                  <th scope="col">module</th>
                  <th scope="col">decision</th>
                  <th scope="col">reason</th>
                  <th scope="col">correlation_id</th>
                </tr>
              </thead>
              <tbody>
                {auditEntries.map((entry) => (
                  <tr key={entry.id}>
                    <td>{formatTimestamp(entry.timestamp)}</td>
                    <td>
                      <code>{entry.tenant_id}</code>
                    </td>
                    <td>{entry.module}</td>
                    <td>
                      <DecisionBadge decision={entry.decision} />
                    </td>
                    <td>{entry.reason}</td>
                    <td>
                      <code>{entry.correlation_id}</code>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}

        {metrics !== null && metricEntries.length > 0 && (
          <div className="metrics-panel">
            <h4 className="result-panel__subtitle">实时指标快照</h4>
            <dl className="metrics-list">
              {metricEntries.map(([key, value]) => (
                <div key={key} className="metrics-list__item">
                  <dt>
                    <code>{key}</code>
                  </dt>
                  <dd>{Number.isInteger(value) ? value : value.toFixed(3)}</dd>
                </div>
              ))}
            </dl>
          </div>
        )}
        {metrics !== null && metricEntries.length === 0 && (
          <p className="status status--empty">后端返回的指标快照为空</p>
        )}
      </section>
    </div>
  );
}

export default BenchmarkAndAudit;
