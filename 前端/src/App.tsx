/**
 * AgentGuard Security Console — 全局总装。
 *
 * 单一安全控制台：顶部品牌栏 + 租户切换 + 实时请求追踪
 * （X-Correlation-ID / X-AgentGuard-Latency-Ms），下方三 Tab 分别承载
 * 输入/输出沙盒、RAG/工具风控台、红队基准与审计中心。仅渲染当前 Tab。
 */

import { useEffect, useRef, useState, type ChangeEvent } from "react";

import {
  getLatestTrace,
  getTenant,
  setTenant,
  subscribeTrace,
  type RequestTrace,
} from "./api/client";
import { BenchmarkAndAudit } from "./components/BenchmarkAndAudit";
import { GuardrailPlayground } from "./components/GuardrailPlayground";
import { RagAndActionConsole } from "./components/RagAndActionConsole";
import { TENANT_IDS, type TenantId } from "./types/guardrails";

// ---------------------------------------------------------------------------
// Tabs
// ---------------------------------------------------------------------------

type TabId = "playground" | "rag-actions" | "benchmark-audit";

const TABS: readonly { id: TabId; label: string; description: string }[] = [
  { id: "playground", label: "护栏攻防沙盒", description: "输入护栏检测与输出校验/修复" },
  { id: "rag-actions", label: "RAG 与工具风控", description: "双语检索溯源与 Agent 动作授权" },
  { id: "benchmark-audit", label: "基准与审计", description: "红队基准大盘与实时审计流水" },
];

// ---------------------------------------------------------------------------
// Formatting helpers
// ---------------------------------------------------------------------------

/** Sub-millisecond latencies render as µs; ms values keep sensible precision. */
function formatLatency(latencyMs: number): string {
  if (latencyMs < 1) {
    return `${Math.round(latencyMs * 1000)} µs`;
  }
  if (latencyMs < 10) {
    return `${latencyMs.toFixed(2)} ms`;
  }
  if (latencyMs < 100) {
    return `${latencyMs.toFixed(1)} ms`;
  }
  return `${Math.round(latencyMs)} ms`;
}

// ---------------------------------------------------------------------------
// Component
// ---------------------------------------------------------------------------

export default function App() {
  const [activeTab, setActiveTab] = useState<TabId>("playground");
  const [tenant, setTenantState] = useState<TenantId>(() => getTenant());
  const [trace, setTrace] = useState<RequestTrace>(() => getLatestTrace());

  const mountedRef = useRef(true);
  useEffect(() => {
    mountedRef.current = true;
    const unsubscribe = subscribeTrace((next) => {
      if (mountedRef.current) {
        setTrace(next);
      }
    });
    return () => {
      mountedRef.current = false;
      unsubscribe();
    };
  }, []);

  const handleTenantChange = (event: ChangeEvent<HTMLSelectElement>) => {
    const nextTenant = event.target.value as TenantId;
    setTenant(nextTenant);
    setTenantState(nextTenant);
  };

  return (
    <div className="app-shell">
      <header className="topbar">
        <div className="topbar__brand">
          <h1 className="topbar__title">AgentGuard Security Console</h1>
          <p className="topbar__subtitle">
            实时对接 AgentGuard 网关（/v1 代理 → 127.0.0.1:8000）：每次请求由后端
            注入租户头并返回追踪信息，此处原样呈现。
          </p>
        </div>

        <div className="topbar__controls">
          <label className="field field--inline topbar__tenant">
            <span className="field__label">租户（X-Tenant-ID）</span>
            <select
              className="field__select"
              value={tenant}
              onChange={handleTenantChange}
            >
              {TENANT_IDS.map((id) => (
                <option key={id} value={id}>
                  {id}
                </option>
              ))}
            </select>
          </label>

          <dl className="trace-bar" aria-label="实时请求追踪">
            <div className="trace-bar__item">
              <dt>Correlation ID</dt>
              <dd>
                <code>{trace.correlationId ?? "—"}</code>
              </dd>
            </div>
            <div className="trace-bar__item">
              <dt>Latency</dt>
              <dd>
                <code>{trace.latencyMs !== null ? formatLatency(trace.latencyMs) : "—"}</code>
              </dd>
            </div>
          </dl>
        </div>
      </header>

      <nav className="tabs" role="tablist" aria-label="AgentGuard 控制台功能区">
        {TABS.map((tab) => (
          <button
            key={tab.id}
            type="button"
            role="tab"
            id={`tab-${tab.id}`}
            aria-selected={activeTab === tab.id}
            aria-controls={`panel-${tab.id}`}
            tabIndex={activeTab === tab.id ? 0 : -1}
            className={`tabs__tab${activeTab === tab.id ? " tabs__tab--active" : ""}`}
            onClick={() => setActiveTab(tab.id)}
          >
            <span className="tabs__tab-label">{tab.label}</span>
            <span className="tabs__tab-description">{tab.description}</span>
          </button>
        ))}
      </nav>

      <main>
        {activeTab === "playground" && (
          <div
            role="tabpanel"
            id="panel-playground"
            aria-labelledby="tab-playground"
            className="tabpanel"
          >
            <GuardrailPlayground />
          </div>
        )}
        {activeTab === "rag-actions" && (
          <div
            role="tabpanel"
            id="panel-rag-actions"
            aria-labelledby="tab-rag-actions"
            className="tabpanel"
          >
            <RagAndActionConsole />
          </div>
        )}
        {activeTab === "benchmark-audit" && (
          <div
            role="tabpanel"
            id="panel-benchmark-audit"
            aria-labelledby="tab-benchmark-audit"
            className="tabpanel"
          >
            <BenchmarkAndAudit />
          </div>
        )}
      </main>
    </div>
  );
}
