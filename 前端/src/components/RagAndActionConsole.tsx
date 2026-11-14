/**
 * Tab 2 — 双语 RAG 溯源与 Agent 工具风控台。
 *
 * 上半区：检索溯源（searchRetrieval）；下半区：工具列表（listTools，
 * 失败时按契约回落到 DEFAULT_TOOLS 并明确提示）与动作授权（authorizeAction）。
 */

import { useEffect, useRef, useState, type FormEvent } from "react";

import { authorizeAction, listTools, searchRetrieval } from "../api/client";
import {
  ACTION_PRESETS,
  DEFAULT_TOOLS,
  RETRIEVAL_PRESETS,
} from "../presets/samples";
import type {
  ActionAuthorizeRequest,
  ActionAuthorizeResponse,
  Citation,
  RetrievalSearchRequest,
  RetrievalSearchResponse,
  ToolSpec,
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

function clamp01(value: number): number {
  if (!Number.isFinite(value)) {
    return 0;
  }
  return Math.min(1, Math.max(0, value));
}

function DecisionBadge({ decision }: { decision: string }) {
  return (
    <span className={`badge badge-decision badge-decision--${decisionTone(decision)}`}>
      {decision.toUpperCase()}
    </span>
  );
}

function ConfidenceBar({ value, label }: { value: number; label: string }) {
  const clamped = clamp01(value);
  return (
    <div className="confidence">
      <div
        className="progress"
        role="progressbar"
        aria-valuemin={0}
        aria-valuemax={1}
        aria-valuenow={Number(clamped.toFixed(3))}
        aria-label={label}
      >
        <div className="progress__bar" style={{ width: `${(clamped * 100).toFixed(1)}%` }} />
      </div>
      <span className="confidence__value">{clamped.toFixed(3)}</span>
    </div>
  );
}

function CitationCard({ citation, index }: { citation: Citation; index: number }) {
  return (
    <article className="citation-card">
      <header className="citation-card__header">
        <strong className="citation-card__title">
          #{index + 1} {citation.title}
        </strong>
        <code className="citation-card__source">{citation.source_id}</code>
      </header>
      <p className="citation-card__content">{citation.content}</p>
      <footer className="citation-card__footer">
        {citation.url !== null && citation.url !== undefined && citation.url.length > 0 && (
          <a className="citation-card__url" href={citation.url} target="_blank" rel="noreferrer">
            {citation.url}
          </a>
        )}
        <ConfidenceBar value={citation.confidence} label={`${citation.title} 置信度`} />
      </footer>
    </article>
  );
}

// ---------------------------------------------------------------------------
// Component
// ---------------------------------------------------------------------------

export function RagAndActionConsole() {
  // --- Retrieval state ------------------------------------------------------
  const [query, setQuery] = useState("");
  const [topK, setTopK] = useState(5);
  const [minConfidence, setMinConfidence] = useState(0.3);
  const [requireGrounding, setRequireGrounding] = useState(true);
  const [retrievalSubmitting, setRetrievalSubmitting] = useState(false);
  const [retrievalResult, setRetrievalResult] = useState<RetrievalSearchResponse | null>(null);
  const [retrievalError, setRetrievalError] = useState<string | null>(null);

  // --- Tools / action state -------------------------------------------------
  const [tools, setTools] = useState<readonly ToolSpec[] | null>(null);
  const [toolsLoading, setToolsLoading] = useState(true);
  const [toolsFallback, setToolsFallback] = useState(false);
  const [selectedTool, setSelectedTool] = useState("");
  const [actionName, setActionName] = useState("");
  const [parametersText, setParametersText] = useState("{}");
  const [parametersError, setParametersError] = useState<string | null>(null);
  const [dryRun, setDryRun] = useState(false);
  const [authorizeSubmitting, setAuthorizeSubmitting] = useState(false);
  const [authorizeResult, setAuthorizeResult] = useState<ActionAuthorizeResponse | null>(null);
  const [authorizeError, setAuthorizeError] = useState<string | null>(null);

  // Guard against setState after unmount / stale async responses.
  const mountedRef = useRef(true);
  const retrievalSeqRef = useRef(0);
  const toolsSeqRef = useRef(0);
  const authorizeSeqRef = useRef(0);
  useEffect(() => {
    mountedRef.current = true;
    return () => {
      mountedRef.current = false;
    };
  }, []);

  // Load tool list once on mount; fall back to DEFAULT_TOOLS only on failure.
  useEffect(() => {
    const seq = ++toolsSeqRef.current;
    setToolsLoading(true);
    listTools()
      .then((specs) => {
        if (!mountedRef.current || seq !== toolsSeqRef.current) {
          return;
        }
        setTools(specs);
        setToolsFallback(false);
        setSelectedTool((prev) => (prev.length > 0 ? prev : (specs[0]?.tool ?? "")));
      })
      .catch(() => {
        if (!mountedRef.current || seq !== toolsSeqRef.current) {
          return;
        }
        setTools(DEFAULT_TOOLS);
        setToolsFallback(true);
        setSelectedTool((prev) => (prev.length > 0 ? prev : DEFAULT_TOOLS[0].tool));
      })
      .finally(() => {
        if (mountedRef.current && seq === toolsSeqRef.current) {
          setToolsLoading(false);
        }
      });
  }, []);

  // Fire a retrieval search as the latest request: clears stale results,
  // bumps the seq so an in-flight older response can no longer overwrite us.
  const runRetrievalSearch = (request: RetrievalSearchRequest) => {
    const seq = ++retrievalSeqRef.current;
    setRetrievalSubmitting(true);
    setRetrievalResult(null);
    setRetrievalError(null);
    searchRetrieval(request)
      .then((response) => {
        if (mountedRef.current && seq === retrievalSeqRef.current) {
          setRetrievalResult(response);
        }
      })
      .catch((error: unknown) => {
        if (mountedRef.current && seq === retrievalSeqRef.current) {
          setRetrievalError(error instanceof Error ? error.message : String(error));
        }
      })
      .finally(() => {
        if (mountedRef.current && seq === retrievalSeqRef.current) {
          setRetrievalSubmitting(false);
        }
      });
  };

  const handleRetrievalSubmit = (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    const trimmedQuery = query.trim();
    if (trimmedQuery.length === 0) {
      return;
    }
    runRetrievalSearch({
      query: trimmedQuery,
      top_k: topK,
      min_confidence: clamp01(minConfidence),
      require_grounding: requireGrounding,
    });
  };

  const parseParameters = (raw: string): { ok: true; value: Record<string, unknown> } | { ok: false; message: string } => {
    let parsed: unknown;
    try {
      parsed = JSON.parse(raw);
    } catch (error) {
      const detail = error instanceof Error ? error.message : String(error);
      return { ok: false, message: `JSON 解析失败：${detail}` };
    }
    if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) {
      return { ok: false, message: "参数必须是 JSON 对象（非 null、非数组）" };
    }
    return { ok: true, value: parsed as Record<string, unknown> };
  };

  // Fire an action authorization as the latest request.
  const runActionAuthorization = (request: ActionAuthorizeRequest) => {
    const seq = ++authorizeSeqRef.current;
    setAuthorizeSubmitting(true);
    setAuthorizeResult(null);
    setAuthorizeError(null);
    authorizeAction(request)
      .then((response) => {
        if (mountedRef.current && seq === authorizeSeqRef.current) {
          setAuthorizeResult(response);
        }
      })
      .catch((error: unknown) => {
        if (mountedRef.current && seq === authorizeSeqRef.current) {
          setAuthorizeError(error instanceof Error ? error.message : String(error));
        }
      })
      .finally(() => {
        if (mountedRef.current && seq === authorizeSeqRef.current) {
          setAuthorizeSubmitting(false);
        }
      });
  };

  const handleAuthorizeSubmit = (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    const tool = selectedTool.trim();
    const action = actionName.trim();
    if (tool.length === 0 || action.length === 0) {
      setParametersError("请先选择工具并填写 action");
      return;
    }
    const parsed = parseParameters(parametersText);
    if (!parsed.ok) {
      setParametersError(parsed.message);
      return;
    }
    setParametersError(null);
    runActionAuthorization({
      action,
      tool,
      parameters: parsed.value,
      dry_run: dryRun,
      idempotency_key: null,
    });
  };

  const applyActionPreset = (presetIndex: number) => {
    const preset = ACTION_PRESETS[presetIndex];
    if (preset === undefined) {
      return;
    }
    setSelectedTool(preset.request.tool);
    setActionName(preset.request.action);
    setParametersText(JSON.stringify(preset.request.parameters, null, 2));
    setDryRun(false);
    setParametersError(null);
    runActionAuthorization(preset.request);
  };

  const toolSpec = tools?.find((spec) => spec.tool === selectedTool) ?? null;
  const riskScore = authorizeResult !== null ? clamp01(authorizeResult.risk_score) : null;

  return (
    <div className="rag-console">
      {/* -------------------------------------------------- retrieval ---- */}
      <section className="panel" aria-labelledby="retrieval-title">
        <h2 id="retrieval-title">双语 RAG 溯源台</h2>
        <form onSubmit={handleRetrievalSubmit} className="playground__form">
          <div className="preset-row" role="group" aria-label="检索预设">
            {RETRIEVAL_PRESETS.map((preset) => (
              <button
                key={preset.id}
                type="button"
                className="preset-button"
                title={preset.description}
                onClick={() => {
                  setQuery(preset.request.query);
                  setTopK(preset.request.top_k ?? 5);
                  setMinConfidence(preset.request.min_confidence ?? 0.3);
                  setRequireGrounding(preset.request.require_grounding ?? true);
                  runRetrievalSearch({
                    query: preset.request.query,
                    top_k: preset.request.top_k ?? 5,
                    min_confidence: preset.request.min_confidence ?? 0.3,
                    require_grounding: preset.request.require_grounding ?? true,
                  });
                }}
              >
                {preset.label}
              </button>
            ))}
          </div>
          <label className="field">
            <span className="field__label">检索 Query</span>
            <textarea
              className="field__textarea"
              rows={2}
              value={query}
              onChange={(event) => setQuery(event.target.value)}
              placeholder="输入中文、英文或中英混合查询…"
            />
          </label>
          <div className="field-row">
            <label className="field field--inline">
              <span className="field__label">top_k</span>
              <input
                className="field__input"
                type="number"
                min={1}
                max={20}
                value={topK}
                onChange={(event) => setTopK(Number(event.target.value))}
              />
            </label>
            <label className="field field--inline">
              <span className="field__label">min_confidence</span>
              <input
                className="field__input"
                type="number"
                min={0}
                max={1}
                step={0.05}
                value={minConfidence}
                onChange={(event) => setMinConfidence(Number(event.target.value))}
              />
            </label>
            <label className="field field--checkbox">
              <input
                type="checkbox"
                checked={requireGrounding}
                onChange={(event) => setRequireGrounding(event.target.checked)}
              />
              <span className="field__label">require_grounding</span>
            </label>
          </div>
          <button type="submit" className="button button--primary" disabled={retrievalSubmitting}>
            {retrievalSubmitting ? "检索中…" : "发起 Hybrid BM25 检索"}
          </button>
        </form>

        {retrievalError !== null && (
          <p className="status status--error" role="alert">
            请求失败：{retrievalError}
          </p>
        )}
        {retrievalSubmitting && <p className="status status--loading">正在检索…</p>}

        {retrievalResult !== null && (
          <div className="result-panel">
            <header className="result-panel__header">
              <h3>检索结果</h3>
              <span
                className={`badge badge-grounded badge-grounded--${retrievalResult.grounded ? "yes" : "no"}`}
              >
                {retrievalResult.grounded ? "GROUNDED" : "UNGROUNDED"}
              </span>
              <span className="result-panel__correlation">
                correlation_id：<code>{retrievalResult.correlation_id}</code>
              </span>
            </header>

            <h4 className="result-panel__subtitle">
              Hybrid BM25 命中（{retrievalResult.citations.length} 条引文）
            </h4>
            {retrievalResult.citations.length === 0 ? (
              <p className="status status--empty">未检索到任何引文，请调整查询或阈值后重试</p>
            ) : (
              <div className="citation-list">
                {retrievalResult.citations.map((citation, index) => (
                  <CitationCard key={citation.source_id} citation={citation} index={index} />
                ))}
              </div>
            )}

            <h4 className="result-panel__subtitle">打包后的 context_text</h4>
            {retrievalResult.context_text.trim().length > 0 ? (
              <pre className="context-text">{retrievalResult.context_text}</pre>
            ) : (
              <p className="status status--empty">后端未返回可用上下文文本</p>
            )}
          </div>
        )}
      </section>

      {/* ------------------------------------------------------ actions -- */}
      <section className="panel" aria-labelledby="action-title">
        <h2 id="action-title">Agent 工具风控台</h2>

        {toolsLoading && <p className="status status--loading">正在加载工具列表…</p>}
        {toolsFallback && (
          <p className="status status--warning" role="status">
            工具列表接口不可达，当前展示「本地默认工具列表」（工作包 1 预设回退）
          </p>
        )}

        {!toolsLoading && tools !== null && (
          <div className="tool-layout">
            <div className="tool-layout__selector">
              <label className="field">
                <span className="field__label">选择工具</span>
                <select
                  className="field__select"
                  value={selectedTool}
                  onChange={(event) => setSelectedTool(event.target.value)}
                >
                  {tools.map((spec) => (
                    <option key={spec.tool} value={spec.tool}>
                      {spec.tool}
                    </option>
                  ))}
                </select>
              </label>
              {toolSpec !== null && (
                <dl className="tool-spec">
                  <div>
                    <dt>描述</dt>
                    <dd>{toolSpec.description}</dd>
                  </div>
                  <div>
                    <dt>risk_base</dt>
                    <dd>{toolSpec.risk_base.toFixed(2)}</dd>
                  </div>
                  <div>
                    <dt>required_params</dt>
                    <dd>
                      {toolSpec.required_params.length > 0
                        ? toolSpec.required_params.join(", ")
                        : "无"}
                    </dd>
                  </div>
                  <div>
                    <dt>max_risk</dt>
                    <dd>
                      <span className={`badge badge-severity badge-severity--${toolSpec.max_risk}`}>
                        {toolSpec.max_risk.toUpperCase()}
                      </span>
                    </dd>
                  </div>
                </dl>
              )}
            </div>

            <form onSubmit={handleAuthorizeSubmit} className="playground__form tool-layout__form">
              <div className="preset-row" role="group" aria-label="动作预设">
                {ACTION_PRESETS.map((preset, index) => (
                  <button
                    key={preset.id}
                    type="button"
                    className="preset-button"
                    title={preset.description}
                    onClick={() => applyActionPreset(index)}
                  >
                    {preset.label}
                  </button>
                ))}
              </div>
              <div className="field-row">
                <label className="field field--inline">
                  <span className="field__label">action</span>
                  <input
                    className="field__input"
                    type="text"
                    value={actionName}
                    onChange={(event) => setActionName(event.target.value)}
                    placeholder="动作名称"
                  />
                </label>
                <label className="field field--inline">
                  <span className="field__label">tool</span>
                  <input
                    className="field__input"
                    type="text"
                    value={selectedTool}
                    onChange={(event) => setSelectedTool(event.target.value)}
                    placeholder="工具名称"
                  />
                </label>
                <label className="field field--checkbox">
                  <input
                    type="checkbox"
                    checked={dryRun}
                    onChange={(event) => setDryRun(event.target.checked)}
                  />
                  <span className="field__label">dry_run</span>
                </label>
              </div>
              <label className="field">
                <span className="field__label">parameters（严格 JSON 对象）</span>
                <textarea
                  className="field__textarea"
                  rows={6}
                  value={parametersText}
                  onChange={(event) => setParametersText(event.target.value)}
                  spellCheck={false}
                  placeholder='{"key": "value"}'
                />
              </label>
              {parametersError !== null && (
                <p className="status status--error" role="alert">
                  {parametersError}
                </p>
              )}
              <button
                type="submit"
                className="button button--primary"
                disabled={authorizeSubmitting}
              >
                {authorizeSubmitting ? "授权评估中…" : "提交授权评估"}
              </button>
            </form>
          </div>
        )}

        {authorizeError !== null && (
          <p className="status status--error" role="alert">
            请求失败：{authorizeError}
          </p>
        )}

        {authorizeResult !== null && (
          <div className="result-panel">
            <header className="result-panel__header">
              <h3>授权结论</h3>
              <DecisionBadge decision={authorizeResult.decision} />
              <span className={`badge badge-risk badge-risk--${authorizeResult.risk_level}`}>
                RiskLevel：{authorizeResult.risk_level.toUpperCase()}
              </span>
              <span className="result-panel__correlation">
                correlation_id：<code>{authorizeResult.correlation_id}</code>
              </span>
            </header>

            {riskScore !== null && (
              <div className="risk-meter">
                <h4>风险分数</h4>
                <div
                  className="progress"
                  role="progressbar"
                  aria-valuemin={0}
                  aria-valuemax={1}
                  aria-valuenow={Number(riskScore.toFixed(3))}
                  aria-label="动作授权风险分数"
                >
                  <div
                    className="progress__bar"
                    style={{ width: `${(riskScore * 100).toFixed(1)}%` }}
                  />
                </div>
                <p className="risk-meter__value">{riskScore.toFixed(3)} / 1.000</p>
              </div>
            )}

            <dl className="authorize-summary">
              <div>
                <dt>requires_approval</dt>
                <dd>{authorizeResult.requires_approval ? "是（需人工审批）" : "否"}</dd>
              </div>
              <div>
                <dt>reason</dt>
                <dd>{authorizeResult.reason}</dd>
              </div>
              {authorizeResult.dry_run !== undefined && (
                <div>
                  <dt>dry_run</dt>
                  <dd>{authorizeResult.dry_run ? "是" : "否"}</dd>
                </div>
              )}
            </dl>
          </div>
        )}
      </section>
    </div>
  );
}

export default RagAndActionConsole;
