/**
 * Tab 1 — 实时攻防演练沙盒：左栏输入护栏检测台，右栏输出校验与
 * <think> 修复台。全部状态经严格类型守卫渲染，不使用 any。
 */

import { useEffect, useRef, useState, type FormEvent } from "react";

import { evaluateInput, validateOutput } from "../api/client";
import { INPUT_PRESETS, OUTPUT_PRESETS } from "../presets/samples";
import type {
  CheckResult,
  InputEvaluationRequest,
  InputEvaluationResponse,
  OutputValidationRequest,
  OutputValidationResponse,
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

function formatMetadataValue(value: unknown): string {
  if (typeof value === "string") {
    return value;
  }
  return JSON.stringify(value);
}

/** Extract a string `repaired_text` from a repair check's metadata, if present. */
function extractRepairedText(checks: CheckResult[]): string | null {
  for (const check of checks) {
    const candidate: unknown = check.metadata["repaired_text"];
    if (typeof candidate === "string" && candidate.length > 0) {
      return candidate;
    }
  }
  return null;
}

function DecisionBadge({ decision }: { decision: string }) {
  return (
    <span className={`badge badge-decision badge-decision--${decisionTone(decision)}`}>
      {decision.toUpperCase()}
    </span>
  );
}

function CheckCard({ check, variant }: { check: CheckResult; variant: "input" | "output" }) {
  const owaspTag: unknown = check.metadata["owasp_llm"];
  const obfuscatedFlag: unknown = check.metadata["obfuscated_base64"];
  const remainingEntries = Object.entries(check.metadata).filter(
    ([key]) => key !== "owasp_llm" && key !== "obfuscated_base64" && key !== "repaired_text",
  );

  return (
    <article className={`check-card check-card--${variant}`}>
      <header className="check-card__header">
        <strong className="check-card__name">{check.check_name}</strong>
        <span
          className={`badge badge-check badge-check--${check.passed ? "pass" : "fail"}`}
        >
          {check.passed ? "PASSED" : "FAILED"}
        </span>
        <DecisionBadge decision={check.decision} />
        <span className={`badge badge-severity badge-severity--${check.severity}`}>
          {check.severity.toUpperCase()}
        </span>
      </header>
      <p className="check-card__reason">{check.reason}</p>
      <dl className="check-card__flags">
        {typeof owaspTag === "string" && owaspTag.length > 0 && (
          <div className="check-card__flag">
            <dt>OWASP LLM</dt>
            <dd>
              <span className="badge badge-tag">{owaspTag}</span>
            </dd>
          </div>
        )}
        {typeof obfuscatedFlag === "boolean" && (
          <div className="check-card__flag">
            <dt>Obfuscated Base64</dt>
            <dd>
              <span
                className={`badge badge-tag ${obfuscatedFlag ? "badge-tag--alert" : ""}`}
              >
                {obfuscatedFlag ? "检测到 Base64 混淆" : "未检测到"}
              </span>
            </dd>
          </div>
        )}
      </dl>
      {remainingEntries.length > 0 && (
        <details className="check-card__metadata">
          <summary>其他 metadata</summary>
          <ul className="metadata-list">
            {remainingEntries.map(([key, value]) => (
              <li key={key}>
                <code>{key}</code>: {formatMetadataValue(value)}
              </li>
            ))}
          </ul>
        </details>
      )}
    </article>
  );
}

// ---------------------------------------------------------------------------
// Component
// ---------------------------------------------------------------------------

const INPUT_CHANNELS = ["web", "api", "mobile", "wecom", "dingtalk"] as const;

interface OutputFormState {
  output_text: string;
  context_text: string;
  system_prompt: string;
  canary_tokens: string;
  require_citations: boolean;
}

const EMPTY_OUTPUT_FORM: OutputFormState = {
  output_text: "",
  context_text: "",
  system_prompt: "",
  canary_tokens: "",
  require_citations: false,
};

export function GuardrailPlayground() {
  // --- Input sandbox state -------------------------------------------------
  const [inputText, setInputText] = useState("");
  const [inputChannel, setInputChannel] = useState<string>(INPUT_CHANNELS[0]);
  const [inputSubmitting, setInputSubmitting] = useState(false);
  const [inputResult, setInputResult] = useState<InputEvaluationResponse | null>(null);
  const [inputError, setInputError] = useState<string | null>(null);

  // --- Output validation state ---------------------------------------------
  const [outputForm, setOutputForm] = useState<OutputFormState>(EMPTY_OUTPUT_FORM);
  const [outputSubmitting, setOutputSubmitting] = useState(false);
  const [outputResult, setOutputResult] = useState<OutputValidationResponse | null>(null);
  const [outputError, setOutputError] = useState<string | null>(null);

  // Guard against setState after unmount / stale async responses.
  const mountedRef = useRef(true);
  const inputSeqRef = useRef(0);
  const outputSeqRef = useRef(0);
  useEffect(() => {
    mountedRef.current = true;
    return () => {
      mountedRef.current = false;
    };
  }, []);

  // Fire an input evaluation as the latest request.
  const runInputEvaluation = (request: InputEvaluationRequest) => {
    const seq = ++inputSeqRef.current;
    setInputSubmitting(true);
    setInputResult(null);
    setInputError(null);
    evaluateInput(request)
      .then((response) => {
        if (mountedRef.current && seq === inputSeqRef.current) {
          setInputResult(response);
        }
      })
      .catch((error: unknown) => {
        if (mountedRef.current && seq === inputSeqRef.current) {
          setInputError(error instanceof Error ? error.message : String(error));
        }
      })
      .finally(() => {
        if (mountedRef.current && seq === inputSeqRef.current) {
          setInputSubmitting(false);
        }
      });
  };

  const handleInputSubmit = (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    const text = inputText.trim();
    if (text.length === 0) {
      return;
    }
    runInputEvaluation({
      text,
      channel: inputChannel,
      metadata: { api: "agentguard-playground", plane: "input" },
    });
  };

  // Fire an output validation as the latest request.
  const runOutputValidation = (request: OutputValidationRequest) => {
    const seq = ++outputSeqRef.current;
    setOutputSubmitting(true);
    setOutputResult(null);
    setOutputError(null);
    validateOutput(request)
      .then((response) => {
        if (mountedRef.current && seq === outputSeqRef.current) {
          setOutputResult(response);
        }
      })
      .catch((error: unknown) => {
        if (mountedRef.current && seq === outputSeqRef.current) {
          setOutputError(error instanceof Error ? error.message : String(error));
        }
      })
      .finally(() => {
        if (mountedRef.current && seq === outputSeqRef.current) {
          setOutputSubmitting(false);
        }
      });
  };

  const handleOutputSubmit = (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    const outputText = outputForm.output_text.trim();
    if (outputText.length === 0) {
      return;
    }
    const canaryTokens = outputForm.canary_tokens
      .split(/[，,]/)
      .map((token) => token.trim())
      .filter((token) => token.length > 0);
    runOutputValidation({
      output_text: outputText,
      context_text: outputForm.context_text.trim() || undefined,
      system_prompt: outputForm.system_prompt.trim() || undefined,
      canary_tokens: canaryTokens.length > 0 ? canaryTokens : null,
      require_citations: outputForm.require_citations,
      include_quality_risk_score: true,
    });
  };

  const repairedText = outputResult !== null ? extractRepairedText(outputResult.checks) : null;
  const qualityRiskScore =
    outputResult !== null && typeof outputResult.metadata.quality_risk_score === "number"
      ? clamp01(outputResult.metadata.quality_risk_score)
      : null;
  const qualityRiskDecision =
    outputResult !== null &&
    typeof outputResult.metadata.quality_risk_decision === "string"
      ? outputResult.metadata.quality_risk_decision
      : null;

  return (
    <div className="playground">
      {/* ------------------------------------------------ input column ----- */}
      <section className="panel playground__column" aria-labelledby="input-sandbox-title">
        <h2 id="input-sandbox-title">输入护栏检测台</h2>
        <form onSubmit={handleInputSubmit} className="playground__form">
          <div className="preset-row" role="group" aria-label="输入预设">
            {INPUT_PRESETS.map((preset) => (
              <button
                key={preset.id}
                type="button"
                className="preset-button"
                title={preset.description}
                onClick={() => {
                  setInputText(preset.request.text);
                  const channel = preset.request.channel ?? inputChannel;
                  setInputChannel(channel);
                  runInputEvaluation({
                    text: preset.request.text,
                    channel,
                    metadata: { api: "agentguard-playground", plane: "input" },
                  });
                }}
              >
                {preset.label}
              </button>
            ))}
          </div>
          <label className="field">
            <span className="field__label">待检测输入文本</span>
            <textarea
              className="field__textarea"
              rows={5}
              value={inputText}
              onChange={(event) => setInputText(event.target.value)}
              placeholder="输入用户请求，或使用上方预设一键填充…"
            />
          </label>
          <label className="field field--inline">
            <span className="field__label">Channel</span>
            <select
              className="field__select"
              value={inputChannel}
              onChange={(event) => setInputChannel(event.target.value)}
            >
              {INPUT_CHANNELS.map((channel) => (
                <option key={channel} value={channel}>
                  {channel}
                </option>
              ))}
            </select>
          </label>
          <button type="submit" className="button button--primary" disabled={inputSubmitting}>
            {inputSubmitting ? "检测中…" : "提交护栏检测"}
          </button>
        </form>

        {inputError !== null && (
          <p className="status status--error" role="alert">
            请求失败：{inputError}
          </p>
        )}
        {inputSubmitting && <p className="status status--loading">正在请求后端检测…</p>}

        {inputResult !== null && (
          <div className="result-panel">
            <header className="result-panel__header">
              <h3>检测结果</h3>
              <DecisionBadge decision={inputResult.decision} />
              <span className="result-panel__correlation">
                correlation_id：<code>{inputResult.correlation_id}</code>
              </span>
            </header>

            <div className="redact-compare">
              <div className="redact-compare__pane">
                <h4>原文</h4>
                <pre className="redact-compare__text">{inputText}</pre>
              </div>
              <div className="redact-compare__pane">
                <h4>脱敏后文本</h4>
                {inputResult.redacted_text !== null ? (
                  <pre className="redact-compare__text redact-compare__text--redacted">
                    {inputResult.redacted_text}
                  </pre>
                ) : (
                  <p className="status status--empty">后端未返回脱敏文本（未触发脱敏规则）</p>
                )}
              </div>
            </div>

            <h4 className="result-panel__subtitle">检查器明细（{inputResult.checks.length} 路）</h4>
            {inputResult.checks.length === 0 ? (
              <p className="status status--empty">后端未返回任何检查明细</p>
            ) : (
              <div className="check-list">
                {inputResult.checks.map((check, index) => (
                  <CheckCard key={`${check.check_name}-${index}`} check={check} variant="input" />
                ))}
              </div>
            )}
          </div>
        )}
      </section>

      {/* --------------------------------------------- output column ------- */}
      <section className="panel playground__column" aria-labelledby="output-sandbox-title">
        <h2 id="output-sandbox-title">输出校验与 &lt;think&gt; 修复台</h2>
        <form onSubmit={handleOutputSubmit} className="playground__form">
          <div className="preset-row" role="group" aria-label="输出预设">
            {OUTPUT_PRESETS.map((preset) => (
              <button
                key={preset.id}
                type="button"
                className="preset-button"
                title={preset.description}
                onClick={() => {
                  setOutputForm({
                    output_text: preset.request.output_text,
                    context_text: preset.request.context_text ?? "",
                    system_prompt: preset.request.system_prompt ?? "",
                    canary_tokens: preset.request.canary_tokens?.join(", ") ?? "",
                    require_citations: preset.request.require_citations ?? false,
                  });
                  runOutputValidation({ ...preset.request, include_quality_risk_score: true });
                }}
              >
                {preset.label}
              </button>
            ))}
          </div>
          <label className="field">
            <span className="field__label">output_text（模型输出）</span>
            <textarea
              className="field__textarea"
              rows={4}
              value={outputForm.output_text}
              onChange={(event) =>
                setOutputForm((prev) => ({ ...prev, output_text: event.target.value }))
              }
              placeholder="待校验的模型输出…"
            />
          </label>
          <label className="field">
            <span className="field__label">context_text（检索上下文，可选）</span>
            <textarea
              className="field__textarea"
              rows={3}
              value={outputForm.context_text}
              onChange={(event) =>
                setOutputForm((prev) => ({ ...prev, context_text: event.target.value }))
              }
              placeholder="用于 grounding / 引用校验的上下文…"
            />
          </label>
          <label className="field">
            <span className="field__label">system_prompt（系统提示词，可选）</span>
            <textarea
              className="field__textarea"
              rows={3}
              value={outputForm.system_prompt}
              onChange={(event) =>
                setOutputForm((prev) => ({ ...prev, system_prompt: event.target.value }))
              }
              placeholder="用于提示词泄露比对…"
            />
          </label>
          <label className="field">
            <span className="field__label">Canary Tokens（逗号分隔，可选）</span>
            <input
              className="field__input"
              type="text"
              value={outputForm.canary_tokens}
              onChange={(event) =>
                setOutputForm((prev) => ({ ...prev, canary_tokens: event.target.value }))
              }
              placeholder="CANARY-XXXX, …"
            />
          </label>
          <label className="field field--checkbox">
            <input
              type="checkbox"
              checked={outputForm.require_citations}
              onChange={(event) =>
                setOutputForm((prev) => ({
                  ...prev,
                  require_citations: event.target.checked,
                }))
              }
            />
            <span className="field__label">要求引用校验（require_citations）</span>
          </label>
          <button type="submit" className="button button--primary" disabled={outputSubmitting}>
            {outputSubmitting ? "校验中…" : "提交输出校验"}
          </button>
        </form>

        {outputError !== null && (
          <p className="status status--error" role="alert">
            请求失败：{outputError}
          </p>
        )}
        {outputSubmitting && <p className="status status--loading">正在校验输出…</p>}

        {outputResult !== null && (
          <div className="result-panel">
            <header className="result-panel__header">
              <h3>校验结果</h3>
              <DecisionBadge decision={outputResult.decision} />
              <span className="result-panel__correlation">
                correlation_id：<code>{outputResult.correlation_id}</code>
              </span>
            </header>

            {qualityRiskScore !== null && (
              <div className="risk-meter">
                <h4>
                  SlopScore 质量风险：
                  {qualityRiskDecision !== null && (
                    <DecisionBadge decision={qualityRiskDecision} />
                  )}
                </h4>
                <div
                  className="progress"
                  role="progressbar"
                  aria-valuemin={0}
                  aria-valuemax={1}
                  aria-valuenow={Number(qualityRiskScore.toFixed(3))}
                  aria-label="质量风险分数（SlopScore）"
                >
                  <div
                    className="progress__bar"
                    style={{ width: `${(qualityRiskScore * 100).toFixed(1)}%` }}
                  />
                </div>
                <p className="risk-meter__value">{qualityRiskScore.toFixed(3)} / 1.000</p>
              </div>
            )}

            <h4 className="result-panel__subtitle">输出检查明细（{outputResult.checks.length} 路）</h4>
            {outputResult.checks.length === 0 ? (
              <p className="status status--empty">后端未返回任何检查明细</p>
            ) : (
              <div className="check-list">
                {outputResult.checks.map((check, index) => (
                  <CheckCard key={`${check.check_name}-${index}`} check={check} variant="output" />
                ))}
              </div>
            )}

            <div className="repair-panel">
              <h4>自动剥离 &lt;think&gt; 后的安全交付文本</h4>
              {repairedText !== null ? (
                <pre className="repair-panel__text">{repairedText}</pre>
              ) : (
                <p className="status status--empty">
                  后端未返回修复文本：本次校验未在检查项 metadata 中提供
                  repaired_text（未触发 repair）
                </p>
              )}
            </div>
          </div>
        )}
      </section>
    </div>
  );
}

export default GuardrailPlayground;
