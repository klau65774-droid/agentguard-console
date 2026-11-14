/**
 * Typed API client for the AgentGuard backend.
 *
 * - Injects the current `X-Tenant-ID` header on every request (default `default`).
 * - Extracts `X-Correlation-ID` and `X-AgentGuard-Latency-Ms` from every
 *   response (including error responses) and publishes them to subscribers so
 *   the top bar can render live trace info.
 */

import {
  DEFAULT_TENANT_ID,
  type ActionAuthorizeRequest,
  type ActionAuthorizeResponse,
  type AuditEntry,
  type BenchmarkSummary,
  type InputEvaluationRequest,
  type InputEvaluationResponse,
  type MetricsSnapshot,
  type OutputValidationRequest,
  type OutputValidationResponse,
  type RetrievalSearchRequest,
  type RetrievalSearchResponse,
  type TenantId,
  type ToolSpec,
} from "../types/guardrails";

export interface RequestTrace {
  correlationId: string | null;
  latencyMs: number | null;
}

type TraceListener = (trace: RequestTrace) => void;

const CORRELATION_HEADER = "X-Correlation-ID";
const LATENCY_HEADER = "X-AgentGuard-Latency-Ms";
const TENANT_HEADER = "X-Tenant-ID";

let currentTenant: TenantId = DEFAULT_TENANT_ID;
let latestTrace: RequestTrace = { correlationId: null, latencyMs: null };
const traceListeners = new Set<TraceListener>();

export function setTenant(tenant: TenantId): void {
  currentTenant = tenant;
}

export function getTenant(): TenantId {
  return currentTenant;
}

export function getLatestTrace(): RequestTrace {
  return latestTrace;
}

/** Subscribe to trace updates; returns an unsubscribe function. */
export function subscribeTrace(listener: TraceListener): () => void {
  traceListeners.add(listener);
  return () => {
    traceListeners.delete(listener);
  };
}

function publishTrace(trace: RequestTrace): void {
  latestTrace = trace;
  for (const listener of traceListeners) {
    listener(trace);
  }
}

/**
 * The latency header carries millisecond values, either as a plain number or
 * as `;`-separated `stage=value` pairs where the value may carry an `ms`
 * suffix (e.g. `input_guardrails=3.200;gateway=0.123ms`). We surface the
 * summed wall-clock latency, or null when nothing parseable is present.
 */
function parseLatencyHeader(raw: string | null): number | null {
  if (raw === null) {
    return null;
  }
  let total = 0;
  let found = false;
  const pattern = /([a-zA-Z_]+)=([0-9.]+)/g;
  let match: RegExpExecArray | null;
  while ((match = pattern.exec(raw)) !== null) {
    const value = Number(match[2]);
    if (Number.isFinite(value)) {
      total += value;
      found = true;
    }
  }
  if (!found) {
    const plain = Number(raw.trim());
    if (Number.isFinite(plain)) {
      total = plain;
      found = true;
    }
  }
  return found ? total : null;
}

function extractTrace(headers: Headers): RequestTrace {
  const parsedLatency = parseLatencyHeader(headers.get(LATENCY_HEADER));
  const trace: RequestTrace = {
    correlationId: headers.get(CORRELATION_HEADER),
    latencyMs: parsedLatency !== null ? parsedLatency : latestTrace.latencyMs,
  };
  publishTrace(trace);
  return trace;
}

/** Best-effort body summary for error messages, never throws. */
async function summarizeBody(response: Response): Promise<string> {
  try {
    const text = await response.text();
    const trimmed = text.trim();
    return trimmed.length > 300 ? `${trimmed.slice(0, 300)}…` : trimmed;
  } catch {
    return "<unreadable body>";
  }
}

export class ApiRequestError extends Error {
  readonly status: number;
  readonly correlationId: string | null;

  constructor(status: number, message: string, correlationId: string | null) {
    super(message);
    this.name = "ApiRequestError";
    this.status = status;
    this.correlationId = correlationId;
  }
}

async function request<T>(path: string, init: RequestInit = {}): Promise<T> {
  const headers = new Headers(init.headers);
  headers.set(TENANT_HEADER, currentTenant);
  if (init.body !== undefined && !headers.has("Content-Type")) {
    headers.set("Content-Type", "application/json");
  }

  let response: Response;
  try {
    response = await fetch(path, { ...init, headers });
  } catch (error) {
    const detail = error instanceof Error ? error.message : String(error);
    throw new Error(`Network error while calling ${path}: ${detail}`);
  }

  const trace = extractTrace(response.headers);

  if (!response.ok) {
    const summary = await summarizeBody(response);
    throw new ApiRequestError(
      response.status,
      `Request to ${path} failed with status ${response.status}` +
        (trace.correlationId !== null ? ` (correlation ${trace.correlationId})` : "") +
        (summary.length > 0 ? `: ${summary}` : ""),
      trace.correlationId,
    );
  }

  try {
    return (await response.json()) as T;
  } catch (error) {
    const detail = error instanceof Error ? error.message : String(error);
    throw new Error(`Failed to parse JSON response from ${path}: ${detail}`);
  }
}

function post<T>(path: string, body: unknown): Promise<T> {
  return request<T>(path, { method: "POST", body: JSON.stringify(body) });
}

function get<T>(path: string): Promise<T> {
  return request<T>(path, { method: "GET" });
}

// ---------------------------------------------------------------------------
// Endpoints
// ---------------------------------------------------------------------------

export function evaluateInput(
  body: InputEvaluationRequest,
): Promise<InputEvaluationResponse> {
  return post<InputEvaluationResponse>("/v1/guardrails/evaluate-input", body);
}

export function validateOutput(
  body: OutputValidationRequest,
): Promise<OutputValidationResponse> {
  return post<OutputValidationResponse>("/v1/outputs/validate", body);
}

export function searchRetrieval(
  body: RetrievalSearchRequest,
): Promise<RetrievalSearchResponse> {
  return post<RetrievalSearchResponse>("/v1/retrieval/search", body);
}

export function listTools(): Promise<ToolSpec[]> {
  return get<ToolSpec[]>("/v1/actions/tools");
}

export function authorizeAction(
  body: ActionAuthorizeRequest,
): Promise<ActionAuthorizeResponse> {
  return post<ActionAuthorizeResponse>("/v1/actions/authorize", body);
}

export function runBenchmark(): Promise<BenchmarkSummary> {
  return post<BenchmarkSummary>("/v1/evals/benchmark", {});
}

export function getAudit(limit = 50, tenantId?: TenantId): Promise<AuditEntry[]> {
  const params = new URLSearchParams();
  params.set("limit", String(limit));
  if (tenantId !== undefined) {
    params.set("tenant_id", tenantId);
  }
  return get<AuditEntry[]>(`/v1/evals/audit?${params.toString()}`);
}

export function getMetrics(): Promise<MetricsSnapshot> {
  return get<MetricsSnapshot>("/v1/evals/metrics");
}
