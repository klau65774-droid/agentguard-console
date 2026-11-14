/**
 * Strict TypeScript contracts mirroring the AgentGuard backend
 * (FastAPI pydantic schemas in `src/agentguard` + reports/benchmark_summary.json).
 *
 * Note: the backend does not return a top-level `repaired_text`; the repair
 * check stores it inside that check result's `metadata.repaired_text`.
 */

export type Severity = "low" | "medium" | "high" | "critical";

export interface CheckResult {
  check_name: string;
  passed: boolean;
  decision: string;
  reason: string;
  severity: Severity;
  metadata: Record<string, unknown>;
}

/** Metadata shape of the repair check result; `repaired_text` lives here. */
export interface RepairCheckMetadata extends Record<string, unknown> {
  repaired_text?: unknown;
}

// ---------------------------------------------------------------------------
// Input guardrails
// ---------------------------------------------------------------------------

export interface InputEvaluationRequest {
  text: string;
  use_case?: string | null;
  channel?: string | null;
  metadata?: Record<string, unknown>;
}

export interface InputEvaluationResponse {
  correlation_id: string;
  decision: string;
  checks: CheckResult[];
  redacted_text: string | null;
  metadata?: Record<string, unknown>;
}

// ---------------------------------------------------------------------------
// Output validation
// ---------------------------------------------------------------------------

export interface OutputValidationRequest {
  output_text: string;
  context_text?: string;
  expected_schema?: Record<string, unknown> | null;
  require_citations?: boolean;
  min_confidence?: number;
  include_quality_risk_score?: boolean;
  system_prompt?: string;
  canary_tokens?: string[] | null;
  metadata?: Record<string, unknown>;
}

export interface OutputValidationResponse {
  correlation_id: string;
  decision: string;
  checks: CheckResult[];
  metadata: {
    quality_risk_score?: number;
    quality_risk_decision?: string;
    [key: string]: unknown;
  };
}

// ---------------------------------------------------------------------------
// Retrieval grounding
// ---------------------------------------------------------------------------

export interface RetrievalSearchRequest {
  query: string;
  collection?: string;
  top_k?: number;
  min_confidence?: number;
  require_grounding?: boolean;
  metadata?: Record<string, unknown>;
}

export interface Citation {
  source_id: string;
  title: string;
  content: string;
  confidence: number;
  url?: string | null;
  metadata?: Record<string, unknown>;
}

export interface RetrievalSearchResponse {
  correlation_id: string;
  grounded: boolean;
  context_text: string;
  citations: Citation[];
  metadata?: Record<string, unknown>;
}

// ---------------------------------------------------------------------------
// Action governance
// ---------------------------------------------------------------------------

export interface ToolSpec {
  tool: string;
  description: string;
  risk_base: number;
  required_params: string[];
  max_risk: string;
}

export interface ActionAuthorizeRequest {
  action: string;
  tool: string;
  parameters: Record<string, unknown>;
  dry_run?: boolean;
  idempotency_key?: string | null;
  metadata?: Record<string, unknown>;
}

export interface ActionAuthorizeResponse {
  correlation_id: string;
  decision: string;
  risk_level: string;
  risk_score: number;
  reason: string;
  requires_approval: boolean;
  dry_run?: boolean;
  metadata?: Record<string, unknown>;
}

// ---------------------------------------------------------------------------
// Benchmarks (aligned with reports/benchmark_summary.json)
// ---------------------------------------------------------------------------

export type BenchmarkPlane = "input" | "output" | "action";

export interface BenchmarkResult {
  case_id: string;
  category: string;
  plane: BenchmarkPlane;
  is_attack: boolean;
  expected: string;
  actual: string;
  passed: boolean;
  latency_ms: number;
}

export interface BenchmarkSummary {
  total_cases: number;
  attack_cases: number;
  attack_mitigated: number;
  attack_defense_rate_pct: number;
  benign_cases: number;
  benign_false_positives: number;
  false_positive_rate_pct: number;
  avg_latency_ms: number;
  p95_latency_ms: number;
  results: BenchmarkResult[];
}

// ---------------------------------------------------------------------------
// Observability
// ---------------------------------------------------------------------------

export interface AuditEntry {
  id: string;
  timestamp: string;
  tenant_id: string;
  correlation_id: string;
  module: string;
  decision: string;
  reason: string;
  metadata: Record<string, unknown>;
}

export type MetricsSnapshot = Record<string, number>;

// ---------------------------------------------------------------------------
// Tenancy
// ---------------------------------------------------------------------------

export type TenantId = "default" | "finance-prod" | "gov-internal";

export const TENANT_IDS: readonly TenantId[] = [
  "default",
  "finance-prod",
  "gov-internal",
];

export const DEFAULT_TENANT_ID: TenantId = "default";
