import { createHash } from "node:crypto";

export const VERSION = "0.2.0";
export const DEFAULT_LIMITS = Object.freeze({ modelCalls: 8, toolCalls: 24, wallMs: 30_000, toolMs: 5_000 });
export const REAL_LIMITS = Object.freeze({ modelCalls: 16, toolCalls: 64, wallMs: 600_000, toolMs: 5_000 });
export const MAX_LIMITS = Object.freeze({ modelCalls: 64, toolCalls: 256, wallMs: 600_000, toolMs: 30_000 });
export function limitsFor(mode: "offline" | "real", overrides: Partial<Limits> = {}): Limits {
  requireThat(Object.keys(overrides).every(key => Object.hasOwn(MAX_LIMITS, key)), "INVALID_ARGUMENT", "Unknown budget field");
  const limits = { ...(mode === "offline" ? DEFAULT_LIMITS : REAL_LIMITS), ...overrides };
  for (const [key, value] of Object.entries(limits)) integer(value, 1, MAX_LIMITS[key as keyof Limits]);
  return limits;
}
export const MAX_FILE = 5 * 1024 * 1024;
export const MAX_TOTAL = 20 * 1024 * 1024;
export const MAX_REPORTED_TOKENS = 8_000_000;
export const TOOL_NAMES = ["target_describe", "artifact_inspect", "ledger_query", "hypothesis_query", "decision_submit"] as const;
export type ToolName = typeof TOOL_NAMES[number];
export interface Limits { modelCalls: number; toolCalls: number; wallMs: number; toolMs: number }
export type Judgment = "suspected" | "not_supported" | "inconclusive";
export type Phase = "preliminary" | "review" | "final";
export type Reason = "EVIDENCE_MISSING" | "CONSTRAINT_CONFLICT" | "BUDGET_EXHAUSTED" | "ORACLE_UNRESOLVED" | "POLICY_DENIED" | "TOOL_DAMAGED";
export type Association = "synthetic_explicit" | "causal_id" | "heuristic" | "unknown";
export interface Target { id: string; kind: "synthetic" | "recorded"; architecture?: string; binary_sha256?: string; firmware_sha256?: string }
export interface Artifact {
  id: string; sha256: string; size_bytes: number; media_type: string; kind: string;
  origin: string; instruction_authority: "none"; content: string;
}
export interface Candidate {
  id: string; source_addrs: string[]; sink_addrs: string[];
  call_chains: string[][]; call_points: string[][][];
  artifact_ids: string[]; association: Association; missing_evidence: string[];
}
export interface AnalysisBundle {
  schema_version: 2; target: Target; artifacts: Artifact[]; candidates: Candidate[];
  input_files: { name: string; sha256: string; size_bytes: number }[];
}
export interface Citation { artifact_id: string; offset: number; length: number }
export interface Decision {
  static_flow: "supported" | "not_supported" | "unknown";
  candidate_id: string; phase: Phase; judgment: Judgment;
  decision: "inspect" | "finish" | "abstain"; reason_code: Reason | null;
  evidence: Citation[]; counterevidence: Citation[]; missing_evidence: string[]; rationale: string;
  validation_status: "not_run"; level: "inferred";
}
export interface LedgerEvent {
  event_id: string; session_id: string; timestamp: string; kind: string;
  level: "raw" | "derived" | "inferred";
  producer: { type: "tool" | "agent"; name: string; version: string };
  claim: unknown; evidence_refs: string[];
  provenance: { target_hash: string; target_hash_kind: "target_descriptor"; binary_sha256: string | null; tool_call_id?: string };
}
export interface CandidateResult {
  static_flow: Decision["static_flow"];
  candidate_id: string; source_addrs: string[]; sink_addrs: string[];
  association: Association; completed: boolean; judgment: Judgment;
  missing_evidence: string[]; validation_status: "not_run"; level: "inferred";
  decisions: Decision[];
}
export interface AnalysisRun {
  schema_version: 2; run_id: string; status: "completed" | "partial" | "failed" | "aborted" | "no_candidates";
  mode: "offline" | "real";
  model: { provider: string; id: string; api: string };
  limits: Limits;
  usage: { input: number; output: number; cacheRead: number; cacheWrite: number; totalTokens: number; reported_messages: number };
  scenario: string; target: Target; candidates: CandidateResult[];
  errors: { code: string; message: string }[];
  metrics: { model_calls: number; tool_calls: number; wall_ms: number; telemetry_dropped: number; settled_events: number };
  ledger: LedgerEvent[]; telemetry: { type: string }[];
}
export class DomainError extends Error {
  constructor(public code: string, message: string) { super(message); this.name = "DomainError"; }
}
export function requireThat(condition: unknown, code: string, message: string): asserts condition {
  if (!condition) throw new DomainError(code, message);
}
export function object(value: unknown, keys: readonly string[], required: readonly string[] = keys): Record<string, unknown> {
  requireThat(value !== null && typeof value === "object" && !Array.isArray(value), "INVALID_ARGUMENT", "Expected an object");
  const obj = value as Record<string, unknown>;
  requireThat(Object.keys(obj).every(k => keys.includes(k)) && required.every(k => Object.hasOwn(obj, k)), "INVALID_ARGUMENT", "Missing or unexpected object fields");
  return obj;
}
export function text(value: unknown, max = 4096, allowEmpty = false): string {
  requireThat(typeof value === "string" && (allowEmpty || value.length > 0) && [...value].length <= max, "INVALID_ARGUMENT", "Invalid or oversized text");
  return value;
}
export function integer(value: unknown, min: number, max: number): number {
  requireThat(typeof value === "number" && Number.isSafeInteger(value) && value >= min && value <= max, "INVALID_ARGUMENT", "Integer out of range");
  return value;
}
export function list(value: unknown, max = 100, min = 0): unknown[] {
  requireThat(Array.isArray(value) && value.length >= min && value.length <= max, "INVALID_ARGUMENT", "Invalid array length"); return value;
}
export function strings(value: unknown, max = 100): string[] { return list(value, max).map(v => text(v)); }
export function enumeration<T extends string>(value: unknown, values: readonly T[]): T {
  requireThat(typeof value === "string" && values.includes(value as T), "INVALID_ARGUMENT", "Unsupported enum value"); return value as T;
}
export function address(value: unknown): string {
  requireThat((typeof value === "number" && Number.isSafeInteger(value) && value >= 0) || (typeof value === "string" && /^(0x[0-9a-fA-F]+|[0-9]+)$/.test(value) && value.length <= 80), "INVALID_ARGUMENT", "Address must be an exact nonnegative integer or decimal/0x string");
  return `0x${BigInt(value as string | number).toString(16)}`;
}
export function sha256(content: string | Uint8Array): string { return createHash("sha256").update(content).digest("hex"); }
export function stable(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(stable).join(",")}]`;
  if (value && typeof value === "object") return `{${Object.entries(value).filter(([, v]) => v !== undefined).sort(([a], [b]) => a.localeCompare(b)).map(([k, v]) => `${JSON.stringify(k)}:${stable(v)}`).join(",")}}`;
  return JSON.stringify(value);
}
export function artifact(content: string, kind: string, origin: string): Artifact {
  const hash = sha256(content);
  return { id: `sha256:${hash}`, sha256: hash, size_bytes: Buffer.byteLength(content), media_type: "text/plain;charset=utf-8", kind, origin, instruction_authority: "none", content };
}
export function safeError(error: unknown): { code: string; message: string } {
  return error instanceof DomainError ? { code: error.code, message: error.message } : { code: "INTERNAL_ERROR", message: "Unexpected runtime error (raw payload withheld)" };
}
