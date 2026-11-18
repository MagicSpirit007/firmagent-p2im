import { randomUUID } from "node:crypto";
import { existsSync, readFileSync, writeFileSync, mkdirSync, renameSync, unlinkSync, openSync, fsyncSync, closeSync } from "node:fs";
import { join } from "node:path";
import { processIdentity } from "./owned-process.js";
import { DomainError, requireThat, sha256, stable } from "../contracts.js";

export interface RunLimits { max_model_requests: number; max_tokens: number; max_output_tokens: number; max_target_execs: number; tool_calls: number; wall_ms: number }
export interface BudgetDetail { scope: "run" | "role" | "task"; resource: "requests" | "tokens" | "tools" | "wall"; limit: number; used: number }
export class BudgetError extends DomainError {
  constructor(readonly detail: BudgetDetail, message: string) { super("BUDGET_EXHAUSTED", message); this.name = "BudgetError"; }
}
export interface TokenThresholdCross { request_id: string; before: number; settled: number; after: number; limit: number }
export interface RequestAccount { id: string; session_id: string; attempt_id: string; retry: boolean; state: "pending" | "settled" | "unknown"; tokens: number | null; cost: number | null }
export interface RunAccount { schema_version: 2; run_id: string; attempt_id: string; parent_attempt_id: string | null; config_sha256: string; limits: RunLimits; requests: RequestAccount[]; responses: number; retries: number; tokens: number; target_execs: number; tools: number; active_ms: number; attempt_started_at: number; last_persisted_at: number; status: "running" | "partial" | "completed" | "failed"; attempts: { id: string; parent: string | null; started_at: number; ended_at: number | null }[] }
/** Synchronous admissions are atomic within the host. Exclusive lock prevents concurrent hosts. */
export class RunGovernance {
  readonly account: RunAccount; readonly attemptDirectory: string;
  private readonly file: string; private readonly lock: string; private baseMs: number; private start = Date.now(); private closed = false;
  private threshold: TokenThresholdCross | null = null;
  constructor(readonly directory: string, config: unknown, limits: RunLimits, parentAttemptId?: string, prepare?: () => void) {
    mkdirSync(directory, { recursive: true }); this.file = join(directory, "account.json"); this.lock = join(directory, "attempt.lock");
    const marker = join(directory, "run-identity.json"); const hash = sha256(stable(config));
    if (!parentAttemptId) requireThat(!existsSync(marker) && !existsSync(this.file) && !existsSync(join(directory, "campaign.json")), "EXPLICIT_RESUME_REQUIRED", "Run directory has prior identity");
    const gate = join(directory, "resume-gate.lock");
    const nonce = randomUUID(); let ownedLock = false;
    if (existsSync(gate)) {
      const gateOwner = JSON.parse(readFileSync(gate, "utf8"));
      requireThat(parentAttemptId !== undefined && processIdentity(gateOwner.pid)?.start_identity !== gateOwner.start_identity, "ATTEMPT_LOCKED", "Resume gate is live");
      // Dead gate recovery is serialized by a separate wx reclamation token.
      const reclaim = gate + ".reclaim"; writeFileSync(reclaim, nonce, { flag: "wx" });
      try { if (existsSync(gate) && readFileSync(gate, "utf8") === JSON.stringify(gateOwner)) unlinkSync(gate); } finally { unlinkSync(reclaim); }
    }
    try { writeFileSync(gate, JSON.stringify({ pid: process.pid, start_identity: processIdentity(process.pid)?.start_identity, nonce }), { flag: "wx" }); } catch { throw new Error("ATTEMPT_LOCKED"); }
    try {
    if (existsSync(this.lock)) {
      const owner = JSON.parse(readFileSync(this.lock, "utf8"));
      requireThat(parentAttemptId !== undefined && processIdentity(owner.pid)?.start_identity !== owner.start_identity, "ATTEMPT_LOCKED", "Live attempt owns the run");
      unlinkSync(this.lock);
    }
    writeFileSync(this.lock, JSON.stringify({ pid: process.pid, start_identity: processIdentity(process.pid)?.start_identity, nonce }), { flag: "wx" }); ownedLock = true;
    let prior: RunAccount | undefined;
    if (parentAttemptId) {
      requireThat(existsSync(marker) && existsSync(this.file) && existsSync(join(directory, "state.json")), "RESUME_STATE_MISSING", "Resume needs retained state and identity");
      prior = JSON.parse(readFileSync(this.file, "utf8")) as RunAccount;
      requireThat(prior.schema_version === 2 && prior.attempt_id === parentAttemptId, "RESUME_PARENT_MISMATCH", "Attempt is no longer the resume head");
      requireThat(prior.status !== "completed", "RUN_ALREADY_COMPLETED", "Completed run cannot resume");
      requireThat(prior.config_sha256 === hash && stable(prior.limits) === stable(limits), "RESUME_CONFIG_CHANGED", "Configuration and budget are immutable");
      requireThat(!prior.requests.some(r => r.state !== "settled"), "REQUEST_UNSETTLED", "Unsettled or unknown usage freezes the run");
    }
    prepare?.();
    if (prior) this.account = { ...prior, parent_attempt_id: prior.attempt_id, attempt_id: randomUUID(), status: "running", active_ms: prior.active_ms + (prior.status === "running" ? Math.max(0, Date.now() - prior.last_persisted_at) : 0) };
    else this.account = { schema_version: 2, run_id: randomUUID(), attempt_id: randomUUID(), parent_attempt_id: null, config_sha256: hash, limits, requests: [], responses: 0, retries: 0, tokens: 0, target_execs: 0, tools: 0, active_ms: 0, attempt_started_at: this.start, last_persisted_at: this.start, status: "running", attempts: [] };
    if (!parentAttemptId) writeFileSync(marker, JSON.stringify({ schema_version: 2, run_id: this.account.run_id, config_sha256: hash }), { flag: "wx" });
    const executions = join(directory, "executions.json"); if (existsSync(executions)) this.account.target_execs = JSON.parse(readFileSync(executions, "utf8")).count;
    this.baseMs = this.account.active_ms; this.account.attempt_started_at = this.start;
    this.account.attempts.push({ id: this.account.attempt_id, parent: this.account.parent_attempt_id, started_at: this.start, ended_at: null });
    this.attemptDirectory = join(directory, "attempts", this.account.attempt_id); mkdirSync(this.attemptDirectory, { recursive: true }); this.persist();
    } catch (error) { if (ownedLock && existsSync(this.lock) && JSON.parse(readFileSync(this.lock, "utf8")).nonce === nonce) unlinkSync(this.lock); throw error; } finally { if (existsSync(gate) && JSON.parse(readFileSync(gate, "utf8")).nonce === nonce) unlinkSync(gate); }
  }
  get activeMs(): number { return this.baseMs + Math.max(0, Date.now() - this.start); }
  get deadline(): number { return this.start + this.account.limits.wall_ms - this.baseMs; }
  check(): void {
    if (this.closed || Date.now() >= this.deadline) throw new BudgetError({ scope: "run", resource: "wall", limit: this.account.limits.wall_ms, used: this.activeMs }, "Wall clock budget exhausted");
  }
  takeThreshold(): TokenThresholdCross | null { const value = this.threshold; this.threshold = null; return value; }
  persist(): void { this.account.active_ms = this.activeMs; const temp = this.file + ".tmp"; this.account.last_persisted_at = Date.now(); writeFileSync(temp, JSON.stringify(this.account, null, 2)); const fd = openSync(temp, "r"); try { fsyncSync(fd); } finally { closeSync(fd); } renameSync(temp, this.file); const dirfd = openSync(this.directory, "r"); try { fsyncSync(dirfd); } finally { closeSync(dirfd); } }
  admitRequest(sessionId: string, retry: boolean): string {
    this.check(); requireThat(!this.account.requests.some(r => r.state === "unknown"), "USAGE_UNKNOWN", "Unknown usage freezes requests");
    requireThat(!this.account.requests.some(r => r.state === "pending"), "REQUEST_IN_FLIGHT", "F0 dispatch is serial");
    if (this.account.requests.length >= this.account.limits.max_model_requests) throw new BudgetError({ scope: "run", resource: "requests", limit: this.account.limits.max_model_requests, used: this.account.requests.length }, "Model budget exhausted");
    if (this.account.tokens >= this.account.limits.max_tokens) throw new BudgetError({ scope: "run", resource: "tokens", limit: this.account.limits.max_tokens, used: this.account.tokens }, "Model budget exhausted");
    const id = randomUUID(); this.account.requests.push({ id, session_id: sessionId, attempt_id: this.account.attempt_id, retry, state: "pending", tokens: null, cost: null }); if (retry) this.account.retries++; this.persist(); return id;
  }
  settle(id: string, usage: { totalTokens?: number; cost?: { total?: number } } | null, known: boolean): void {
    const record = this.account.requests.find(r => r.id === id); requireThat(record?.state === "pending", "REQUEST_SETTLEMENT", "Request is not pending");
    const tokens = usage?.totalTokens; known &&= typeof tokens === "number" && Number.isFinite(tokens) && tokens >= 0;
    record.state = known ? "settled" : "unknown"; record.tokens = known ? tokens! : null; record.cost = null; // F0 has no independent billing source; SDK defaults are estimates.
    this.account.responses++;
    if (known) {
      const before = this.account.tokens; this.account.tokens += tokens!;
      const limit = this.account.limits.max_tokens;
      if (before < limit && this.account.tokens >= limit) this.threshold = { request_id: id, before, settled: tokens!, after: this.account.tokens, limit };
    }
    this.persist();
  }
  admitTool(): void {
    this.check();
    if (this.account.tools >= this.account.limits.tool_calls) throw new BudgetError({ scope: "run", resource: "tools", limit: this.account.limits.tool_calls, used: this.account.tools }, "Tool budget exhausted");
    this.account.tools++; this.persist();
  }
  finish(status: RunAccount["status"]): void { if (this.closed) return; this.account.status = status; this.account.attempts.at(-1)!.ended_at = Date.now(); this.persist(); this.closed = true; unlinkSync(this.lock); }
}
