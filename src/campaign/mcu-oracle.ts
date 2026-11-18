import { spawn, type ChildProcess } from "node:child_process";
import { DomainError } from "../contracts.js";
import type { Mcup2imConfig } from "./mcu-types.js";

export class OracleError extends DomainError {
  constructor(readonly code: string, message: string, readonly detail?: Record<string, unknown>) {
    super(code, message);
    this.name = "OracleError";
  }
}

export interface OracleResult<T = Record<string, unknown>> {
  payload: T;
  command: string[];
  duration_ms: number;
  stderr_tail: string;
}

export interface OracleClientOptions {
  /** Injection point for tests: never spawn a process. */
  execute?: (command: string[], timeoutMs: number) => Promise<{ code: number | null; stdout: string; stderr: string; duration_ms: number; timedOut: boolean }>;
  platform?: NodeJS.Platform;
  max_stdout_bytes?: number;
}

const MAX_STDOUT = 32 * 1024 * 1024;

function tail(value: string, limit = 4096): string {
  return value.length <= limit ? value : value.slice(value.length - limit);
}

/**
 * Host-owned bridge to tools/p2im_oracle.py. On Windows the oracle runs inside the WSL2
 * distribution, so every path in the configuration is a Linux path; the bridge never rewrites
 * arguments and never passes them through a shell.
 */
export class Mcup2imOracle {
  constructor(readonly config: Mcup2imConfig, private readonly options: OracleClientOptions = {}) {}

  private baseCommand(): string[] {
    const platform = this.options.platform ?? process.platform;
    if (platform === "win32") {
      const distro = this.config.wsl_distro;
      if (!distro) throw new OracleError("WSL_DISTRO_MISSING", "Windows hosts must name a WSL distribution");
      if (this.config.runner) return ["wsl.exe", "-d", distro, "--", "bash", this.config.runner];
      return ["wsl.exe", "-d", distro, "--", this.config.python, this.config.oracle];
    }
    return [this.config.python, this.config.oracle];
  }

  async call<T = Record<string, unknown>>(argv: string[], timeoutMs = 600_000): Promise<OracleResult<T>> {
    const command = [...this.baseCommand(), ...argv];
    const execute = this.options.execute ?? ((cmd, timeout) => this.spawnBounded(cmd, timeout));
    const outcome = await execute(command, timeoutMs);
    if (outcome.timedOut) {
      throw new OracleError("ORACLE_TIMEOUT", `oracle did not finish within ${timeoutMs} ms`,
        { command, stderr_tail: tail(outcome.stderr) });
    }
    if (outcome.code !== 0) {
      let parsed: Record<string, unknown> | null = null;
      try { parsed = JSON.parse(outcome.stdout) as Record<string, unknown>; } catch { parsed = null; }
      const code = outcome.code === 3 ? "ORACLE_REFUSED" : "ORACLE_FAILED";
      throw new OracleError(code, String(parsed?.error ?? `oracle exited ${outcome.code}`),
        { command, exit_code: outcome.code, stderr_tail: tail(outcome.stderr), payload: parsed });
    }
    let payload: T;
    try { payload = JSON.parse(outcome.stdout) as T; } catch {
      throw new OracleError("ORACLE_OUTPUT", "oracle stdout was not a single JSON object",
        { command, stdout_head: outcome.stdout.slice(0, 512), stderr_tail: tail(outcome.stderr) });
    }
    const envelope = payload as unknown as { ok?: boolean; schema?: string; error?: string };
    if (envelope.ok === false) {
      throw new OracleError("ORACLE_REFUSED", String(envelope.error ?? "oracle refused"), { payload });
    }
    if (typeof envelope.schema !== "string" || !envelope.schema.startsWith("mcu-p2im/")) {
      throw new OracleError("ORACLE_SCHEMA", "oracle payload has no mcu-p2im schema", { payload });
    }
    return { payload, command, duration_ms: outcome.duration_ms, stderr_tail: tail(outcome.stderr) };
  }

  private spawnBounded(command: string[], timeoutMs: number) {
    return new Promise<{ code: number | null; stdout: string; stderr: string; duration_ms: number; timedOut: boolean }>((resolve, reject) => {
      const started = Date.now();
      const child: ChildProcess = spawn(command[0]!, command.slice(1), {
        detached: process.platform !== "win32", windowsHide: true, stdio: ["ignore", "pipe", "pipe"],
      });
      let stdout = ""; let stderr = ""; let timedOut = false; let overflow = false;
      const timer = setTimeout(() => {
        timedOut = true;
        this.kill(child);
      }, timeoutMs);
      child.stdout?.on("data", (chunk: Buffer) => {
        if (stdout.length + chunk.length > (this.options.max_stdout_bytes ?? MAX_STDOUT)) { overflow = true; this.kill(child); return; }
        stdout += chunk.toString("utf8");
      });
      child.stderr?.on("data", (chunk: Buffer) => { stderr = tail(stderr + chunk.toString("utf8"), 16384); });
      child.on("error", (error) => { clearTimeout(timer); reject(new OracleError("ORACLE_SPAWN", String(error))); });
      child.on("close", (code) => {
        clearTimeout(timer);
        if (overflow) { reject(new OracleError("ORACLE_OUTPUT_OVERSIZE", "oracle stdout exceeded the bridge limit")); return; }
        resolve({ code, stdout, stderr, duration_ms: Date.now() - started, timedOut });
      });
    });
  }

  private kill(child: ChildProcess): void {
    if (child.pid === undefined) return;
    if (process.platform === "win32") {
      spawn("taskkill", ["/PID", String(child.pid), "/T", "/F"], { windowsHide: true });
      return;
    }
    try { process.kill(-child.pid, "SIGKILL"); } catch { try { child.kill("SIGKILL"); } catch { /* already gone */ } }
  }
}
