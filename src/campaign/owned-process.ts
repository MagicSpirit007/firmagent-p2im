import { spawn } from "node:child_process";
import { existsSync, readFileSync, appendFileSync, mkdirSync, readdirSync } from "node:fs";
import { join } from "node:path";
import { requireThat } from "../contracts.js";
export interface OwnedIdentity { pid: number; pgid: number; sid: number; start_identity: string; kind: string; attempt_id: string }
function procStat(pid: number): { state: string; pgid: number; sid: number; start_identity: string } | null {
  try {
    const text = readFileSync(`/proc/${pid}/stat`, "utf8"), fields = text.slice(text.lastIndexOf(")") + 2).split(" ");
    const pgid = Number(fields[2]), sid = Number(fields[3]), start = fields[19];
    if (!fields[0] || !Number.isInteger(pgid) || !Number.isInteger(sid) || !start) return null;
    return { state: fields[0], pgid, sid, start_identity: start };
  } catch { return null; }
}
/** Live identity. A zombie is not a process cleanup can still own. */
export function processIdentity(pid: number): Omit<OwnedIdentity, "kind" | "attempt_id"> | null {
  const row = procStat(pid);
  if (!row || row.state === "Z") return null;
  return { pid, pgid: row.pgid, sid: row.sid, start_identity: row.start_identity };
}
/** Registration identity. A helper may already be a zombie when the spawn callback runs. */
export function helperIdentity(pid: number): Omit<OwnedIdentity, "kind" | "attempt_id"> | null {
  const row = procStat(pid);
  if (!row) return null;
  return { pid, pgid: row.pgid, sid: row.sid, start_identity: row.start_identity };
}
function identities(file: string): OwnedIdentity[] {
  if (!existsSync(file)) return [];
  return readFileSync(file, "utf8").split("\n").filter(Boolean).map(line => { const i = JSON.parse(line) as OwnedIdentity; requireThat(Number.isInteger(i.pid) && Number.isInteger(i.pgid) && typeof i.start_identity === "string" && typeof i.attempt_id === "string", "OWNERSHIP_RECORD_INVALID", "Malformed ownership record"); return i; });
}
const pause = (ms: number) => new Promise<void>(r => setTimeout(r, ms));
function ownedAlive(all: OwnedIdentity[]): OwnedIdentity[] {
  const proc = readdirSync("/proc").filter(name => /^\d+$/.test(name)).flatMap(name => { const i = processIdentity(Number(name)); return i ? [i] : []; });
  const found = new Map<number, OwnedIdentity>();
  for (const owner of all) {
    const current = proc.find(p => p.pid === owner.pid);
    // A PID reused after the owned leader vanished cannot grant ownership to its new group.
    if (current && current.start_identity !== owner.start_identity) continue;
    const same = proc.filter(p => p.pgid === owner.pgid && p.sid === (owner.sid ?? owner.pgid) && BigInt(p.start_identity) >= BigInt(owner.start_identity));
    for (const member of same) found.set(member.pid, { ...owner, ...member });
    if (current?.start_identity === owner.start_identity) found.set(current.pid, { ...owner, ...current });
  }
  return [...found.values()];
}
export async function cleanupOwned(file: string, attemptId: string): Promise<{ status: "clean" | "failed"; reason?: string; survivors: OwnedIdentity[]; identities: OwnedIdentity[] }> {
  if (!existsSync(file)) {
    const receipt = { status: "failed" as const, reason: "OWNERSHIP_RECORD_MISSING", survivors: [] as OwnedIdentity[], identities: [] as OwnedIdentity[] };
    appendFileSync(join(file, "..", "cleanup.jsonl"), JSON.stringify({ at: Date.now(), ...receipt }) + "\n");
    return receipt;
  }
  const start = Date.now(); let all: OwnedIdentity[] = [], survivors: OwnedIdentity[] = [], emptySince: number | undefined;
  do {
    all = identities(file).filter(i => i.attempt_id === attemptId); survivors = ownedAlive(all);
    if (!survivors.length) { emptySince ??= Date.now(); if (Date.now() - emptySince >= 75) break; } else emptySince = undefined;
    const sig = Date.now() - start >= 2000 ? "SIGKILL" : "SIGTERM";
    const groups = new Set<number>(); const self = processIdentity(process.pid);
    for (const item of survivors) {
      if (item.pgid > 1 && item.pgid !== self?.pgid) groups.add(item.pgid);
      else try { process.kill(item.pid, sig); } catch {}
    }
    for (const pgid of groups) try { process.kill(-pgid, sig); } catch {}
    await pause(25);
  } while (Date.now() - start < 4800);
  const receipt = { status: survivors.length ? "failed" as const : "clean" as const, survivors, identities: all };
  appendFileSync(join(file, "..", "cleanup.jsonl"), JSON.stringify({ at: Date.now(), ...receipt }) + "\n"); return receipt;
}
export async function ownedHelper(argv: string[], options: { cwd: string; attemptDirectory: string; signal: AbortSignal; timeoutMs: number; env: Record<string,string> }): Promise<{ code: number; stdout: string; stderr: string }> {
  options.signal.throwIfAborted(); mkdirSync(options.attemptDirectory, { recursive: true });
  const file = join(options.attemptDirectory, "owned.jsonl"), attemptId = options.env.F0_ATTEMPT_ID!;
  const child = spawn(argv[0]!, argv.slice(1), { cwd: options.cwd, env: { ...process.env, ...options.env }, detached: true, windowsHide: true });
  let stdout = "", stderr = "", spawned = false, stopping = false, cleanup: Promise<unknown> | undefined;
  child.stdout?.on("data", b => { stdout += String(b); }); child.stderr?.on("data", b => { stderr += String(b); });
  const stop = () => { stopping = true; if (spawned && !cleanup) cleanup = cleanupOwned(file, attemptId); };
  const timer = setTimeout(stop, options.timeoutMs); options.signal.addEventListener("abort", stop, { once: true });
  try {
    const code = await new Promise<number>((resolve, reject) => {
      child.once("spawn", () => {
        try {
          const identity = helperIdentity(child.pid!); requireThat(identity, "OWNERSHIP_REGISTRATION", "Cannot identify helper");
          appendFileSync(file, JSON.stringify({ ...identity, kind: "helper", attempt_id: attemptId }) + "\n"); spawned = true; if (options.signal.aborted || stopping) stop();
        } catch (error) { try { process.kill(-child.pid!, "SIGKILL"); } catch {} reject(error); }
      });
      child.once("error", reject); child.once("close", code => resolve(code ?? -1));
    });
    await cleanup; const receipt = await cleanupOwned(file, attemptId); requireThat(receipt.status === "clean", "CLEANUP_FAILED", JSON.stringify(receipt.survivors));
    options.signal.throwIfAborted(); requireThat(!stopping, "HELPER_TIMEOUT", "Helper exceeded its deadline"); return { code, stdout, stderr };
  } finally {
    clearTimeout(timer); options.signal.removeEventListener("abort", stop);
    if (spawned) { await cleanup; const receipt = await cleanupOwned(file, attemptId); requireThat(receipt.status === "clean", "CLEANUP_FAILED", JSON.stringify(receipt.survivors)); }
  }
}
