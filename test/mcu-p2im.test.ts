import test from "node:test";
import assert from "node:assert/strict";
import { existsSync, mkdtempSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { Mcup2imOracle, OracleError } from "../src/campaign/mcu-oracle.js";
import { assertNoLeak, mcup2imTools } from "../src/campaign/mcu-tools.js";
import { Mcup2imCampaign, MCUP2IM_PROMPTS, linkUpstream } from "../src/campaign/mcu-runtime.js";
import { mcup2imBudget, parseMcup2imConfig, type Mcup2imConfig } from "../src/campaign/mcu-types.js";
import { sha256, stable } from "../src/contracts.js";

const HASH = "a".repeat(64);

function config(overrides: Partial<Mcup2imConfig> = {}): Mcup2imConfig {
  return parseMcup2imConfig({
    schema_version: 1, target: "PLC", elf: "/targets/PLC", elf_sha256: HASH,
    board: "STM32F429I-Discovery", mcu: "STM32F429ZI", work_root: "/home/u/fa-p2im",
    oracle: "/tools/p2im_oracle.py", runner: "/tools/oracle.sh", python: "python3",
    wsl_distro: "Ubuntu-24.04", fuzz_hard_cap_s: 60, segment_seconds: 30, max_segments: 1,
    replay_repeat: 3, contrast_budget: 1, max_contrast_replays: 10, ...overrides,
  });
}

function oracleFor(configValue: Mcup2imConfig, platform: NodeJS.Platform, response: object) {
  const seen: string[][] = [];
  const oracle = new Mcup2imOracle(configValue, {
    platform,
    execute: async (command) => {
      seen.push(command);
      return { code: 0, stdout: JSON.stringify(response), stderr: "", duration_ms: 1, timedOut: false };
    },
  });
  return { oracle, seen };
}

test("mcu-p2im config is frozen and validated", () => {
  const parsed = config();
  assert.equal(parsed.target, "PLC");
  assert.throws(() => config({ elf_sha256: "not-a-hash" }), /elf_sha256/);
  assert.throws(() => config({ segment_seconds: 120, fuzz_hard_cap_s: 60 }), /segment_seconds/);
  assert.throws(() => parseMcup2imConfig({ ...JSON.parse(JSON.stringify(parsed)), extra: 1 }), /object fields/i);
  const budget = mcup2imBudget({ max_model_requests: 2, tool_calls: 5 });
  assert.equal(budget.max_model_requests, 2);
  assert.equal(budget.max_tokens, 40_000);
});

test("oracle bridge keeps platform command shape and never rewrites arguments", async () => {
  const { oracle, seen } = oracleFor(config(), "linux", { schema: "mcu-p2im/oracle-0.2", ok: true, status: {} });
  await oracle.call(["status", "--target", "PLC"]);
  assert.deepEqual(seen[0], ["python3", "/tools/p2im_oracle.py", "status", "--target", "PLC"]);

  const win = oracleFor(config(), "win32", { schema: "mcu-p2im/oracle-0.2", ok: true, status: {} });
  await win.oracle.call(["status"]);
  assert.deepEqual(win.seen[0], ["wsl.exe", "-d", "Ubuntu-24.04", "--", "bash", "/tools/oracle.sh", "status"]);

  const bare = oracleFor(config({ runner: "" }), "win32", { schema: "mcu-p2im/oracle-0.2", ok: true, status: {} });
  await bare.oracle.call(["status"]);
  assert.deepEqual(bare.seen[0], ["wsl.exe", "-d", "Ubuntu-24.04", "--", "python3", "/tools/p2im_oracle.py", "status"]);
});

test("oracle bridge maps refusal, timeout and non-JSON output to typed errors", async () => {
  const refusal = new Mcup2imOracle(config(), {
    platform: "linux",
    execute: async () => ({ code: 3, stdout: JSON.stringify({ ok: false, error: "ELF hash does not match" }), stderr: "", duration_ms: 1, timedOut: false }),
  });
  await assert.rejects(() => refusal.call(["prepare"]), (error: unknown) => error instanceof OracleError && error.code === "ORACLE_REFUSED");

  const timeout = new Mcup2imOracle(config(), {
    platform: "linux",
    execute: async () => ({ code: null, stdout: "", stderr: "killed", duration_ms: 5, timedOut: true }),
  });
  await assert.rejects(() => timeout.call(["fuzz"]), (error: unknown) => error instanceof OracleError && error.code === "ORACLE_TIMEOUT");

  const garbage = new Mcup2imOracle(config(), {
    platform: "linux",
    execute: async () => ({ code: 0, stdout: "not json", stderr: "", duration_ms: 1, timedOut: false }),
  });
  await assert.rejects(() => garbage.call(["status"]), (error: unknown) => error instanceof OracleError && error.code === "ORACLE_OUTPUT");
});

test("mcu-p2im prompts are stable, truth-free and role-scoped", () => {
  const digests = Object.fromEntries(Object.entries(MCUP2IM_PROMPTS).map(([role, prompt]) => [role, sha256(stable(prompt))]));
  assert.equal(new Set(Object.values(digests)).size, 3);
  for (const prompt of Object.values(MCUP2IM_PROMPTS)) {
    assertNoLeak(prompt, "prompt");
    assert.ok(!/fuzz_run/i.test(prompt) || prompt === MCUP2IM_PROMPTS.discover);
  }
  assert.throws(() => assertNoLeak("see CVE-2024-0001", "artifact"), /truth-set token/);
  assert.throws(() => assertNoLeak("CWE-121 stack overflow", "artifact"), /truth-set token/);
});

test("discover role only receives fuzz_run when discovery is enabled", () => {
  const ports = {} as never;
  const enabled = mcup2imTools("discover", ports, { fuzzHardCapS: 120, discoverEnabled: true }).map(tool => tool.name);
  const disabled = mcup2imTools("discover", ports, { fuzzHardCapS: 120, discoverEnabled: false }).map(tool => tool.name);
  assert.ok(enabled.includes("fuzz_run"));
  assert.ok(!disabled.includes("fuzz_run"));
  assert.deepEqual(mcup2imTools("main", ports, { fuzzHardCapS: 120 }).map(tool => tool.name).sort(),
    ["crash_list", "hypothesis_note", "mcu_status", "read_artifact_chunk", "seed_propose", "slice_paths"]);
  assert.deepEqual(mcup2imTools("replay", ports, { fuzzHardCapS: 120 }).map(tool => tool.name).sort(), ["crash_contrast", "crash_list", "crash_replay", "mcu_status"]);
});

type FakePayload = Record<string, unknown>;

/** A deterministic stand-in for the oracle: same envelope schema, no process, no QEMU. */
class FakeOracle {
  calls: string[][] = [];
  constructor(private readonly responses: Record<string, FakePayload>) {}
  async call<T>(argv: string[]): Promise<{ payload: T; command: string[]; duration_ms: number; stderr_tail: string }> {
    this.calls.push(argv);
    const key = argv[0] ?? "";
    const body = this.responses[key];
    if (!body) throw new OracleError("ORACLE_FAILED", `fake oracle has no response for ${key}`);
    return { payload: body as T, command: argv, duration_ms: 1, stderr_tail: "" };
  }
}

function fakeResponses(): Record<string, FakePayload> {
  const crash = { id: "id:000000,ret_v:0xff,src:000000", sha256: "b".repeat(64), bytes: 97, ret_v: "0xff", segment_dir: "outputs-s1" };
  const replay = { run_id: "r-1", input_sha256: crash.sha256, input_bytes: 97, round: "0",
    outcome: "crash", exit_code: 255, fault: { kind: "read", address: "0xfffc0004" },
    last_bbl: { start: "0x8003f30", end: "0x8003f3e", function: "HAL_UART_RxCpltCallback" } };
  return {
    prepare: { schema: "mcu-p2im/oracle-0.2", ok: true, target: "PLC", work_dir: "/home/u/fa-p2im/plc", elf_sha256: HASH },
    status: { schema: "mcu-p2im/oracle-0.2", ok: true, status: { target: "PLC", rounds: ["0"], segments: 0 } },
    fuzz: { schema: "mcu-p2im/oracle-0.2", ok: true, segment: { segment: "s1", requested_seconds: 30, duration_s: 31.2,
      exit_code: 124, timed_out: true, execs_done: 1480, paths_total: 12, unique_crashes: 1, unique_hangs: 0,
      queue_files: 13, crash_files: 1, bitmap_cvg: "0.01%", crashes: [crash], rounds: ["0"] } },
    crashes: { schema: "mcu-p2im/oracle-0.2", ok: true, crashes: { raw_files: 2, unique: 1, crashes: [crash] } },
    replay: { schema: "mcu-p2im/oracle-0.2", ok: true, replay, repeated: 3, deterministic: true, outcomes: [replay, replay, replay] },
    contrast: { schema: "mcu-p2im/oracle-0.2", ok: true, contrast: { schema: "mcu-p2im/contrast-0.2", contrast_confirmed: true,
      replays_used: 7, replay_budget: 10, decisive_byte: 41,
      minimized: { path: "/home/u/fa-p2im/plc/evidence/contrast-1.min", sha256: "c".repeat(64), bytes: 12, outcome: "crash", fault: replay.fault },
      negative: { path: "/home/u/fa-p2im/plc/evidence/contrast-1.min.neg", sha256: "d".repeat(64), bytes: 11, outcome: "ok", fault: null } } },
    "extract-sources": { schema: "mcu-p2im/oracle-0.2", ok: true, source_count: 2, sources_path: "/x/sources.json" },
    "slice-paths": { schema: "mcu-p2im/oracle-0.2", ok: true, paths_path: "/x/paths.json",
      counts: { functions: 371, paths: 3, sinks: 4, sources: 2, static_edges: 900, dynamic_indirect_edges: 7 } },
  };
}

test("offline campaign runs the full host pipeline with model_requests = 0", async () => {
  const out = mkdtempSync(join(tmpdir(), "mcu-p2im-run-"));
  const oracle = new FakeOracle(fakeResponses());
  const campaign = await Mcup2imCampaign.start({
    config: config(), out, mode: "offline", budget: mcup2imBudget({ tool_calls: 32 }),
    oracle: oracle as never,
  });
  const state = await campaign.run();
  assert.equal(state.status, "completed");
  assert.equal(state.layers.l1, 2);
  assert.equal(state.layers.l2, 1);
  assert.equal(state.layers.l3, 1);
  assert.equal(state.layers.l4, 1);
  assert.equal(state.segments.length, 1);
  assert.equal(state.segments[0]!.execs_done, 1480);
  assert.equal(campaign.governance.account.requests.length, 0, "offline mode must issue zero model requests");
  assert.ok(existsSync(join(out, "score-owned.json")));
  assert.ok(existsSync(join(out, "state.json")));
  assert.ok(existsSync(join(out, "ledger.jsonl")));
  const score = JSON.parse(readFileSync(join(out, "score-owned.json"), "utf8"));
  assert.equal(score.model_requests, 0);
  assert.equal(score.layers.l4, 1);
  assert.equal(score.detail.length, 1);
  const calls = oracle.calls.map(argv => argv[0]);
  assert.deepEqual(calls, ["prepare", "status", "fuzz", "extract-sources", "slice-paths", "crashes", "replay", "contrast"]);
  const ledger = readFileSync(join(out, "ledger.jsonl"), "utf8");
  assert.match(ledger, /discover_seg1/);
  assert.match(ledger, /analyze_skipped/);
  assert.ok(existsSync(join(out, "l5-candidates.json")));
});

test("shared via keeps the indexed overlap when a later global also names the crash", () => {
  const crash = "HAL_UART_RxCpltCallback";
  const globals = [
    { symbol: "rx_callback", indexed_reach: [{ function: "Modbus::process_FC3" }], adjacent: [],
      referencers: [{ function: crash }, { function: "Modbus::process_FC3" }] },
    { symbol: "rx_callback_obj", referencers: [{ function: crash }, { function: "uart_attach_rx_callback" }] },
  ];
  const forward = linkUpstream(crash, globals);
  assert.equal(forward.via, "rx_callback");
  assert.ok(forward.upstream.includes("Modbus::process_FC3"));
  const backward = linkUpstream(crash, [...globals].reverse());
  assert.equal(backward.via, "rx_callback");
});

test("offline campaign stops at the wall budget without claiming completion", async () => {
  const out = mkdtempSync(join(tmpdir(), "mcu-p2im-budget-"));
  const oracle = new FakeOracle(fakeResponses());
  const campaign = await Mcup2imCampaign.start({
    config: config({ max_segments: 4 }), out, mode: "offline",
    budget: mcup2imBudget({ tool_calls: 2 }), oracle: oracle as never,
  });
  await assert.rejects(() => campaign.run(), /BUDGET_EXHAUSTED|tool/i);
  assert.notEqual(campaign.state.status, "completed");
});
