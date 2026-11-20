import test from "node:test";
import assert from "node:assert/strict";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { createFauxCore, fauxAssistantMessage, fauxToolCall, type FauxResponseStep } from "@earendil-works/pi-ai";
import { ModelRuntime } from "@earendil-works/pi-coding-agent";
import { Mcup2imOracle, OracleError } from "../src/campaign/mcu-oracle.js";
import { assertNoLeak, mcup2imTools } from "../src/campaign/mcu-tools.js";
import { Mcup2imCampaign, MCUP2IM_PROMPTS, interleaveCrashRows, linkUpstream } from "../src/campaign/mcu-runtime.js";
import { MCUP2IM_BUDGET, mcup2imBudget, parseMcup2imConfig, type Mcup2imConfig, type Mcup2imRole } from "../src/campaign/mcu-types.js";
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
  assert.equal(budget.max_tokens, 160_000);
  assert.equal(MCUP2IM_BUDGET.max_output_tokens, 16_384);
  assert.equal(MCUP2IM_BUDGET.wall_ms, 3_600_000);
  assert.equal(MCUP2IM_BUDGET.analyze_model_calls, 6);
  assert.equal(MCUP2IM_BUDGET.replay_model_calls, 0);
  assert.equal(parsed.inherit_queue_s2, true);
  assert.equal(parsed.collect_coverage, false);
  const custom = config({ inherit_queue_s2: false, collect_coverage: true });
  assert.equal(custom.inherit_queue_s2, false);
  assert.equal(custom.collect_coverage, true);
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

function setupSlicedWorkDir(workRoot: string, slug = "plc") {
  const workDir = join(workRoot, slug);
  mkdirSync(join(workDir, "analysis"), { recursive: true });
  writeFileSync(join(workDir, "analysis", "sources.json"), JSON.stringify({ sources: [{ function: "HAL_UART_IRQHandler" }] }));
  writeFileSync(join(workDir, "analysis", "paths.json"), JSON.stringify({
    counts: { paths: 1, shared_globals: 1 },
    shared_globals: [{
      symbol: "rx_callback",
      address: "0x20000214",
      kind: "via_shared_global",
      call_edge: false,
      interrupt_write_side: ["HAL_UART_RxCpltCallback"],
      main_consume_side: [],
      referencers: [{ function: "HAL_UART_RxCpltCallback" }, { function: "Modbus::process_FC1" }],
      indexed_reach: [{ function: "Modbus::process_FC1", base_symbol: "slave", member_offset: 9, max_index: 255, call_edge: false }],
      adjacent: [{ symbol: "slave", address: "0x20000124", gap: 0 }],
    }],
  }));
  return workDir;
}

class DynamicFakeOracle {
  calls: string[][] = [];
  private readonly base: Record<string, FakePayload>;
  constructor(workDir: string, extra: Record<string, FakePayload> = {}) {
    this.base = {
      ...fakeResponses(),
      prepare: { schema: "mcu-p2im/oracle-0.2", ok: true, target: "PLC", work_dir: workDir, elf_sha256: HASH },
      ...extra,
    };
  }
  async call<T>(argv: string[]): Promise<{ payload: T; command: string[]; duration_ms: number; stderr_tail: string }> {
    this.calls.push(argv);
    const key = argv[0] ?? "";
    if (key === "fuzz") {
      const segIdx = argv.indexOf("--segment");
      const seg = segIdx >= 0 ? argv[segIdx + 1]! : "s1";
      const inhIdx = argv.indexOf("--inherit-queue");
      const inh = inhIdx >= 0 ? argv[inhIdx + 1]! : null;
      const inc = argv.includes("--include-proposed");
      const segTemplate = (this.base.fuzz as { segment: Record<string, unknown> }).segment;
      return {
        payload: {
          schema: "mcu-p2im/oracle-0.2",
          ok: true,
          segment: {
            ...segTemplate,
            segment: seg,
            inherit_queue: inh,
            inherited_queue_files: inh ? 10 : 0,
            proposed_seeds: inc ? 1 : 0,
          },
        } as T,
        command: argv,
        duration_ms: 1,
        stderr_tail: "",
      };
    }
    const body = this.base[key];
    if (!body) throw new OracleError("ORACLE_FAILED", `dynamic fake oracle has no response for ${key}`);
    return { payload: body as T, command: argv, duration_ms: 1, stderr_tail: "" };
  }
}

async function createFauxBindingFactory(
  authRoot: string,
  responsesByRole: Partial<Record<Mcup2imRole, FauxResponseStep[]>>,
  seenRoles: Mcup2imRole[],
) {
  const faux = createFauxCore({
    provider: "faux-deepseek",
    api: "faux-api",
    models: [{ id: "faux-flash", name: "Faux Flash", reasoning: true, maxTokens: 32768 }],
  });
  const model = faux.getModel();
  const runtime = await ModelRuntime.create({
    authPath: join(authRoot, "auth.json"),
    modelsPath: null,
    allowModelNetwork: false,
    refreshOnCreate: false,
  });
  runtime.hasConfiguredAuth = () => true;
  runtime.checkAuth = async () => ({ type: "api_key" } as never);
  runtime.getAuth = async () => ({ auth: { apiKey: "mock-test-only" }, env: {} } as never);
  runtime.isUsingOAuth = () => false;

  return (role: Mcup2imRole) => {
    seenRoles.push(role);
    faux.setResponses(responsesByRole[role] ?? [fauxAssistantMessage("done")]);
    runtime.streamSimple = faux.streamSimple as never;
    return Promise.resolve({ runtime, model, thinkingLevel: "low" as const });
  };
}

test("real mode records thinking/stop_reason diagnostics and emits ANALYZE_TRUNCATED_ZERO_SEEDS warning (#10, #11)", async () => {
  const root = mkdtempSync(join(tmpdir(), "mcu-p2im-real-trunc-"));
  const workRoot = join(root, "work");
  const workDir = setupSlicedWorkDir(workRoot);
  const out = join(root, "run");
  const oracle = new DynamicFakeOracle(workDir);
  const seenRoles: Mcup2imRole[] = [];
  const progressEvents: string[] = [];
  const bindingFactory = await createFauxBindingFactory(join(root, "pi-auth"), {
    main: [
      fauxAssistantMessage("cut off in reasoning", { stopReason: "length" }),
      fauxAssistantMessage("cut off again", { stopReason: "length" }),
    ],
  }, seenRoles);

  const campaign = await Mcup2imCampaign.start({
    config: config({ work_root: workRoot, max_segments: 2 }),
    out,
    mode: "real",
    selection: { provider: "deepseek", model: "deepseek-v4-flash", thinking: "low" },
    budget: mcup2imBudget({ analyze_model_calls: 2 }),
    oracle: oracle as never,
    bindingFactory,
    onProgress: (_state, event) => progressEvents.push(event),
  });
  const state = await campaign.run();
  assert.equal(state.status, "completed");
  assert.deepEqual(seenRoles, ["main"], "replay_model_calls=0 must NOT open a replay LLM session (#11)");
  assert.equal(state.model_diagnostics.thinking, "low");
  assert.equal(state.model_diagnostics.analyze_length_truncations, 2);
  assert.equal(state.model_diagnostics.stop_reasons.length, 2);
  assert.ok(state.warnings.some(w => w.includes("ANALYZE_TRUNCATED_ZERO_SEEDS")));
  assert.ok(progressEvents.includes("warning:analyze_truncated_zero_seeds"));

  const score = JSON.parse(readFileSync(join(out, "score-owned.json"), "utf8"));
  assert.equal(score.model_diagnostics.analyze_length_truncations, 2);
  assert.ok(score.warnings.some((w: string) => w.includes("ANALYZE_TRUNCATED_ZERO_SEEDS")));
  const ledger = readFileSync(join(out, "ledger.jsonl"), "utf8");
  assert.match(ledger, /ANALYZE_TRUNCATED_ZERO_SEEDS/);
  assert.match(ledger, /host_deterministic/);
  assert.equal(state.layers.l4, 1);

  const fuzzCalls = oracle.calls.filter(c => c[0] === "fuzz");
  assert.equal(fuzzCalls.length, 2);
  assert.ok(fuzzCalls[1]!.includes("--inherit-queue"), "s2 should inherit s1 queue by default (#12)");
  assert.equal(fuzzCalls[1]![fuzzCalls[1]!.indexOf("--inherit-queue") + 1], "s1");
});

test("real mode opens replay session only when --replay-model-calls > 0 (#11) and honors inherit_queue_s2=false (#12)", async () => {
  const root = mkdtempSync(join(tmpdir(), "mcu-p2im-real-ablate-"));
  const workRoot = join(root, "work");
  const workDir = setupSlicedWorkDir(workRoot);
  const out = join(root, "run");
  const oracle = new DynamicFakeOracle(workDir, {
    "admit-seed": { schema: "mcu-p2im/oracle-0.2", ok: true, seed: { sha256: "e".repeat(64), bytes: 8, frame: "modbus_rtu", crc_checked: true } },
  });
  const seenRoles: Mcup2imRole[] = [];
  const bindingFactory = await createFauxBindingFactory(join(root, "pi-auth"), {
    main: [
      fauxAssistantMessage(fauxToolCall("seed_propose", { hex: "010300000001840a", frame: "modbus_rtu", note: "valid modbus read" })),
      fauxAssistantMessage("proposed one seed"),
    ],
    replay: [fauxAssistantMessage("replay verified")],
  }, seenRoles);

  const campaign = await Mcup2imCampaign.start({
    config: config({ work_root: workRoot, max_segments: 2, inherit_queue_s2: false }),
    out,
    mode: "real",
    budget: mcup2imBudget({ replay_model_calls: 1 }),
    oracle: oracle as never,
    bindingFactory,
  });
  const state = await campaign.run();
  assert.equal(state.status, "completed");
  assert.deepEqual(seenRoles, ["main", "replay"]);
  assert.equal(state.warnings.length, 0);
  const fuzzCalls = oracle.calls.filter(c => c[0] === "fuzz");
  assert.equal(fuzzCalls.length, 2);
  assert.ok(fuzzCalls[1]!.includes("--include-proposed"));
  assert.ok(!fuzzCalls[1]!.includes("--inherit-queue"), "cold-restart ablation disables s2 queue inheritance");
});

test("b0 mode runs single segment with 0 model calls, optional bbl-coverage, and emits bare vs SRAM-slice L5 candidates (#13)", async () => {
  const root = mkdtempSync(join(tmpdir(), "mcu-p2im-b0-"));
  const workRoot = join(root, "work");
  const workDir = setupSlicedWorkDir(workRoot);
  const out = join(root, "run");
  const oracle = new DynamicFakeOracle(workDir, {
    "bbl-coverage": {
      schema: "mcu-p2im/oracle-0.2",
      ok: true,
      coverage_path: join(workDir, "analysis", "bbl-coverage.json"),
      coverage: {
        schema: "mcu-p2im/bbl-coverage-0.1",
        total_execs_done: 1480,
        union: { unique_bbls: 120, unique_functions: 14 },
        segments: { s1: { unique_bbls: 120, new_bbls_over_prior: 120, cumulative_unique_bbls: 120 } },
      },
    },
  });

  const campaign = await Mcup2imCampaign.start({
    config: config({ work_root: workRoot, max_segments: 2, collect_coverage: true }),
    out,
    mode: "b0",
    oracle: oracle as never,
  });
  const state = await campaign.run();
  assert.equal(state.status, "completed");
  assert.equal(state.mode, "b0");
  assert.equal(campaign.governance.account.requests.length, 0);
  const fuzzCalls = oracle.calls.filter(c => c[0] === "fuzz");
  assert.equal(fuzzCalls.length, 1, "b0 must run only a single continuous segment");
  assert.ok(oracle.calls.some(c => c[0] === "bbl-coverage"));

  const score = JSON.parse(readFileSync(join(out, "score-owned.json"), "utf8"));
  assert.equal(score.mode, "b0");
  assert.equal(score.work_dir, workDir);
  assert.equal(score.coverage.union.unique_bbls, 120);
  assert.equal(typeof score.stage_wall_ms.discover_seg1, "number");

  const withSlice = JSON.parse(readFileSync(join(out, "l5-candidates.json"), "utf8"));
  const bare = JSON.parse(readFileSync(join(out, "l5-candidates-bare.json"), "utf8"));
  assert.equal(withSlice.attribution_mode, "with_shared_sram_slice");
  assert.ok(withSlice.candidates[0].upstream_functions.includes("Modbus::process_FC1"));
  assert.equal(bare.attribution_mode, "bare_without_sram_slice");
  assert.deepEqual(bare.candidates[0].upstream_functions, []);
  assert.equal(bare.candidates[0].via_shared_global, null);
});

test("judgeCrashes interleaves s2 ahead of s1, deduplicates L2>=L3>=L4 fingerprints, and deduplicates l5-candidates", async () => {
  const root = mkdtempSync(join(tmpdir(), "mcu-p2im-dedup-"));
  const workRoot = join(root, "work");
  const workDir = setupSlicedWorkDir(workRoot);
  const out = join(root, "run");

  const s1Crashes = Array.from({ length: 10 }, (_, idx) => ({
    id: `s1-crash-${idx}`,
    sha256: `${idx}`.padStart(64, "1"),
    bytes: 64,
    ret_v: "0xff",
    segment_dir: "outputs-s1",
  }));
  const s2Crash = {
    id: "s2-crash-new",
    sha256: "2".repeat(64),
    bytes: 48,
    ret_v: "0x72",
    segment_dir: "outputs-s2",
  };
  const interleaved = interleaveCrashRows([...s1Crashes, s2Crash]);
  assert.equal(interleaved[0]!.id, "s2-crash-new", "s2 crash must not be starved behind 10 s1 crashes");

  let contrastCalls = 0;
  const oracle = {
    calls: [] as string[][],
    async call<T>(argv: string[]) {
      this.calls.push(argv);
      const cmd = argv[0]!;
      if (cmd === "prepare") {
        return { payload: { schema: "mcu-p2im/oracle-0.2", ok: true, target: "PLC", work_dir: workDir, elf_sha256: HASH } as T, command: argv, duration_ms: 1, stderr_tail: "" };
      }
      if (cmd === "status") {
        return { payload: { schema: "mcu-p2im/oracle-0.2", ok: true, status: { target: "PLC", rounds: ["0"], segments: 0 } } as T, command: argv, duration_ms: 1, stderr_tail: "" };
      }
      if (cmd === "fuzz") {
        const seg = argv[argv.indexOf("--segment") + 1]!;
        return {
          payload: {
            schema: "mcu-p2im/oracle-0.2", ok: true,
            segment: { segment: seg, requested_seconds: 30, duration_s: 30, exit_code: 124, timed_out: true, execs_done: 500, paths_total: 10, unique_crashes: 2, unique_hangs: 0, queue_files: 10, crash_files: seg === "s1" ? 10 : 1, bitmap_cvg: "0.02%" },
          } as T, command: argv, duration_ms: 1, stderr_tail: "",
        };
      }
      if (cmd === "extract-sources") {
        return { payload: { schema: "mcu-p2im/oracle-0.2", ok: true, source_count: 1, sources_path: join(workDir, "analysis", "sources.json") } as T, command: argv, duration_ms: 1, stderr_tail: "" };
      }
      if (cmd === "slice-paths") {
        return { payload: { schema: "mcu-p2im/oracle-0.2", ok: true, paths_path: join(workDir, "analysis", "paths.json"), counts: { paths: 1 } } as T, command: argv, duration_ms: 1, stderr_tail: "" };
      }
      if (cmd === "crashes") {
        return { payload: { schema: "mcu-p2im/oracle-0.2", ok: true, crashes: { raw_files: 11, unique: 11, crashes: [...s1Crashes, s2Crash] } } as T, command: argv, duration_ms: 1, stderr_tail: "" };
      }
      if (cmd === "replay") {
        const inputId = argv[argv.indexOf("--input") + 1]!;
        const isS2 = inputId === "s2-crash-new";
        const row = isS2
          ? { run_id: "r-s2", input_sha256: s2Crash.sha256, input_bytes: 48, round: "0.s2", outcome: "crash", exit_code: 0x72, fault: { kind: "exec_peri", address: "0x20001000" }, last_bbl: { start: "0x8000950", end: "0x8000958", function: "Modbus::process_FC1" } }
          : { run_id: "r-s1", input_sha256: "1".repeat(64), input_bytes: 64, round: "0", outcome: "crash", exit_code: 255, fault: { kind: "read", address: "0xfffc0004" }, last_bbl: { start: "0x8003f30", end: "0x8003f3e", function: "HAL_UART_RxCpltCallback" } };
        return { payload: { schema: "mcu-p2im/oracle-0.2", ok: true, replay: row, repeated: 3, deterministic: true, outcomes: [row, row, row] } as T, command: argv, duration_ms: 1, stderr_tail: "" };
      }
      if (cmd === "contrast") {
        contrastCalls += 1;
        return { payload: { schema: "mcu-p2im/oracle-0.2", ok: true, contrast: { contrast_confirmed: true, replays_used: 4 } } as T, command: argv, duration_ms: 1, stderr_tail: "" };
      }
      throw new Error(`unexpected cmd ${cmd}`);
    },
  };

  const campaign = await Mcup2imCampaign.start({
    config: config({ work_root: workRoot, max_segments: 2, trial_seed: 1707 }),
    out,
    mode: "offline",
    oracle: oracle as never,
  });
  const state = await campaign.run();
  assert.equal(state.status, "completed");
  assert.deepEqual(state.layers, { l1: 11, l2: 2, l3: 2, l4: 2 }, "L2>=L3>=L4 must be deduplicated by crash fingerprint");
  assert.equal(state.layers_files?.l3, 11);
  assert.equal(contrastCalls, 2, "contrast must run once per confirmed crash fingerprint rather than 11 times");
  const prepareCall = oracle.calls.find(c => c[0] === "prepare")!;
  assert.ok(prepareCall.includes("--trial-seed"));
  assert.equal(prepareCall[prepareCall.indexOf("--trial-seed") + 1], "1707");

  const candDoc = JSON.parse(readFileSync(join(out, "l5-candidates.json"), "utf8"));
  assert.equal(candDoc.candidates.length, 2, "l5-candidates must deduplicate identical crash sites");
  const fc1Cand = candDoc.candidates.find((c: { function: string }) => c.function === "Modbus::process_FC1");
  assert.ok(fc1Cand, "s2 crash candidate must be preserved");
  assert.deepEqual(fc1Cand.bbl_range, ["0x8000950", "0x8000958"]);
});

test("fuzz_budget_s enforces equal wall-clock cap, marks skipped seg2 as partial, and parentOut accumulates cost", async () => {
  const root = mkdtempSync(join(tmpdir(), "mcu-p2im-budget-parent-"));
  const workRoot = join(root, "work");
  const workDir = setupSlicedWorkDir(workRoot);
  const parentDir = join(root, "parent-run");
  const oracle1 = new DynamicFakeOracle(workDir);
  const seenRoles: Mcup2imRole[] = [];
  const bindingFactory = await createFauxBindingFactory(join(root, "pi-auth"), {
    main: [fauxAssistantMessage("done")],
  }, seenRoles);

  // Parent run with fuzz_budget_s = 10s (< 15s minimum for seg2) -> seg2 skipped -> status === "partial"
  const parentCampaign = await Mcup2imCampaign.start({
    config: config({ work_root: workRoot, max_segments: 2, segment_seconds: 10, fuzz_budget_s: 10, fuzz_hard_cap_s: 60 }),
    out: parentDir,
    mode: "real",
    budget: mcup2imBudget({ analyze_model_calls: 1 }),
    oracle: oracle1 as never,
    bindingFactory,
  });
  const parentState = await parentCampaign.run();
  assert.equal(parentState.status, "partial", "skipping seg2 due to exhausted fuzz_budget_s must mark run partial");
  assert.ok(parentState.warnings.some(w => w.includes("SEG2_SKIPPED_WALL_BUDGET")));

  // Child retry run linked via parentOut accumulates prior model requests & tokens, and isolates bbl-coverage time
  const childDir = join(root, "child-run");
  const oracle2 = new DynamicFakeOracle(workDir, {
    "bbl-coverage": {
      schema: "mcu-p2im/oracle-0.2",
      ok: true,
      coverage: { union: { unique_bbls: 88, unique_functions: 9 }, segments: {} },
    },
  });
  const origCall = oracle2.call.bind(oracle2);
  oracle2.call = async <T>(argv: string[]) => {
    if (argv[0] === "bbl-coverage") {
      await new Promise(r => setTimeout(r, 40));
    }
    return origCall<T>(argv);
  };
  const childCampaign = await Mcup2imCampaign.start({
    config: config({ work_root: workRoot, max_segments: 2, segment_seconds: 20, fuzz_budget_s: 60, fuzz_hard_cap_s: 60, collect_coverage: true }),
    out: childDir,
    mode: "real",
    parentOut: parentDir,
    budget: mcup2imBudget({ analyze_model_calls: 1 }),
    oracle: oracle2 as never,
    bindingFactory,
  });
  const childState = await childCampaign.run();
  assert.equal(childState.status, "completed");
  const childScore = JSON.parse(readFileSync(join(childDir, "score-owned.json"), "utf8"));
  assert.ok(childScore.cumulative_cost.total_model_requests > childScore.model_requests, "cumulative_cost must include parent requests");
  assert.ok(childScore.wall_clock.eval_coverage_wall_ms >= 30, "post-hoc coverage duration is tracked separately");
  assert.ok(childScore.wall_clock.end_to_end_wall_ms < childScore.wall_clock.eval_coverage_wall_ms + 35,
    "end_to_end_wall_ms must be frozen before bbl-coverage runs");
});
