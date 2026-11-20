import { enumeration, integer, object, requireThat, text } from "../contracts.js";

/**
 * One mcu-p2im target. This is the configuration that is frozen for a run: the ELF hash is
 * checked again by the oracle before any execution, so a patched or rebuilt image cannot be
 * substituted between runs.
 */
export interface Mcup2imConfig {
  schema_version: 1;
  target: string;
  elf: string;
  elf_sha256: string;
  board: string;
  mcu: string;
  work_root: string;
  oracle: string;
  runner: string;
  python: string;
  wsl_distro: string | null;
  fuzz_hard_cap_s: number;
  segment_seconds: number;
  max_segments: number;
  /** Optional equal end-to-end discovery+guidance wall-clock budget (s) across b0/offline/real. */
  fuzz_budget_s: number | null;
  /** Optional equal target-execution cap (execs_done) across discovery segments. */
  max_execs: number | null;
  /** Optional paired trial seed identifier passed to oracle prepare for multi-trial experiments. */
  trial_seed: number | null;
  replay_repeat: number;
  contrast_budget: number;
  max_contrast_replays: number;
  /** Optional Thumb PC at which QEMU calls startForkserver once. Null leaves svc 0x3f behavior unchanged. */
  auto_forkserver_pc: string | null;
  /** When true, triage may attach gdb for one SRAM watch. A missing debugger is recorded and does not fail the run. */
  gdb_watch: boolean;
  /** When true, discover_seg2 inherits outputs-s1/queue/* into inputs-s2/ alongside admitted seeds. */
  inherit_queue_s2: boolean;
  /** When true, score stage runs p2im_oracle.py bbl-coverage to record cross-segment unique BBL union coverage. */
  collect_coverage: boolean;
}

export const MCUP2IM_DEFAULTS = {
  fuzz_hard_cap_s: 300,
  segment_seconds: 120,
  max_segments: 2,
  fuzz_budget_s: null,
  max_execs: null,
  trial_seed: null,
  replay_repeat: 3,
  contrast_budget: 24,
  max_contrast_replays: 60,
  inherit_queue_s2: true,
  collect_coverage: false,
} as const;

const CONFIG_KEYS = ["schema_version", "target", "elf", "elf_sha256", "board", "mcu", "work_root",
  "oracle", "runner", "python", "wsl_distro", "fuzz_hard_cap_s", "segment_seconds", "max_segments",
  "fuzz_budget_s", "max_execs", "trial_seed",
  "replay_repeat", "contrast_budget", "max_contrast_replays", "auto_forkserver_pc", "gdb_watch",
  "inherit_queue_s2", "collect_coverage"];
const REQUIRED_KEYS = ["schema_version", "target", "elf", "elf_sha256", "board", "mcu", "work_root", "oracle"];

export function parseMcup2imConfig(value: unknown): Mcup2imConfig {
  const raw = object(value, CONFIG_KEYS, REQUIRED_KEYS);
  requireThat(raw.schema_version === 1, "INVALID_CONFIG", "Expected mcu-p2im schema version 1");
  const config: Mcup2imConfig = {
    schema_version: 1,
    target: text(raw.target, 64),
    elf: text(raw.elf, 1024),
    elf_sha256: text(raw.elf_sha256, 64),
    board: text(raw.board, 64),
    mcu: text(raw.mcu, 64),
    work_root: text(raw.work_root, 512),
    oracle: text(raw.oracle, 1024),
    runner: raw.runner === undefined || raw.runner === "" ? "" : text(raw.runner, 1024),
    python: raw.python === undefined ? "python3" : text(raw.python, 256),
    wsl_distro: raw.wsl_distro === undefined || raw.wsl_distro === null ? null : text(raw.wsl_distro, 64),
    fuzz_hard_cap_s: raw.fuzz_hard_cap_s === undefined ? MCUP2IM_DEFAULTS.fuzz_hard_cap_s
      : integer(raw.fuzz_hard_cap_s, 1, 14_400),
    segment_seconds: raw.segment_seconds === undefined ? MCUP2IM_DEFAULTS.segment_seconds
      : integer(raw.segment_seconds, 1, 14_400),
    max_segments: raw.max_segments === undefined ? MCUP2IM_DEFAULTS.max_segments
      : integer(raw.max_segments, 0, 64),
    fuzz_budget_s: raw.fuzz_budget_s === undefined || raw.fuzz_budget_s === null ? null
      : integer(raw.fuzz_budget_s, 1, 14_400),
    max_execs: raw.max_execs === undefined || raw.max_execs === null ? null
      : integer(raw.max_execs, 1, 100_000_000),
    trial_seed: raw.trial_seed === undefined || raw.trial_seed === null ? null
      : integer(raw.trial_seed, 0, 2_147_483_647),
    replay_repeat: raw.replay_repeat === undefined ? MCUP2IM_DEFAULTS.replay_repeat
      : integer(raw.replay_repeat, 1, 9),
    contrast_budget: raw.contrast_budget === undefined ? MCUP2IM_DEFAULTS.contrast_budget
      : integer(raw.contrast_budget, 0, 512),
    max_contrast_replays: raw.max_contrast_replays === undefined ? MCUP2IM_DEFAULTS.max_contrast_replays
      : integer(raw.max_contrast_replays, 1, 4096),
    auto_forkserver_pc: raw.auto_forkserver_pc === undefined || raw.auto_forkserver_pc === null || raw.auto_forkserver_pc === ""
      ? null : text(raw.auto_forkserver_pc, 16),
    gdb_watch: raw.gdb_watch === undefined ? false : raw.gdb_watch === true,
    inherit_queue_s2: raw.inherit_queue_s2 === undefined ? MCUP2IM_DEFAULTS.inherit_queue_s2 : raw.inherit_queue_s2 === true,
    collect_coverage: raw.collect_coverage === undefined ? MCUP2IM_DEFAULTS.collect_coverage : raw.collect_coverage === true,
  };
  requireThat(/^[0-9a-f]{64}$/.test(config.elf_sha256), "INVALID_CONFIG", "elf_sha256 must be 64 lowercase hex characters");
  requireThat(config.segment_seconds <= config.fuzz_hard_cap_s, "INVALID_CONFIG",
    "segment_seconds must not exceed fuzz_hard_cap_s");
  requireThat(config.fuzz_budget_s === null || config.fuzz_budget_s <= config.fuzz_hard_cap_s, "INVALID_CONFIG",
    "fuzz_budget_s must not exceed fuzz_hard_cap_s");
  requireThat(config.auto_forkserver_pc === null || /^0x[0-9a-fA-F]{4,8}$/.test(config.auto_forkserver_pc),
    "INVALID_CONFIG", "auto_forkserver_pc must be a 0x-prefixed address");
  requireThat(raw.gdb_watch === undefined || raw.gdb_watch === true || raw.gdb_watch === false,
    "INVALID_CONFIG", "gdb_watch must be a boolean");
  requireThat(raw.inherit_queue_s2 === undefined || typeof raw.inherit_queue_s2 === "boolean",
    "INVALID_CONFIG", "inherit_queue_s2 must be a boolean");
  requireThat(raw.collect_coverage === undefined || typeof raw.collect_coverage === "boolean",
    "INVALID_CONFIG", "collect_coverage must be a boolean");
  return config;
}

export type Mcup2imRole = "main" | "discover" | "replay";
export type Mcup2imStage = "prepare" | "model" | "discover_seg1" | "slice" | "analyze_and_propose" | "discover_seg2" | "triage_and_verify" | "score";
export type Mcup2imMode = "real" | "offline" | "b0";

export interface Mcup2imBudget {
  max_model_requests: number;
  max_tokens: number;
  max_output_tokens: number;
  max_target_execs: number;
  tool_calls: number;
  wall_ms: number;
  discover_model_calls: number;
  analyze_model_calls: number;
  replay_model_calls: number;
}

export const MCUP2IM_BUDGET: Mcup2imBudget = {
  max_model_requests: 64, max_tokens: 160_000, max_output_tokens: 16_384, max_target_execs: 2_000_000,
  tool_calls: 200, wall_ms: 3_600_000, discover_model_calls: 2, analyze_model_calls: 6, replay_model_calls: 0,
};

export function mcup2imBudget(overrides: Partial<Mcup2imBudget> = {}): Mcup2imBudget {
  object(overrides, Object.keys(MCUP2IM_BUDGET), []);
  const budget = { ...MCUP2IM_BUDGET, ...overrides };
  for (const key of ["max_model_requests", "max_tokens", "max_output_tokens", "max_target_execs",
    "tool_calls", "wall_ms", "discover_model_calls", "analyze_model_calls", "replay_model_calls"] as const) {
    integer(budget[key], 0, 100_000_000);
  }
  return budget;
}

export interface Mcup2imSegmentSummary {
  segment: string; requested_seconds: number; duration_s: number; exit_code: number | null;
  timed_out: boolean; execs_done: number; paths_total: number; unique_crashes: number;
  unique_hangs: number; queue_files: number; crash_files: number; bitmap_cvg: string | null;
  inherit_queue: string | null; inherited_queue_files: number; proposed_seeds: number;
  max_execs?: number | null; exec_cap_reached?: boolean;
}

export interface Mcup2imModelDiagnostics {
  provider: string | null;
  model: string | null;
  thinking: string | null;
  max_output_tokens: number;
  stop_reasons: Record<string, number>;
  analyze_length_truncations: number;
  warnings: string[];
}

export interface Mcup2imCrashRow {
  id: string; sha256: string; bytes: number; ret_v: string | null; segment_dir: string;
}

export interface Mcup2imReplayRow {
  run_id: string; input_sha256: string; input_bytes: number; round: string;
  outcome: "ok" | "crash" | "hang" | "error"; exit_code: number | null;
  fault: { kind: string; address: string } | null;
  last_bbl: { start: string; end: string; function: string } | null;
}

export interface Mcup2imState {
  schema_version: 1;
  run_id: string;
  attempt_id: string;
  target: string;
  elf_sha256: string;
  mode: Mcup2imMode;
  trial_seed?: number | null;
  work_root: string;
  work_dir: string;
  status: "running" | "completed" | "partial" | "failed";
  stage: Mcup2imStage;
  error?: string;
  totals: { model_calls: number; tokens: number; tool_calls: number; target_execs: number; wall_ms: number };
  stage_wall_ms: Partial<Record<Mcup2imStage, number>>;
  rounds: string[];
  segments: Mcup2imSegmentSummary[];
  crashes: { raw_files: number; unique: number; replayed: number; reproduced: number };
  layers: { l1: number; l2: number; l3: number; l4: number };
  layers_files?: { l1: number; l2: number; l3: number; l4: number };
  prior_attempts?: Record<string, unknown> | null;
  model_diagnostics: Mcup2imModelDiagnostics;
  warnings: string[];
  coverage?: Record<string, unknown> | null;
  artifacts: Record<string, string>;
  instruction_authority: "none";
}

export function renderEnvelopeStatus(value: string): Mcup2imStage {
  return enumeration(value, ["prepare", "model", "discover_seg1", "slice", "analyze_and_propose", "discover_seg2", "triage_and_verify", "score"]) as Mcup2imStage;
}
