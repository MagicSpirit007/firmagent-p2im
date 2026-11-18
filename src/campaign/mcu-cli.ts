import { readFile } from "node:fs/promises";
import { resolve } from "node:path";
import { enumeration, requireThat, safeError } from "../contracts.js";
import type { PiSelection } from "../pi-model-runtime.js";
import { Mcup2imCampaign } from "./mcu-runtime.js";
import { parseMcup2imConfig, type Mcup2imBudget } from "./mcu-types.js";

function usage(): string {
  return [
    "mcu-p2im --config FILE --out DIR [--mode real|offline] [--pi-agent-dir DIR] [--provider NAME --model ID] [--thinking LEVEL]",
    "Budgets: --model-calls N --tool-calls N --wall-ms N --max-output-tokens N --max-total-tokens N --analyze-model-calls N --replay-model-calls N",
    "The configuration freezes target, ELF SHA256, board/MCU, work root and segment caps; the host refuses a hash mismatch.",
  ].join("\n");
}

const VALUE_OPTIONS = new Set(["--config", "--out", "--mode", "--pi-agent-dir", "--provider", "--model", "--thinking",
  "--model-calls", "--tool-calls", "--wall-ms", "--max-output-tokens", "--max-total-tokens",
  "--analyze-model-calls", "--replay-model-calls"]);

function parse(argv: string[]): Map<string, string> {
  requireThat(argv.length % 2 === 0, "INVALID_ARGUMENT", "Options are --name value pairs");
  const args = new Map<string, string>();
  for (let index = 0; index < argv.length; index += 2) {
    const key = argv[index]!;
    requireThat(VALUE_OPTIONS.has(key), "INVALID_ARGUMENT", `Unknown option ${key}`);
    requireThat(!args.has(key), "INVALID_ARGUMENT", `Duplicate option ${key}`);
    args.set(key, argv[index + 1]!);
  }
  return args;
}

function integer(args: Map<string, string>, key: string): number | undefined {
  const value = args.get(key);
  if (value === undefined) return undefined;
  requireThat(/^[0-9]+$/.test(value), "INVALID_ARGUMENT", `${key} must be a non-negative integer`);
  return Number(value);
}

export async function mcup2imCommand(argv: string[]): Promise<void> {
  if (argv.length === 0 || argv[0] === "--help") { console.log(usage()); return; }
  const args = parse(argv);
  requireThat(args.has("--config") && args.has("--out"), "INVALID_ARGUMENT", "--config and --out are required");
  const config = parseMcup2imConfig(JSON.parse(await readFile(resolve(args.get("--config")!), "utf8")));
  const mode = enumeration(args.get("--mode") ?? "offline", ["real", "offline"] as const);
  const selection: PiSelection = {
    agentDir: args.has("--pi-agent-dir") ? resolve(args.get("--pi-agent-dir")!) : undefined,
    provider: args.get("--provider"), model: args.get("--model"),
    thinking: args.has("--thinking") ? enumeration(args.get("--thinking"), ["off", "minimal", "low", "medium", "high", "xhigh", "max"] as const) : undefined,
  };
  const budget: Partial<Mcup2imBudget> = {};
  const modelCalls = integer(args, "--model-calls");
  if (modelCalls !== undefined) budget.max_model_requests = modelCalls;
  const toolCalls = integer(args, "--tool-calls");
  if (toolCalls !== undefined) budget.tool_calls = toolCalls;
  const wall = integer(args, "--wall-ms");
  if (wall !== undefined) budget.wall_ms = wall;
  const outputTokens = integer(args, "--max-output-tokens");
  if (outputTokens !== undefined) budget.max_output_tokens = outputTokens;
  const totalTokens = integer(args, "--max-total-tokens");
  if (totalTokens !== undefined) budget.max_tokens = totalTokens;
  const analyzeCalls = integer(args, "--analyze-model-calls");
  if (analyzeCalls !== undefined) budget.analyze_model_calls = analyzeCalls;
  const replayCalls = integer(args, "--replay-model-calls");
  if (replayCalls !== undefined) budget.replay_model_calls = replayCalls;

  const campaign = await Mcup2imCampaign.start({
    config, out: resolve(args.get("--out")!), mode, selection, budget,
    onProgress: (state, event) => { process.stderr.write(`[mcu-p2im] ${event} stage=${state.stage} status=${state.status}\n`); },
  });
  try {
    const state = await campaign.run();
    console.log(JSON.stringify({ schema: "mcu-p2im/run-0.2", state }, null, 2));
    if (state.status !== "completed") process.exitCode = 2;
  } catch (error) {
    const info = safeError(error);
    process.stderr.write(`[mcu-p2im] failed ${info.code}: ${info.message}\n`);
    process.exitCode = 1;
    throw error;
  }
}
