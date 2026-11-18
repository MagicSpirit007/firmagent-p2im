import { resolve } from "node:path";
import { enumeration, requireThat, safeError } from "./contracts.js";
import type { PiSelection } from "./pi-model-runtime.js";

function usage(): string {
  return [
    "firmagent-p2im 0.2.0",
    "",
    "Commands:",
    "  mcu-p2im --config FILE --out DIR [--mode real|offline] [--pi-agent-dir DIR] [--provider NAME --model ID] [--thinking LEVEL]",
    "  doctor [--pi-agent-dir DIR] [--provider NAME --model ID] [--thinking LEVEL]",
    "",
    "Budgets (mcu-p2im):",
    "  --model-calls N --tool-calls N --wall-ms N --max-output-tokens N --max-total-tokens N --analyze-model-calls N --replay-model-calls N",
  ].join("\n");
}

function parseDoctorArgs(argv: string[]): PiSelection {
  requireThat(argv.length % 2 === 0, "INVALID_ARGUMENT", "Unknown option or missing option value");
  const allowed = new Set(["--pi-agent-dir", "--provider", "--model", "--thinking"]);
  const args = new Map<string, string>();
  for (let index = 0; index < argv.length; index += 2) {
    const key = argv[index]!;
    requireThat(allowed.has(key) && !args.has(key), "INVALID_ARGUMENT", `Unknown or duplicate option ${key}`);
    args.set(key, argv[index + 1]!);
  }
  return {
    agentDir: args.has("--pi-agent-dir") ? resolve(args.get("--pi-agent-dir")!) : undefined,
    provider: args.get("--provider"),
    model: args.get("--model"),
    thinking: args.has("--thinking")
      ? enumeration(args.get("--thinking"), ["off", "minimal", "low", "medium", "high", "xhigh", "max"] as const)
      : undefined,
  };
}

async function main(): Promise<void> {
  const [command, ...rest] = process.argv.slice(2);
  if (!command || command === "--help" || command === "-h") {
    console.log(usage());
    return;
  }
  if (command === "mcu-p2im") {
    await (await import("./campaign/mcu-cli.js")).mcup2imCommand(rest);
    return;
  }
  if (command === "doctor") {
    const selection = parseDoctorArgs(rest);
    const { selectPiModel } = await import("./pi-model-runtime.js");
    console.log(JSON.stringify({
      node: process.version,
      platform: process.platform,
      sdk: "0.85.1",
      selection: selectPiModel(selection, process.cwd()),
      model_request: "not_run",
      credentials: "not_inspected",
    }));
    return;
  }
  requireThat(false, "INVALID_ARGUMENT", `Unknown command ${command}`);
}

main().catch((error) => {
  console.error(JSON.stringify(safeError(error)));
  process.exitCode = 1;
});
