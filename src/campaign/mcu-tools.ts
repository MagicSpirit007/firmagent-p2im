import { Type } from "typebox";
import { defineTool, type ToolDefinition } from "@earendil-works/pi-coding-agent";
import { requireThat } from "../contracts.js";
import { envelope, refusal, TOOL_VERSION, type ToolEnvelope } from "./tools.js";
import type { Mcup2imRole } from "./mcu-types.js";

/**
 * mcu-p2im tool surface. Same envelope contract as the Linux campaign: the model receives
 * observations and artifact ids, never a shell, a path outside the run, or instruction authority.
 * Every payload is scanned for blind-test truth tokens before it leaves the host.
 */

const LEAK_PATTERN = /(CVE-\d{4}-\d+|CWE-\d+|Table\s*5|Table5)/i;

export function assertNoLeak(text: string, where: string): void {
  const match = LEAK_PATTERN.exec(text);
  requireThat(!match, "BLIND_TEST_LEAK", `${where} contains a truth-set token: ${match?.[0] ?? ""}`);
}

export interface Mcup2imToolPorts {
  requestId(tool: string): string;
  mcuStatus(): Promise<ToolEnvelope>;
  fuzzStatus(): Promise<ToolEnvelope>;
  fuzzRun(seconds: number): Promise<ToolEnvelope>;
  crashList(): Promise<ToolEnvelope>;
  crashReplay(crashId: string): Promise<ToolEnvelope>;
  crashContrast(crashId: string, op: "trim" | "shorten", shortenTo: number | null): Promise<ToolEnvelope>;
  slicePaths(): Promise<ToolEnvelope>;
  readArtifactChunk(sha256: string, offset: number, limit: number): Promise<ToolEnvelope>;
  seedPropose(hex: string, frame: "raw" | "modbus_rtu", note: string): Promise<ToolEnvelope>;
  hypothesisNote(sink: string, sharedGlobal: string | null, upstream: string | null, note: string): Promise<ToolEnvelope>;
}

export interface Mcup2imToolOptions {
  /** Hard cap for one fuzz_run, in seconds. A request above it is refused by the host. */
  fuzzHardCapS: number;
  discoverEnabled?: boolean;
}

function present(value: ToolEnvelope) {
  assertNoLeak(JSON.stringify(value), value.tool);
  return { content: [{ type: "text" as const, text: JSON.stringify(value) }], details: value };
}

function tool(name: string, description: string, parameters: ReturnType<typeof Type.Object>,
  run: (value: any) => Promise<ToolEnvelope>): ToolDefinition {
  return defineTool({
    name, label: name, description, parameters,
    async execute(_id, value) { return present(await run(value)); },
  });
}

const crashId = Type.String({ minLength: 1, maxLength: 120 });

export function mcup2imTools(role: Mcup2imRole, ports: Mcup2imToolPorts, options: Mcup2imToolOptions): ToolDefinition[] {
  const status = tool("mcu_status",
    "Report the prepared ELF hash, board/MCU, model rounds, segment totals and crash counts. Read-only.",
    Type.Object({}, { additionalProperties: false }), () => ports.mcuStatus());
  const fuzzStatus = tool("fuzz_status",
    "Report the bounded mutation segments already on disk: execs, paths, crash files and seconds. Read-only.",
    Type.Object({}, { additionalProperties: false }), () => ports.fuzzStatus());
  const fuzzRun = tool("fuzz_run",
    `Run one bounded P2IM mutation segment (round 0 model plus AFL) and persist its stats and crashes. Seconds must be 1..${options.fuzzHardCapS}.`,
    Type.Object({ seconds: Type.Integer({ minimum: 1, maximum: options.fuzzHardCapS }) }, { additionalProperties: false }),
    value => ports.fuzzRun(Number(value.seconds)));
  const crashList = tool("crash_list",
    "List deduplicated crash ids with input hash, size and the AFL return value recorded in the file name. Read-only.",
    Type.Object({}, { additionalProperties: false }), () => ports.crashList());
  const replay = tool("crash_replay",
    "Replay one crash input against the same unpatched image and round, three times, and report outcome, fault address and enclosing basic block.",
    Type.Object({ crash_id: crashId }, { additionalProperties: false }),
    value => ports.crashReplay(String(value.crash_id)));
  const contrast = tool("crash_contrast",
    "Minimise one reproduced crash by byte deletion (or truncation) under a replay budget, then delete one decisive byte and confirm the fault disappears. The original input is never modified.",
    Type.Object({ crash_id: crashId, op: Type.Union([Type.Literal("trim"), Type.Literal("shorten")]),
      shorten_to: Type.Optional(Type.Integer({ minimum: 1, maximum: 4096 })) }, { additionalProperties: false }),
    value => ports.crashContrast(String(value.crash_id), value.op as "trim" | "shorten",
      typeof value.shorten_to === "number" ? Number(value.shorten_to) : null));
  const paths = tool("slice_paths",
    "Read the host-built Csource -> sink candidate paths with their reachable seed counts. Read-only artifact summary.",
    Type.Object({}, { additionalProperties: false }), () => ports.slicePaths());
  const readArtifact = tool("read_artifact_chunk",
    "Read a bounded UTF-8 slice (offset >= 0, limit 1..4096) from a host-verified analysis artifact by sha256. Never accepts a path.",
    Type.Object({ artifact_sha256: Type.String({ minLength: 64, maxLength: 64, pattern: "^[0-9a-f]{64}$" }),
      offset: Type.Optional(Type.Integer({ minimum: 0 })),
      limit: Type.Optional(Type.Integer({ minimum: 1, maximum: 4096 })) }, { additionalProperties: false }),
    value => ports.readArtifactChunk(String(value.artifact_sha256), Number(value.offset ?? 0), Number(value.limit ?? 2048)));
  const seedPropose = tool("seed_propose",
    "Propose one protocol seed as even-length hex, at most 256 bytes. frame is raw or modbus_rtu. The host checks length, truth-set tokens and, for modbus_rtu, CRC16. Admitted bytes go to an independent directory, not the original corpus.",
    Type.Object({
      hex: Type.String({ minLength: 2, maxLength: 512, pattern: "^[0-9a-fA-F]+$" }),
      frame: Type.Union([Type.Literal("raw"), Type.Literal("modbus_rtu")]),
      note: Type.String({ minLength: 1, maxLength: 400 }),
    }, { additionalProperties: false }),
    value => ports.seedPropose(String(value.hex), value.frame as "raw" | "modbus_rtu", String(value.note)));
  const hypothesis = tool("hypothesis_note",
    "Record one sink or bounds hypothesis grounded in a shared SRAM object. This is not a verdict.",
    Type.Object({
      sink: Type.String({ minLength: 1, maxLength: 120 }),
      shared_global: Type.Optional(Type.String({ minLength: 1, maxLength: 80 })),
      upstream: Type.Optional(Type.String({ minLength: 1, maxLength: 120 })),
      note: Type.String({ minLength: 1, maxLength: 400 }),
    }, { additionalProperties: false }),
    value => ports.hypothesisNote(String(value.sink),
      typeof value.shared_global === "string" ? value.shared_global : null,
      typeof value.upstream === "string" ? value.upstream : null,
      String(value.note)));

  if (role === "main") return [status, crashList, paths, readArtifact, seedPropose, hypothesis];
  if (role === "discover") return options.discoverEnabled === false ? [status, fuzzStatus] : [status, fuzzStatus, fuzzRun, crashList];
  return [status, crashList, replay, contrast];
}

export const MCUP2IM_TOOL_VERSION = TOOL_VERSION;

export function refused(toolName: string, requestId: string, code: string, detail?: string): ToolEnvelope {
  return refusal(toolName, requestId, code, detail);
}

export function okEnvelope(toolName: string, requestId: string, patch: Partial<ToolEnvelope> = {}): ToolEnvelope {
  return envelope(toolName, requestId, patch);
}
