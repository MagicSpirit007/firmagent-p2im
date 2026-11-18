import { Type } from "typebox";
import { defineTool, type ToolDefinition } from "@earendil-works/pi-coding-agent";

/**
 * Campaign tool envelope contract.
 *
 * Every tool returns the envelope from docs/TOOL_CONTRACTS.md. Firmware bytes, mappings, disassembly
 * and CVE descriptions all carry instruction_authority "none"; free text appears only in
 * warnings/errors. Tools are host-owned: the model never runs a shell or the Python helper.
 */

export type CampaignRole = "main" | "discover" | "replay" | "cve";
export const TOOL_VERSION = "0.1.0";

export interface ToolEnvelope {
  status: "ok" | "rejected";
  tool: string;
  tool_version: string;
  request_id: string;
  observations: { kind: string; value: unknown; evidence_refs: string[] }[];
  metrics: Record<string, number>;
  artifacts: { id: string; media_type: string; size: number; origin: string; instruction_authority: "none" }[];
  warnings: string[];
  errors: { code: string; detail?: string }[];
  provenance: Record<string, unknown>;
}

export function envelope(tool: string, request_id: string, patch: Partial<ToolEnvelope> = {}): ToolEnvelope {
  return { status: "ok", tool, tool_version: TOOL_VERSION, request_id, observations: [], metrics: {},
    artifacts: [], warnings: [], errors: [], provenance: {}, ...patch };
}

export function refusal(tool: string, request_id: string, code: string, detail?: string): ToolEnvelope {
  return envelope(tool, request_id, { status: "rejected", errors: [{ code, ...(detail ? { detail } : {}) }] });
}

export interface CampaignToolPorts {
  requestId(tool: string): string;
  harnessStatus(): Promise<ToolEnvelope>;
  harnessSmoke(): Promise<ToolEnvelope>;
  fuzzStatus(): Promise<ToolEnvelope>;
  fuzzRun(seconds: number): Promise<ToolEnvelope>;
  crashList(): Promise<ToolEnvelope>;
  crashReplay(crash_id: string): Promise<ToolEnvelope>;
  crashContrast(crash_id: string, field: string, op: "delete" | "shorten", shorten_to: number | null): Promise<ToolEnvelope>;
  cveQuery(vendor: string, product: string, version: string): Promise<ToolEnvelope>;
  cveBind(args: { crash_id: string; cve_id?: string; cited_function?: string; rationale: string }): Promise<ToolEnvelope>;
}

function present(envelopeValue: ToolEnvelope) {
  return { content: [{ type: "text" as const, text: JSON.stringify(envelopeValue) }], details: envelopeValue };
}

const crashId = Type.String({ minLength: 1, maxLength: 80 });

function tool(name: string, description: string, parameters: ReturnType<typeof Type.Object>,
  run: (value: any) => Promise<ToolEnvelope>): ToolDefinition {
  return defineTool({
    name, label: name, description, parameters,
    async execute(_id, value) { return present(await run(value)); },
  });
}

/**
 * Tool sets per role. `fuzz_run` is registered for the discover role only, so bind mode can neither
 * start a campaign nor pay for one; `fuzz_status` stays readable everywhere.
 */
export function campaignTools(role: CampaignRole, ports: CampaignToolPorts, options: { discover?: boolean } = {}): ToolDefinition[] {
  const status = tool("harness_status", "Report rootfs, httpd hash, replacement library, SONAME, listeners and leftover pids. Read-only.", Type.Object({}, { additionalProperties: false }),
    () => ports.harnessStatus());
  const listTool = tool("crash_list", "List deduplicated crash ids with input hash, fingerprint, whether a replay exists and the terminal bind state. Read-only.", Type.Object({}, { additionalProperties: false }),
    () => ports.crashList());
  const smoke = tool("harness_smoke", "Start the rehosted httpd and request the configured page. One execution at a time.", Type.Object({}, { additionalProperties: false }),
    () => ports.harnessSmoke());
  const fuzzStatus = tool("fuzz_status", "Read the bounded mutation segments already on disk: execs, crash files, unique crashes, seconds. Read-only.", Type.Object({}, { additionalProperties: false }),
    () => ports.fuzzStatus());
  const fuzzRun = tool("fuzz_run", "Run one bounded mutation segment against the rehosted target, then deduplicate and minimise what it finds. Seconds must stay within the configured hard cap.",
    Type.Object({ seconds: Type.Number({ minimum: 1 }) }, { additionalProperties: false }),
    value => ports.fuzzRun(Number(value.seconds)));
  const replay = tool("crash_replay", 'Replay one minimized crash input over HTTP, e.g. {"crash_id":"sample-1"}. One crash per call; the rehost is exclusive.', Type.Object({ crash_id: crashId }, { additionalProperties: false }),
    value => ports.crashReplay(String(value.crash_id)));
  const contrast = tool("crash_contrast", "Replay the same crash after changing one named field of the previous replay. delete, or shorten with shorten_to 0..64. Stores a new replay and keeps the original.",
    Type.Object({ crash_id: crashId, field: Type.String({ minLength: 1, maxLength: 128 }),
      op: Type.Union([Type.Literal("delete"), Type.Literal("shorten")]),
      shorten_to: Type.Optional(Type.Integer({ minimum: 0, maximum: 64 })) }, { additionalProperties: false }),
    value => ports.crashContrast(String(value.crash_id), String(value.field), value.op, typeof value.shorten_to === "number" ? value.shorten_to : null));
  const query = tool("cve_query", "Read the local CVE snapshot for the configured vendor, product and version. No network access.",
    Type.Object({ vendor: Type.String({ minLength: 1, maxLength: 128 }), product: Type.String({ minLength: 1, maxLength: 128 }),
      version: Type.String({ minLength: 1, maxLength: 128 }) }, { additionalProperties: false }),
    value => ports.cveQuery(String(value.vendor), String(value.product), String(value.version)));
  const bind = tool("cve_bind", 'Submit one crash for binding, e.g. {"crash_id":"sample-1","rationale":"..."}. The program computes validation_status; a request cannot ask for "matched".',
    Type.Object({ crash_id: crashId, cve_id: Type.Optional(Type.String({ minLength: 1, maxLength: 128 })),
      cited_function: Type.Optional(Type.String({ minLength: 1, maxLength: 128 })),
      rationale: Type.String({ minLength: 1, maxLength: 2000 }) }, { additionalProperties: false }),
    value => ports.cveBind({ crash_id: String(value.crash_id), cve_id: value.cve_id ? String(value.cve_id) : undefined,
      cited_function: value.cited_function ? String(value.cited_function) : undefined, rationale: String(value.rationale) }));

  if (role === "main") return [status, listTool, fuzzStatus];
  if (role === "discover") return options.discover ? [fuzzStatus, fuzzRun] : [fuzzStatus];
  if (role === "replay") return [smoke, replay, contrast];
  return [query, bind];
}

export interface AnalysisToolPorts {
  requestId(tool: string): string;
  sliceFunction(address: string): Promise<ToolEnvelope>;
  getPath(address: string): Promise<ToolEnvelope>;
  getCallers?(address: string, depth: number): Promise<ToolEnvelope>;
  readArtifactChunk?(artifactSha256: string, offset: number, limit: number): Promise<ToolEnvelope>;
}

const addressParam = Type.String({ minLength: 3, maxLength: 10, pattern: "^0x[0-9a-fA-F]{1,8}$" });
const sha256Param = Type.String({ minLength: 64, maxLength: 64, pattern: "^[0-9a-f]{64}$" });

/** Static analysis tools. Fuzz, replay and CVE roles do not register these. */
export function analysisCampaignTools(ports: AnalysisToolPorts): ToolDefinition[] {
  const slice = tool("slice_function", "Decompile the function that contains one address. Returns a short summary and an artifact id. The decompiled text stays in the artifact.",
    Type.Object({ address: addressParam }, { additionalProperties: false }),
    value => ports.sliceFunction(String(value.address)));
  const path = tool("get_path", "List simple CFG paths from the function entry to the block that contains one address. Returns path count and the crash instruction. A missing backend stays missing.",
    Type.Object({ address: addressParam }, { additionalProperties: false }),
    value => ports.getPath(String(value.address)));
  const out: ToolDefinition[] = [slice, path];
  if (ports.getCallers) {
    const getCallers = ports.getCallers.bind(ports);
    out.push(tool("get_callers", "Walk upstream callers and callsite xrefs of the function containing one address up to depth 1..4. Returns caller summary and an artifact id.",
      Type.Object({ address: addressParam, depth: Type.Optional(Type.Integer({ minimum: 1, maximum: 4 })) }, { additionalProperties: false }),
      value => getCallers(String(value.address), typeof value.depth === "number" ? value.depth : 2)));
  }
  if (ports.readArtifactChunk) {
    const readChunk = ports.readArtifactChunk.bind(ports);
    out.push(tool("read_artifact_chunk", "Read a bounded UTF-8 slice (offset >= 0, limit 1..4096) from a host-verified analysis artifact by sha256. Never accepts filesystem paths.",
      Type.Object({ artifact_sha256: sha256Param, offset: Type.Optional(Type.Integer({ minimum: 0 })), limit: Type.Optional(Type.Integer({ minimum: 1, maximum: 4096 })) }, { additionalProperties: false }),
      value => readChunk(String(value.artifact_sha256), typeof value.offset === "number" ? value.offset : 0, typeof value.limit === "number" ? value.limit : 2048)));
  }
  return out;
}
