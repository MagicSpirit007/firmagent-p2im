import { resolve } from "node:path";
import type { Api, Model } from "@earendil-works/pi-ai";
import {
  createAgentSession, DefaultResourceLoader, SessionManager, SettingsManager,
  type CreateAgentSessionOptions, type ExtensionFactory, type ModelRuntime, type ToolDefinition,
} from "@earendil-works/pi-coding-agent";
import { requireThat } from "../contracts.js";

export interface PiBinding {
  runtime: ModelRuntime;
  model: Model<Api>;
  thinkingLevel?: CreateAgentSessionOptions["thinkingLevel"];
  close?: () => void;
}

/** The sole SDK assembly point. Domain policy and dispatch accounting belong to callers. */
export async function createControlledSession(binding: PiBinding, options: {
  cwd: string; directory: string; systemPrompt: string; tools: ToolDefinition[];
  extensions?: { name: string; factory: ExtensionFactory }[];
  retry?: boolean; retryDelayMs?: number;
}) {
  const settings = SettingsManager.inMemory({
    retry: { enabled: options.retry ?? true, maxRetries: 2, baseDelayMs: options.retryDelayMs ?? 1000, provider: { maxRetries: 0 } },
    compaction: { enabled: false },
  });
  const agentDir = resolve(options.directory);
  const loader = new DefaultResourceLoader({
    cwd: options.cwd, agentDir, settingsManager: settings,
    noExtensions: true, noSkills: true, noPromptTemplates: true, noThemes: true, noContextFiles: true,
    systemPromptOverride: () => options.systemPrompt, appendSystemPromptOverride: () => [],
    extensionFactories: options.extensions ?? [],
  });
  await loader.reload();
  requireThat(!loader.getAgentsFiles().agentsFiles.length && !loader.getSkills().skills.length && !loader.getPrompts().prompts.length,
    "RESOURCE_LEAK", "Unexpected discovered resources");
  const manager = SessionManager.inMemory(options.cwd);
  const names = options.tools.map(tool => tool.name);
  const created = await createAgentSession({
    cwd: options.cwd, agentDir, modelRuntime: binding.runtime, model: binding.model,
    thinkingLevel: binding.thinkingLevel ?? "off", sessionManager: manager, settingsManager: settings,
    resourceLoader: loader, customTools: options.tools, tools: names, noTools: "builtin",
  });
  try {
    requireThat(!created.extensionsResult.errors.length && !created.modelFallbackMessage,
      "SESSION_CONFIGURATION_ERROR", "Pi rejected the fixed configuration");
    requireThat(JSON.stringify(created.session.getActiveToolNames().sort()) === JSON.stringify([...names].sort()),
      "POLICY_DENIED", "Actual tools differ from allowlist");
    return { session: created.session, manager };
  } catch (error) { created.session.dispose(); throw error; }
}
