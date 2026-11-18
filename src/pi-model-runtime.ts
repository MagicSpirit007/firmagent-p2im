import { join, resolve } from "node:path";
import { getAgentDir, ModelRuntime, SettingsManager, type CreateAgentSessionOptions } from "@earendil-works/pi-coding-agent";
import type { PiBinding } from "./core/session.js";
import { requireThat } from "./contracts.js";
export interface PiSelection { agentDir?: string; provider?: string; model?: string; thinking?: CreateAgentSessionOptions["thinkingLevel"] }
/** Settings/authentication remain Pi-owned; never copy or log secret values. */
export function selectPiModel(options: PiSelection, cwd: string) {
  const agentDir = resolve(options.agentDir ?? getAgentDir());
  const settings = SettingsManager.create(cwd, agentDir, { projectTrusted: false });
  requireThat(!settings.drainErrors().length, "PI_SETTINGS_INVALID", "Pi settings could not be read; configuration errors are not ignored");
  const provider = options.provider ?? settings.getDefaultProvider(), model = options.model ?? settings.getDefaultModel();
  requireThat(provider && model, "MODEL_NOT_SELECTED", "Select a model in Pi settings or pass --provider and --model; no fallback is allowed");
  return { agentDir, provider, model, thinking: options.thinking ?? settings.getModelThinkingLevel(provider, model) ?? settings.getDefaultThinkingLevel() ?? "off" };
}
export async function openPiModel(options: PiSelection, cwd: string, signal?: AbortSignal): Promise<PiBinding> {
  const selected = selectPiModel(options, cwd);
  const runtime = await ModelRuntime.create({ authPath: join(selected.agentDir, "auth.json"), modelsPath: join(selected.agentDir, "models.json"), allowModelNetwork: false, refreshOnCreate: false, signal });
  requireThat(!runtime.getError(), "PI_MODELS_INVALID", "Pi models configuration is invalid; no fallback is allowed");
  const model = runtime.getModel(selected.provider, selected.model);
  requireThat(model, "MODEL_NOT_FOUND", "Selected model is absent from the Pi registry");
  requireThat(!model.api.toLowerCase().includes("faux") && !model.provider.toLowerCase().includes("faux"), "POLICY_DENIED", "Real mode cannot select a Faux provider");
  return { runtime, model, thinkingLevel: selected.thinking };
}
