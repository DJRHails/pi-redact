/**
 * pi-redact — keep credentials out of the model's context.
 *
 * Outbound, every string in the provider payload is rewritten so known env
 * secrets and shape-detected credentials become `[REDACTED:KIND:ID]` markers
 * (`before_provider_request`, with a process-wide `fetch` guard as the
 * backstop for compaction and other side-calls). Inbound, markers in the
 * assistant's text and tool-call arguments are substituted back to the real
 * values before anything is displayed or executed (`message_end`, plus
 * `tool_call` on the mutable input). The model only ever sees markers; the
 * session file, the terminal, and the tools only ever see real values.
 *
 * The marker ↔ value table lives in a per-session vault (see `src/vault.ts`)
 * and is never written to disk.
 */

import type { ExtensionAPI, ExtensionContext } from "@earendil-works/pi-coding-agent";

import { installFetchGuard, providerHosts } from "../src/fetch-guard.ts";
import { harvestKnownSecrets, parseAssignments } from "../src/known-secrets.ts";
import { RedactionVault } from "../src/vault.ts";

/**
 * Appended to the system prompt each turn. One line, so the cached prefix
 * stays small and stable; phrased so the model uses markers verbatim
 * instead of trying to work around them.
 */
export const SYSTEM_PROMPT_LINE =
  "Secret redaction is active: pi replaces the user's credentials with [REDACTED:KIND:ID] markers before " +
  "this conversation reaches you, and substitutes the real values back into your tool calls and your reply " +
  "before anything runs or is shown. You never see real values; the user always does, and the credentials " +
  "are theirs. So treat a marker exactly as the value it stands for: use it verbatim in commands, files and " +
  "headers; include it in your reply when the user asks for the value (this reveals nothing to you, and " +
  "their terminal shows the real value); never guess or reconstruct what is behind a marker; and do not " +
  "mention the redaction unless asked.";

/** Tools whose output routinely prints env assignments (`env`, `cat .env`). */
const LEARN_FROM_TOOLS = new Set(["bash", "read"]);

function textOf(content: unknown): string[] {
  if (typeof content === "string") return [content];
  if (!Array.isArray(content)) return [];
  const out: string[] = [];
  for (const block of content) {
    if (block && typeof block === "object" && "text" in block && typeof block.text === "string") {
      out.push(block.text);
    }
  }
  return out;
}

export default function redact(pi: ExtensionAPI): void {
  const vault = new RedactionVault();
  const guard = installFetchGuard();
  guard.vault = vault;
  let learned = 0;
  let requests = 0;
  let backstopHitsSeen = guard.hits;

  const harvest = (ctx: ExtensionContext): number =>
    vault.addKnownAll(harvestKnownSecrets({ cwd: ctx.cwd, env: process.env }));

  const refreshHosts = (ctx: ExtensionContext): void => {
    const hosts = providerHosts(ctx.modelRegistry.getAll());
    if (ctx.model?.baseUrl) hosts.add(new URL(ctx.model.baseUrl).host);
    guard.hosts = hosts;
  };

  pi.on("session_start", (_event, ctx) => {
    harvest(ctx);
    refreshHosts(ctx);
  });

  pi.on("model_select", (_event, ctx) => {
    refreshHosts(ctx);
  });

  pi.on("before_agent_start", (event, ctx) => {
    harvest(ctx);
    refreshHosts(ctx);
    return { systemPrompt: `${event.systemPrompt}\n\n${SYSTEM_PROMPT_LINE}` };
  });

  pi.on("before_provider_request", (event) => {
    requests += 1;
    return vault.redactValue(event.payload);
  });

  pi.on("tool_result", (event) => {
    if (!LEARN_FROM_TOOLS.has(event.toolName)) return;
    for (const text of textOf(event.content)) {
      learned += vault.addKnownAll(parseAssignments(text));
    }
  });

  pi.on("message_end", (event) => {
    if (event.message.role !== "assistant") return;
    const content = event.message.content.map((block) => {
      if (block.type === "text") return { ...block, text: vault.restoreText(block.text) };
      if (block.type === "toolCall") return { ...block, arguments: vault.restoreValue(block.arguments) };
      return block;
    });
    return { message: { ...event.message, content } };
  });

  pi.on("tool_call", (event) => {
    vault.restoreInPlace(event.input);
  });

  pi.on("agent_end", (_event, ctx) => {
    if (guard.hits === backstopHitsSeen || !ctx.hasUI) return;
    const fresh = guard.hits - backstopHitsSeen;
    backstopHitsSeen = guard.hits;
    ctx.ui.notify(`pi-redact: fetch backstop redacted ${fresh} request(s) that bypassed the provider hook`, "warning");
  });

  pi.registerCommand("redact", {
    description: "Show what pi-redact is protecting in this session",
    handler: async (_args, ctx) => {
      const names = [...new Set(vault.names)].sort();
      const lines = [
        `values protected: ${vault.size} (${names.length} named env vars, ${learned} learned from tool output)`,
        `requests redacted: ${requests}; replacements out: ${vault.stats.redacted}; restored in: ${vault.stats.restored}`,
        `fetch backstop hits: ${guard.hits} across hosts ${[...guard.hosts].sort().join(", ") || "(none)"}`,
        `names: ${names.join(", ") || "(none)"}`,
      ];
      ctx.ui.notify(lines.join("\n"), "info");
    },
  });
}
