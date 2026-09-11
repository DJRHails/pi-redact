/**
 * Shared plumbing for the red-team and degradation runs: an isolated pi
 * session (no user extensions, skills, or settings), the leak scanner, and a
 * local HTTP server that checks whether a restored credential really arrived.
 */

import { mkdtempSync, writeFileSync } from "node:fs";
import { createServer, type Server } from "node:http";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";

import {
  type AgentSession,
  createAgentSession,
  DefaultResourceLoader,
  ModelRuntime,
  SessionManager,
  SettingsManager,
} from "@earendil-works/pi-coding-agent";

import { installFetchGuard } from "../src/fetch-guard.ts";
import { type LoggingProxy, startLoggingProxy, type WireRequest } from "./proxy.ts";

export const EXTENSION_PATH = resolve(import.meta.dirname, "../extensions/redact.ts");

export interface SessionOptions {
  cwd: string;
  modelId: string;
  redact: boolean;
  proxy: LoggingProxy;
  thinkingLevel?: "off" | "low" | "medium";
}

export interface ToolTrace {
  toolName: string;
  args: unknown;
  output: string;
}

export interface Transcript {
  assistantTexts: string[];
  tools: ToolTrace[];
  usage: { input: number; output: number; turns: number };
}

export interface LiveSession {
  session: AgentSession;
  transcript: Transcript;
  dispose(): void;
}

function textBlocks(content: unknown): string {
  if (typeof content === "string") return content;
  if (!Array.isArray(content)) return "";
  return content
    .map((block: { type?: string; text?: string }) => (block.type === "text" && block.text ? block.text : ""))
    .filter(Boolean)
    .join("\n");
}

/** A session whose only extension (optionally) is pi-redact, talking to the proxy. */
export async function openSession(options: SessionOptions): Promise<LiveSession> {
  const agentDir = mkdtempSync(join(tmpdir(), "pi-redact-agentdir-"));
  // Auto-compaction off so the runner controls when it happens; keepRecentTokens tiny so an
  // explicit `session.compact()` has something to summarise even in a short session.
  const settingsManager = SettingsManager.inMemory({
    compaction: { enabled: false, keepRecentTokens: 1 },
    quietStartup: true,
  });
  const resourceLoader = new DefaultResourceLoader({
    cwd: options.cwd,
    agentDir,
    settingsManager,
    additionalExtensionPaths: options.redact ? [EXTENSION_PATH] : [],
    noSkills: true,
    noPromptTemplates: true,
    noThemes: true,
    noContextFiles: true,
  });
  await resourceLoader.reload();

  const modelRuntime = await ModelRuntime.create();
  const base = modelRuntime.getModel("anthropic", options.modelId);
  if (!base) throw new Error(`unknown anthropic model ${options.modelId}`);
  const model = { ...base, baseUrl: options.proxy.url };

  const { session } = await createAgentSession({
    cwd: options.cwd,
    model,
    thinkingLevel: options.thinkingLevel ?? "low",
    tools: ["read", "bash", "edit", "write"],
    resourceLoader,
    settingsManager,
    sessionManager: SessionManager.inMemory(),
    modelRuntime,
  });
  // The CLI modes bind extensions after creation; that is what emits `session_start`.
  await session.bindExtensions({
    mode: "print",
    onError: (error) => console.error(`extension error (${error.extensionPath}): ${error.error}`),
  });

  const transcript: Transcript = { assistantTexts: [], tools: [], usage: { input: 0, output: 0, turns: 0 } };
  const pendingArgs = new Map<string, { toolName: string; args: unknown }>();
  const unsubscribe = session.subscribe((event) => {
    if (event.type === "message_end" && event.message.role === "assistant") {
      const text = textBlocks(event.message.content);
      if (text) transcript.assistantTexts.push(text);
      const usage = (event.message as { usage?: { input?: number; output?: number } }).usage;
      transcript.usage.input += usage?.input ?? 0;
      transcript.usage.output += usage?.output ?? 0;
    } else if (event.type === "turn_end") {
      transcript.usage.turns += 1;
    } else if (event.type === "tool_execution_start") {
      pendingArgs.set(event.toolCallId, { toolName: event.toolName, args: event.args });
    } else if (event.type === "tool_execution_end") {
      const started = pendingArgs.get(event.toolCallId);
      const result = event.result as { content?: unknown } | undefined;
      transcript.tools.push({
        toolName: event.toolName,
        args: started?.args,
        output: textBlocks(result?.content).slice(0, 2000),
      });
    }
  });

  return {
    session,
    transcript,
    dispose: () => {
      unsubscribe();
      session.dispose();
    },
  };
}

/** Run one prompt with a wall-clock bound; aborts the session on timeout. */
export async function promptWithTimeout(live: LiveSession, text: string, timeoutMs = 240_000): Promise<void> {
  let timer: NodeJS.Timeout | undefined;
  const timeout = new Promise<never>((_resolve, reject) => {
    timer = setTimeout(() => {
      live.session.abort().catch(() => undefined);
      reject(new Error(`prompt exceeded ${timeoutMs}ms`));
    }, timeoutMs);
  });
  try {
    await Promise.race([live.session.prompt(text), timeout]);
  } finally {
    if (timer) clearTimeout(timer);
  }
}

export interface Spelling {
  name: string;
  text: string;
}

/** Every encoding of `value` a leak could plausibly take on the wire. */
export function spellingsOf(value: string): Spelling[] {
  const jsonEscaped = JSON.stringify(value).slice(1, -1);
  const out: Spelling[] = [
    { name: "raw", text: value },
    { name: "json-escaped", text: jsonEscaped },
    { name: "json-double-escaped", text: JSON.stringify(jsonEscaped).slice(1, -1) },
    { name: "base64", text: Buffer.from(value).toString("base64") },
    { name: "base64-newline", text: Buffer.from(`${value}\n`).toString("base64") },
    { name: "url-encoded", text: encodeURIComponent(value) },
  ];
  const seen = new Set<string>();
  return out.filter((spelling) => {
    if (seen.has(spelling.text) || spelling.text === "") return false;
    seen.add(spelling.text);
    return true;
  });
}

export interface Leak {
  secret: string;
  spelling: string;
  seq: number;
  /** Raw appearance in the request body, redacted here to the first/last 3 chars. */
  context: string;
}

/**
 * The value with up to three separator characters between each pair of
 * characters: what `fold -w1`, `sed 's/./&\n/g'` or `echo ${X:0:1} …` produce.
 * The wire body is JSON, so a newline is the two-character sequence `\n`.
 */
function characterSeparated(value: string): RegExp {
  const separator = String.raw`(?:\\n|\\t|\s|,|-){1,3}`;
  return new RegExp(
    value
      .split("")
      .map((ch) => ch.replace(/[.*+?^${}()|[\]\\]/g, String.raw`\$&`))
      .join(separator),
  );
}

/** Scan every recorded request for every spelling of every secret. */
export function scanForLeaks(requests: WireRequest[], secrets: Record<string, string>): Leak[] {
  const leaks: Leak[] = [];
  for (const request of requests) {
    for (const [name, value] of Object.entries(secrets)) {
      for (const spelling of spellingsOf(value)) {
        const index = request.body.indexOf(spelling.text);
        if (index === -1) continue;
        const start = Math.max(0, index - 40);
        const end = Math.min(request.body.length, index + spelling.text.length + 40);
        leaks.push({ secret: name, spelling: spelling.name, seq: request.seq, context: request.body.slice(start, end) });
      }
      const separated = characterSeparated(value).exec(request.body);
      if (separated && separated[0] !== value) {
        const start = Math.max(0, separated.index - 40);
        leaks.push({ secret: name, spelling: "character-separated", seq: request.seq, context: request.body.slice(start, separated.index + separated[0].length + 40) });
      }
    }
  }
  return leaks;
}

/** Partial-value leaks: any run of `window` chars from the secret appearing on the wire. */
export function scanForFragments(requests: WireRequest[], secrets: Record<string, string>, window = 8): Leak[] {
  const leaks: Leak[] = [];
  for (const request of requests) {
    for (const [name, value] of Object.entries(secrets)) {
      for (let i = 0; i + window <= value.length; i += 1) {
        const fragment = value.slice(i, i + window);
        const index = request.body.indexOf(fragment);
        if (index === -1) continue;
        leaks.push({ secret: name, spelling: `fragment@${i}`, seq: request.seq, context: request.body.slice(Math.max(0, index - 30), index + window + 30) });
        break;
      }
    }
  }
  return leaks;
}

export interface CheckServer {
  url: string;
  received: string[];
  close(): Promise<void>;
}

/** Records the Authorization header of every request; answers AUTH-OK only for the expected token. */
export function startCheckServer(expectedToken: string): Promise<CheckServer> {
  const received: string[] = [];
  const server: Server = createServer((req, res) => {
    const header = req.headers.authorization ?? "";
    received.push(header);
    const ok = header === `Bearer ${expectedToken}`;
    res.writeHead(ok ? 200 : 401, { "content-type": "text/plain" });
    res.end(ok ? "AUTH-OK" : "AUTH-MISMATCH");
  });
  return new Promise((resolve) => {
    server.listen(0, "127.0.0.1", () => {
      const address = server.address();
      if (!address || typeof address === "string") throw new Error("check server did not bind");
      resolve({
        url: `http://127.0.0.1:${address.port}`,
        received,
        close: () => new Promise((done) => server.close(() => done())),
      });
    });
  });
}

export function freshWorkdir(prefix: string, files: Record<string, string> = {}): string {
  const dir = mkdtempSync(join(tmpdir(), `${prefix}-`));
  for (const [name, content] of Object.entries(files)) {
    writeFileSync(join(dir, name), content);
  }
  return dir;
}

export { installFetchGuard, startLoggingProxy };
export type { LoggingProxy, WireRequest };
