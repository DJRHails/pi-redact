/**
 * Recording reverse proxy in front of the Anthropic API.
 *
 * Runs in the harness process and records every request body it receives
 * before forwarding it upstream, so a scenario can assert on the exact bytes
 * pi sent. `rawFetch` is captured at import time, before any extension can
 * wrap `globalThis.fetch`, so the forward leg is never itself redacted and the
 * log reflects what the client emitted.
 *
 * Three modes:
 * - `live`    — forward and stream every response (the red-team CLI default).
 * - `record`  — forward, buffer the response, and append it to the cassette.
 * - `replay`  — serve responses from the cassette; a miss is a hard error that
 *               names the request so the cassette can be re-recorded.
 *
 * Cassette entries are keyed by the SHA-256 of the request body. Bodies only
 * ever contain markers (the extension redacts before the proxy sees them), so
 * a cassette holds no planted secret in plain text.
 *
 * pi's system prompt embeds machine-specific absolute paths (the checkout's
 * `node_modules` docs, the scenario cwd under the temp dir), so the key is
 * computed over the body with those paths swapped for stable placeholders.
 * Without that a cassette only replays from the exact path it was recorded at.
 */

import { createHash } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, realpathSync, writeFileSync } from "node:fs";
import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import { homedir, tmpdir } from "node:os";
import { dirname, resolve } from "node:path";
import { Readable } from "node:stream";

const rawFetch = globalThis.fetch;

export type ProxyMode = "live" | "record" | "replay";

export interface WireRequest {
  seq: number;
  at: string;
  path: string;
  body: string;
  /** Whether the response came from the cassette. */
  replayed: boolean;
}

export interface CassetteEntry {
  /** SHA-256 of path + body; named so secret scanners do not mistake it for a credential. */
  requestHash: string;
  path: string;
  status: number;
  headers: Record<string, string>;
  body: string;
}

export interface Cassette {
  file: string;
  entries: CassetteEntry[];
}

export interface LoggingProxy {
  url: string;
  requests: WireRequest[];
  mode: ProxyMode;
  close(): Promise<void>;
}

export function loadCassette(file: string): Cassette {
  if (!existsSync(file)) return { file, entries: [] };
  const parsed = JSON.parse(readFileSync(file, "utf8")) as { entries: CassetteEntry[] };
  return { file, entries: parsed.entries };
}

export function saveCassette(cassette: Cassette): void {
  mkdirSync(dirname(cassette.file), { recursive: true });
  writeFileSync(cassette.file, `${JSON.stringify({ entries: cassette.entries }, null, 2)}\n`);
}

/** A machine-specific directory and the placeholder that stands for it in request keys. */
export interface MachineRoot {
  dir: string;
  placeholder: string;
}

function withRealpath(dir: string): string[] {
  const real = existsSync(dir) ? realpathSync(dir) : dir;
  return real === dir ? [dir] : [dir, real];
}

/**
 * Checkout root, temp dirs and home dir of this machine, plus their realpaths (macOS `/private/var`).
 * `/tmp` counts as a temp dir even when `TMPDIR` points elsewhere: recorded model replies echo the
 * recorder's scenario cwd, and those replies come back verbatim in the next request.
 */
export function machineRoots(): MachineRoot[] {
  const named: Array<[string, string]> = [
    [resolve(import.meta.dirname, ".."), "<repo>"],
    [tmpdir(), "<tmp>"],
    ["/tmp", "<tmp>"],
    [homedir(), "<home>"],
  ];
  return named.flatMap(([dir, placeholder]) => withRealpath(dir).map((variant) => ({ dir: variant, placeholder })));
}

function escapeRegExp(text: string): string {
  return text.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

/**
 * Replace every machine root in `text` with its placeholder. Longest root first, so the checkout
 * wins over a home dir that contains it; a root only matches as a whole path segment (`/tmp` does
 * not touch `/tmpfoo`); a bare `/` is never a root.
 */
export function normaliseMachinePaths(text: string, roots: MachineRoot[] = machineRoots()): string {
  const usable = roots.filter((root) => root.dir.length > 1).sort((a, b) => b.dir.length - a.dir.length);
  if (usable.length === 0) return text;
  const placeholders = new Map(usable.map((root) => [root.dir, root.placeholder]));
  const alternation = usable.map((root) => escapeRegExp(root.dir)).join("|");
  const pattern = new RegExp(`(?:${alternation})(?![\\w.-])`, "g");
  return text.replace(pattern, (dir) => placeholders.get(dir) ?? dir);
}

export function requestKey(path: string, body: string, roots: MachineRoot[] = machineRoots()): string {
  return createHash("sha256").update(path).update("\0").update(normaliseMachinePaths(body, roots)).digest("hex");
}

function readBody(req: IncomingMessage): Promise<string> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    req.on("data", (chunk: Buffer) => chunks.push(chunk));
    req.on("end", () => resolve(Buffer.concat(chunks).toString("utf8")));
    req.on("error", reject);
  });
}

const HOP_BY_HOP = new Set(["host", "connection", "content-length", "transfer-encoding", "keep-alive", "content-encoding"]);

function forwardHeaders(req: IncomingMessage): Headers {
  const headers = new Headers();
  for (const [name, value] of Object.entries(req.headers)) {
    if (HOP_BY_HOP.has(name) || value === undefined) continue;
    headers.set(name, Array.isArray(value) ? value.join(", ") : value);
  }
  return headers;
}

function responseHeaders(response: Response): Record<string, string> {
  const out: Record<string, string> = {};
  response.headers.forEach((value, name) => {
    if (!HOP_BY_HOP.has(name)) out[name] = value;
  });
  return out;
}

interface ProxyState {
  upstream: string;
  mode: ProxyMode;
  cassette?: Cassette;
  requests: WireRequest[];
}

async function relay(state: ProxyState, req: IncomingMessage, res: ServerResponse): Promise<void> {
  const body = await readBody(req);
  const path = req.url ?? "/";
  const key = requestKey(path, body);
  const cached = state.cassette?.entries.find((entry) => entry.requestHash === key);
  const record: WireRequest = { seq: state.requests.length + 1, at: new Date().toISOString(), path, body, replayed: false };
  state.requests.push(record);

  if (state.mode === "replay") {
    if (!cached) {
      throw new Error(
        `cassette miss for request #${record.seq} ${path} (key ${key.slice(0, 12)}…) in ${state.cassette?.file ?? "(no cassette)"}; ` +
          "re-record with PI_REDACT_E2E=record",
      );
    }
    record.replayed = true;
    res.writeHead(cached.status, cached.headers);
    res.end(cached.body);
    return;
  }

  const response = await rawFetch(`${state.upstream}${path}`, {
    method: req.method,
    headers: forwardHeaders(req),
    body: body.length > 0 ? body : undefined,
  });

  if (state.mode === "record" && state.cassette) {
    const text = await response.text();
    const entry: CassetteEntry = { requestHash: key, path, status: response.status, headers: responseHeaders(response), body: text };
    const existing = state.cassette.entries.findIndex((candidate) => candidate.requestHash === key);
    if (existing === -1) state.cassette.entries.push(entry);
    else state.cassette.entries[existing] = entry;
    saveCassette(state.cassette);
    res.writeHead(entry.status, entry.headers);
    res.end(text);
    return;
  }

  res.writeHead(response.status, responseHeaders(response));
  if (!response.body) {
    res.end();
    return;
  }
  Readable.fromWeb(response.body as import("node:stream/web").ReadableStream).pipe(res);
}

export interface ProxyOptions {
  upstream?: string;
  mode?: ProxyMode;
  cassette?: Cassette;
}

export function startLoggingProxy(options: ProxyOptions = {}): Promise<LoggingProxy> {
  const state: ProxyState = {
    upstream: options.upstream ?? "https://api.anthropic.com",
    mode: options.mode ?? "live",
    cassette: options.cassette,
    requests: [],
  };
  if (state.mode !== "live" && !state.cassette) throw new Error(`proxy mode ${state.mode} needs a cassette`);
  const server: Server = createServer((req, res) => {
    relay(state, req, res).catch((error: unknown) => {
      const message = error instanceof Error ? error.message : String(error);
      console.error(`proxy: ${message}`);
      res.writeHead(502, { "content-type": "text/plain" });
      res.end(`proxy error: ${message}`);
    });
  });
  return new Promise((resolve) => {
    server.listen(0, "127.0.0.1", () => {
      const address = server.address();
      if (!address || typeof address === "string") throw new Error("proxy did not bind a TCP port");
      resolve({
        url: `http://127.0.0.1:${address.port}`,
        requests: state.requests,
        mode: state.mode,
        close: () => new Promise((done) => server.close(() => done())),
      });
    });
  });
}
