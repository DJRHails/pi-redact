/**
 * Logging reverse proxy in front of the Anthropic API.
 *
 * Runs in the harness process and records every request body it receives
 * before forwarding it upstream, so a scenario can assert on the exact bytes
 * pi sent. `rawFetch` is captured at import time, before any extension can
 * wrap `globalThis.fetch`, so the forward leg is never itself redacted and the
 * log reflects what the client emitted.
 */

import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import { Readable } from "node:stream";

const rawFetch = globalThis.fetch;

export interface WireRequest {
  seq: number;
  at: string;
  path: string;
  body: string;
}

export interface LoggingProxy {
  url: string;
  requests: WireRequest[];
  close(): Promise<void>;
}

function readBody(req: IncomingMessage): Promise<string> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    req.on("data", (chunk: Buffer) => chunks.push(chunk));
    req.on("end", () => resolve(Buffer.concat(chunks).toString("utf8")));
    req.on("error", reject);
  });
}

const HOP_BY_HOP = new Set(["host", "connection", "content-length", "transfer-encoding", "keep-alive"]);

function forwardHeaders(req: IncomingMessage): Headers {
  const headers = new Headers();
  for (const [name, value] of Object.entries(req.headers)) {
    if (HOP_BY_HOP.has(name) || value === undefined) continue;
    headers.set(name, Array.isArray(value) ? value.join(", ") : value);
  }
  return headers;
}

async function relay(upstream: string, requests: WireRequest[], req: IncomingMessage, res: ServerResponse): Promise<void> {
  const body = await readBody(req);
  requests.push({ seq: requests.length + 1, at: new Date().toISOString(), path: req.url ?? "/", body });
  const response = await rawFetch(`${upstream}${req.url ?? "/"}`, {
    method: req.method,
    headers: forwardHeaders(req),
    body: body.length > 0 ? body : undefined,
  });
  const responseHeaders: Record<string, string> = {};
  response.headers.forEach((value, name) => {
    if (!HOP_BY_HOP.has(name) && name !== "content-encoding") responseHeaders[name] = value;
  });
  res.writeHead(response.status, responseHeaders);
  if (!response.body) {
    res.end();
    return;
  }
  Readable.fromWeb(response.body as import("node:stream/web").ReadableStream).pipe(res);
}

export function startLoggingProxy(upstream = "https://api.anthropic.com"): Promise<LoggingProxy> {
  const requests: WireRequest[] = [];
  const server: Server = createServer((req, res) => {
    relay(upstream, requests, req, res).catch((error: unknown) => {
      res.writeHead(502, { "content-type": "text/plain" });
      res.end(`proxy error: ${error instanceof Error ? error.message : String(error)}`);
    });
  });
  return new Promise((resolve) => {
    server.listen(0, "127.0.0.1", () => {
      const address = server.address();
      if (!address || typeof address === "string") throw new Error("proxy did not bind a TCP port");
      resolve({
        url: `http://127.0.0.1:${address.port}`,
        requests,
        close: () => new Promise((done) => server.close(() => done())),
      });
    });
  });
}
