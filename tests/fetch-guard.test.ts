import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { installFetchGuard, looksLikeModelRequest, providerHosts } from "../src/fetch-guard.ts";
import { RedactionVault } from "../src/vault.ts";

const TOKEN = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij";

describe("installFetchGuard", () => {
  const realFetch = globalThis.fetch;
  let sent: Array<{ url: string; body: unknown }>;

  beforeEach(() => {
    sent = [];
    // Install a recording fetch *below* the guard, then re-point the guard's original at it.
    const recorder: typeof fetch = async (input, init) => {
      const url = typeof input === "string" ? input : input instanceof URL ? input.href : input.url;
      sent.push({ url, body: init?.body });
      return new Response("ok");
    };
    const guard = installFetchGuard();
    Object.assign(guard, { original: recorder });
    guard.hosts = new Set(["api.anthropic.com"]);
    guard.vault = new RedactionVault({ salt: Buffer.alloc(32, 1) });
    guard.vault.addKnown({ name: "GITHUB_TOKEN", value: TOKEN });
    guard.hits = 0;
  });

  afterEach(() => {
    const guard = installFetchGuard();
    guard.vault = null;
    guard.hosts = new Set();
    Object.assign(guard, { original: realFetch });
  });

  it("installs once and wraps the global", () => {
    expect(installFetchGuard()).toBe(installFetchGuard());
    expect(globalThis.fetch).not.toBe(realFetch);
  });

  it("redacts string bodies sent to a provider host and counts the hit", async () => {
    const body = JSON.stringify({ messages: [{ role: "user", content: `use ${TOKEN}` }] });
    await fetch("https://api.anthropic.com/v1/messages", { method: "POST", body });
    expect(sent).toHaveLength(1);
    expect(sent[0].body).not.toContain(TOKEN);
    expect(JSON.parse(sent[0].body as string)).toEqual({
      messages: [{ role: "user", content: "use [REDACTED:KNOWN:GITHUB_TOKEN]" }],
    });
    expect(installFetchGuard().hits).toBe(1);
  });

  it("leaves other hosts, non-string bodies and clean bodies untouched", async () => {
    const body = JSON.stringify({ q: TOKEN });
    await fetch("https://example.com/search", { method: "POST", body });
    await fetch(new URL("https://api.anthropic.com/v1/messages"), { method: "POST", body: new Blob([TOKEN]) });
    await fetch("https://api.anthropic.com/v1/messages", { method: "POST", body: JSON.stringify({ q: "clean" }) });
    expect(sent[0].body).toBe(body);
    expect(sent[1].body).toBeInstanceOf(Blob);
    expect(sent[2].body).toBe(JSON.stringify({ q: "clean" }));
    expect(installFetchGuard().hits).toBe(0);
  });

  it("redacts a chat-shaped body on an unknown host", async () => {
    const body = JSON.stringify({ model: "claude-haiku-4-5", messages: [{ role: "user", content: `use ${TOKEN}` }] });
    await fetch("http://127.0.0.1:4321/v1/messages", { method: "POST", body });
    expect(sent[0].body).not.toContain(TOKEN);
    expect(installFetchGuard().hits).toBe(1);
  });

  it("passes through when no vault is attached", async () => {
    installFetchGuard().vault = null;
    const body = JSON.stringify({ q: TOKEN });
    await fetch("https://api.anthropic.com/v1/messages", { method: "POST", body });
    expect(sent[0].body).toBe(body);
  });

  it("does not stack a second wrapper on repeated install", () => {
    const spy = vi.spyOn(globalThis, "fetch");
    installFetchGuard();
    expect(spy).not.toHaveBeenCalled();
    spy.mockRestore();
  });
});

describe("looksLikeModelRequest", () => {
  it("recognises the chat request shapes and nothing else", () => {
    expect(looksLikeModelRequest(JSON.stringify({ model: "m", messages: [] }))).toBe(true);
    expect(looksLikeModelRequest(JSON.stringify({ model: "m", input: [] }))).toBe(true);
    expect(looksLikeModelRequest(JSON.stringify({ model: "m", contents: [] }))).toBe(true);
    expect(looksLikeModelRequest(JSON.stringify({ model: "m" }))).toBe(false);
    expect(looksLikeModelRequest(JSON.stringify({ messages: [] }))).toBe(false);
    expect(looksLikeModelRequest(JSON.stringify({ model: 1, messages: [] }))).toBe(false);
    expect(looksLikeModelRequest("not json {model")).toBe(false);
    expect(looksLikeModelRequest(JSON.stringify([{ model: "m", messages: [] }]))).toBe(false);
  });
});

describe("providerHosts", () => {
  it("collects distinct hosts and skips unparsable or missing baseUrls", () => {
    const hosts = providerHosts([
      { baseUrl: "https://api.anthropic.com" },
      { baseUrl: "https://api.anthropic.com/v1" },
      { baseUrl: "http://localhost:8080/v1" },
      { baseUrl: "not a url" },
      {},
    ]);
    expect([...hosts].sort()).toEqual(["api.anthropic.com", "localhost:8080"]);
  });
});
