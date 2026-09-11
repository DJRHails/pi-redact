/**
 * Process-wide `fetch` guard: the backstop for provider calls that bypass pi's
 * `before_provider_request` hook.
 *
 * That hook is wired through the agent loop's `onPayload` option, and only the
 * main loop passes it: compaction summaries, branch summaries (`/tree`), and
 * extensions that call `complete()` directly all invoke the provider transport
 * without it (verified against pi 0.85.1 `compaction.js`, which builds its
 * request options without `onPayload`). A compaction would therefore ship the
 * un-redacted conversation. Every provider SDK pi uses resolves `fetch` from
 * the global at client-construction time, and pi constructs a client per
 * request, so wrapping `globalThis.fetch` once covers all of them.
 *
 * Scope is deliberately narrow: only string bodies (what the SDKs send), and
 * only when the URL host is a registered model provider's host or the body is
 * shaped like a chat-completion request (`looksLikeModelRequest`). Anything
 * else passes through untouched, so web-fetching extensions are unaffected.
 *
 * Installed once per process behind a `Symbol.for` key: pi reloads extensions
 * per session, and the guard must keep pointing at the *current* session's
 * vault rather than stacking wrappers.
 */

import type { RedactionVault } from "./vault.ts";

const GUARD_KEY = Symbol.for("pi-redact.fetch-guard");

export interface FetchGuard {
  /** The unwrapped `fetch`, for the guard itself and for tests. */
  readonly original: typeof globalThis.fetch;
  /** Hosts whose request bodies are redacted. */
  hosts: Set<string>;
  /** The vault redacting bodies right now; `null` disables redaction without unwrapping. */
  vault: RedactionVault | null;
  /** Requests whose body changed under the guard — i.e. a path the primary hook missed. */
  hits: number;
}

function requestUrl(input: RequestInfo | URL): string {
  if (typeof input === "string") return input;
  if (input instanceof URL) return input.href;
  return input.url;
}

function hostOf(url: string): string | null {
  try {
    return new URL(url).host;
  } catch {
    return null;
  }
}

/** Conversation-array keys across the chat APIs pi speaks: Anthropic/OpenAI `messages`, Responses `input`, Gemini `contents`. */
const CONVERSATION_KEYS = ["messages", "input", "contents"];

/**
 * Cheap structural test for an LLM request body: a JSON object with a `model`
 * string and a conversation array. Complements the host allow-list so a
 * provider registered under a host we never learned (a proxy, a side-call
 * made before any session event fired) is still covered. A false positive
 * only means a non-LLM request gets its secrets redacted, which is the safe
 * direction to fail.
 */
export function looksLikeModelRequest(body: string): boolean {
  if (!body.startsWith("{") || !body.includes('"model"')) return false;
  let parsed: unknown;
  try {
    parsed = JSON.parse(body);
  } catch {
    return false;
  }
  if (typeof parsed !== "object" || parsed === null) return false;
  const record = parsed as Record<string, unknown>;
  if (typeof record.model !== "string") return false;
  return CONVERSATION_KEYS.some((key) => Array.isArray(record[key]));
}

/** Install (or return the already-installed) guard. */
export function installFetchGuard(): FetchGuard {
  const registry = globalThis as typeof globalThis & { [GUARD_KEY]?: FetchGuard };
  const existing = registry[GUARD_KEY];
  if (existing) return existing;

  const guard: FetchGuard = {
    original: globalThis.fetch,
    hosts: new Set(),
    vault: null,
    hits: 0,
  };

  const guarded: typeof globalThis.fetch = (input, init) => {
    const body = init?.body;
    if (!guard.vault || typeof body !== "string") return guard.original(input, init);
    const host = hostOf(requestUrl(input));
    const inScope = (host !== null && guard.hosts.has(host)) || looksLikeModelRequest(body);
    if (!inScope) return guard.original(input, init);
    const redacted = guard.vault.redactSerialized(body);
    if (redacted !== body) guard.hits += 1;
    return guard.original(input, { ...init, body: redacted });
  };

  globalThis.fetch = guarded;
  registry[GUARD_KEY] = guard;
  return guard;
}

/** Hosts of every model's `baseUrl` in the list, for `FetchGuard.hosts`. */
export function providerHosts(models: Iterable<{ baseUrl?: string }>): Set<string> {
  const hosts = new Set<string>();
  for (const model of models) {
    const host = model.baseUrl ? hostOf(model.baseUrl) : null;
    if (host) hosts.add(host);
  }
  return hosts;
}
