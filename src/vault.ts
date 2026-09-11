/**
 * Session-scoped redaction vault: the marker ↔ value table plus the exact-value
 * replacement it drives in both directions.
 *
 * Port of palst's `redactor.py` / `markers.py`, adapted for a live agent loop:
 *
 * - Known secrets (harvested env values) become `[REDACTED:KNOWN:<NAME>]`.
 * - Detected values (shape-based, see `detectors.ts`) become
 *   `[REDACTED:<KIND>:<hash>]` where `<hash>` is a salted SHA-256 prefix. The
 *   salt is minted per vault, so the same credential yields the same marker
 *   for the whole session (prompt caches stay warm) and a different one in
 *   any other session.
 * - Replacement is by exact value, longest-first, so a secret embedded in a
 *   longer one never splits the longer match. Each value is also matched in
 *   its JSON-escaped spelling, since tool output routinely contains JSON.
 *
 * Nothing here is persisted: the table lives for one session and dies with
 * it. Values never appear in errors or stats.
 */

import { createHash, randomBytes } from "node:crypto";

import { DETECTORS, type Detector, detectSecrets } from "./detectors.ts";
import type { KnownSecret } from "./known-secrets.ts";

const HASH_LENGTH = 8;

export const MARKER_PATTERN = /\[REDACTED:(?<kind>[A-Z0-9_]+):(?<id>[A-Za-z0-9_#.-]+)\]/g;

export interface RedactionStats {
  /** Values replaced on the way out, across every call. */
  redacted: number;
  /** Markers substituted back on the way in, across every call. */
  restored: number;
}

/** The literal value plus its JSON-escaped form when they differ. */
export function valueSpellings(value: string): string[] {
  const encoded = JSON.stringify(value).slice(1, -1);
  return encoded === value ? [value] : [value, encoded];
}

function escapeRegExp(text: string): string {
  return text.replace(/[.*+?^${}()|[\]\\]/g, String.raw`\$&`);
}

/** Keys whose string values must pass through untouched (see `shouldSkipString`). */
const OPAQUE_KEYS = new Set(["signature", "thinkingSignature"]);

/**
 * Strings the walker must not rewrite: provider-signed thinking blocks (a
 * changed byte invalidates the signature) and base64 image payloads (huge,
 * and never contain a credential in literal form).
 */
function shouldSkipString(key: string | undefined, parent: Record<string, unknown> | undefined, value: string): boolean {
  if (key !== undefined && OPAQUE_KEYS.has(key)) return true;
  if (key === "data" && parent && ("media_type" in parent || parent.type === "base64")) return true;
  return value.startsWith("data:") && value.includes(";base64,");
}

export class RedactionVault {
  private readonly markerByValue = new Map<string, string>();
  private readonly valueByMarker = new Map<string, string>();
  private readonly knownNames: string[] = [];
  private readonly salt: Buffer;
  private readonly detectors: readonly Detector[];
  private alternation: RegExp | null = null;
  readonly stats: RedactionStats = { redacted: 0, restored: 0 };

  constructor(options: { salt?: Buffer; detectors?: readonly Detector[] } = {}) {
    this.salt = options.salt ?? randomBytes(32);
    this.detectors = options.detectors ?? DETECTORS;
  }

  /** Number of distinct values the vault will redact. */
  get size(): number {
    return this.markerByValue.size;
  }

  /** Env-var names attributed to known secrets, in insertion order. Safe to display. */
  get names(): readonly string[] {
    return this.knownNames;
  }

  /**
   * Register a harvested secret. Returns true when the value was new.
   *
   * Duplicate values keep the first name that introduced them (palst's
   * attribution rule). A name reused for a *different* value gets a `#n`
   * suffix so the two markers stay distinguishable — restoring
   * `[REDACTED:KNOWN:DB_PASSWORD]` must never have to guess between values.
   */
  addKnown(secret: KnownSecret): boolean {
    if (!secret.value) throw new Error(`known secret ${secret.name} has an empty value`);
    if (this.markerByValue.has(secret.value)) return false;
    const collisions = this.knownNames.filter((name) => name === secret.name).length;
    const id = collisions === 0 ? secret.name : `${secret.name}#${collisions + 1}`;
    this.register(secret.value, `[REDACTED:KNOWN:${id}]`);
    this.knownNames.push(secret.name);
    return true;
  }

  /** Register many secrets; returns how many were new. */
  addKnownAll(secrets: Iterable<KnownSecret>): number {
    let added = 0;
    for (const secret of secrets) {
      if (this.addKnown(secret)) added += 1;
    }
    return added;
  }

  private register(value: string, marker: string): void {
    this.markerByValue.set(value, marker);
    this.valueByMarker.set(marker, value);
    this.alternation = null;
  }

  private detectedMarker(kind: string, value: string): string {
    const hash = createHash("sha256").update(this.salt).update("\0").update(value, "utf8").digest("hex");
    return `[REDACTED:${kind}:${hash.slice(0, HASH_LENGTH)}]`;
  }

  /** One regex over every registered value and its JSON-escaped spelling, longest first. */
  private valuePattern(): RegExp | null {
    if (this.markerByValue.size === 0) return null;
    if (this.alternation) return this.alternation;
    const spellings = new Set<string>();
    for (const value of this.markerByValue.keys()) {
      for (const spelling of valueSpellings(value)) spellings.add(spelling);
    }
    const ordered = [...spellings].sort((a, b) => b.length - a.length || (a < b ? -1 : 1));
    this.alternation = new RegExp(ordered.map(escapeRegExp).join("|"), "g");
    return this.alternation;
  }

  /** The marker for a matched spelling — literal or JSON-escaped. */
  private markerForSpelling(spelling: string): string {
    const direct = this.markerByValue.get(spelling);
    if (direct) return direct;
    const decoded = JSON.parse(`"${spelling}"`) as string;
    const marker = this.markerByValue.get(decoded);
    if (!marker) throw new Error("vault matched a spelling it has no marker for");
    return marker;
  }

  /**
   * Replace every registered value in `text`, then run the shape detectors over
   * what remains and register + replace their hits. Idempotent: markers contain
   * no value and match no detector.
   */
  redactText(text: string): string {
    let out = text;
    const pattern = this.valuePattern();
    if (pattern) {
      out = out.replace(pattern, (spelling) => {
        this.stats.redacted += 1;
        return this.markerForSpelling(spelling);
      });
    }
    const detections = detectSecrets(out, this.detectors).filter(({ value }) => !this.markerByValue.has(value));
    if (detections.length === 0) return out;
    for (const { kind, value } of detections) {
      this.register(value, this.detectedMarker(kind, value));
    }
    const fresh = this.valuePattern();
    if (!fresh) return out;
    return out.replace(fresh, (spelling) => {
      this.stats.redacted += 1;
      return this.markerForSpelling(spelling);
    });
  }

  /** Substitute known markers back to their values; unknown markers are left as written. */
  restoreText(text: string): string {
    if (this.valueByMarker.size === 0 || !text.includes("[REDACTED:")) return text;
    MARKER_PATTERN.lastIndex = 0;
    return text.replace(MARKER_PATTERN, (marker) => {
      const value = this.valueByMarker.get(marker);
      if (value === undefined) return marker;
      this.stats.restored += 1;
      return value;
    });
  }

  /** Deep-copy `value` with every eligible string redacted (see `shouldSkipString`). */
  redactValue<T>(value: T): T {
    return this.walk(value, (text) => this.redactText(text), undefined, undefined) as T;
  }

  /** Deep-copy `value` with every eligible string restored. */
  restoreValue<T>(value: T): T {
    return this.walk(value, (text) => this.restoreText(text), undefined, undefined) as T;
  }

  /** Restore markers inside `target`'s strings, mutating it in place (for mutable event inputs). */
  restoreInPlace(target: unknown): void {
    if (typeof target !== "object" || target === null) return;
    const record = target as Record<string, unknown>;
    for (const key of Object.keys(record)) {
      const value = record[key];
      if (typeof value === "string") {
        if (!shouldSkipString(key, record, value)) record[key] = this.restoreText(value);
      } else if (typeof value === "object" && value !== null) {
        this.restoreInPlace(value);
      }
    }
  }

  /**
   * Redact a serialized request body. JSON bodies are parsed, walked, and
   * re-serialized so the skip rules apply; anything else is treated as text.
   */
  redactSerialized(body: string): string {
    if (!body.startsWith("{") && !body.startsWith("[")) return this.redactText(body);
    let parsed: unknown;
    try {
      parsed = JSON.parse(body);
    } catch {
      return this.redactText(body);
    }
    return JSON.stringify(this.redactValue(parsed));
  }

  private walk(
    value: unknown,
    transform: (text: string) => string,
    key: string | undefined,
    parent: Record<string, unknown> | undefined,
  ): unknown {
    if (typeof value === "string") {
      return shouldSkipString(key, parent, value) ? value : transform(value);
    }
    if (Array.isArray(value)) {
      return value.map((item) => this.walk(item, transform, undefined, undefined));
    }
    if (typeof value === "object" && value !== null) {
      const record = value as Record<string, unknown>;
      const out: Record<string, unknown> = {};
      for (const [childKey, child] of Object.entries(record)) {
        out[childKey] = this.walk(child, transform, childKey, record);
      }
      return out;
    }
    return value;
  }
}
