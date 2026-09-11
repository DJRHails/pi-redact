/**
 * Structural credential detectors: values whose *format alone* identifies
 * them as a secret, for the case where a credential reaches the model
 * without ever passing through a named env var (pasted into a prompt, read
 * from a config file, printed by a CLI).
 *
 * Ported from the credential subset of palst's `pii_rules.py` (AWS key ids,
 * signed JWTs, Slack tokens) plus the vendor prefixes that show up in a
 * coding session's tool output. PII rules (emails, IBANs, SSNs) are
 * deliberately left out: redacting an email address in a git log would
 * degrade the model's answers for no security gain here.
 *
 * Every hit is redacted as `[REDACTED:<KIND>:<salted-hash>]` (see
 * `vault.ts`). Detectors run in list order, each over the text left by the
 * previous one, so the Anthropic rule must precede the generic OpenAI `sk-`
 * rule that would otherwise also match `sk-ant-…`.
 */

export interface Detector {
  /** Marker kind — upper-case, `[A-Z0-9_]` only. */
  readonly kind: string;
  /** Global regex. When `group` is set, only that named group is the secret. */
  readonly pattern: RegExp;
  readonly group?: string;
  /** Optional post-filter to drop structurally-similar non-secrets. */
  readonly accept?: (value: string) => boolean;
}

/** base64url-decode a JWT segment and require a JSON object with `alg`. */
function isJwtHeader(segment: string): boolean {
  try {
    const json = Buffer.from(segment, "base64url").toString("utf8");
    const parsed: unknown = JSON.parse(json);
    return typeof parsed === "object" && parsed !== null && "alg" in parsed;
  } catch {
    return false;
  }
}

export const DETECTORS: readonly Detector[] = [
  {
    kind: "PRIVATE_KEY",
    // Whole PEM block, header through footer, so no fragment of the key survives.
    pattern: /-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----/g,
  },
  {
    kind: "AWS",
    // Access-key-id families: long-term AKIA/ACCA, STS-issued ASIA/ABIA; 16 uppercase alnum.
    pattern: /\b(?:AKIA|ABIA|ACCA|ASIA)[A-Z0-9]{16}\b/g,
  },
  {
    kind: "GITHUB",
    // Classic/fine-grained/app tokens: ghp_/gho_/ghu_/ghs_/ghr_ + 36 alnum, or github_pat_ + 60+.
    pattern: /\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{60,})\b/g,
  },
  {
    kind: "ANTHROPIC",
    pattern: /\bsk-ant-[A-Za-z0-9_-]{40,}/g,
  },
  {
    kind: "OPENAI",
    // Legacy `sk-…`, project `sk-proj-…`, service-account `sk-svcacct-…`.
    pattern: /\bsk-(?:proj-|svcacct-)?[A-Za-z0-9_-]{32,}/g,
  },
  {
    kind: "GOOGLE",
    pattern: /\bAIza[0-9A-Za-z_-]{35}\b/g,
  },
  {
    kind: "HUGGINGFACE",
    pattern: /\bhf_[A-Za-z0-9]{30,}\b/g,
  },
  {
    kind: "SLACK",
    // Family prefix (bot/app/browser-client/cookie/refresh/user/legacy) + hyphenated tail.
    pattern: /\bxox[abcdeprs]-[0-9A-Za-z-]{10,71}[0-9A-Za-z]\b/g,
  },
  {
    kind: "JWT",
    // Three base64url segments; the header always encodes to `eyJ`. Lookarounds instead of
    // `\b` because `-`/`_` are non-word chars, so a token ending in one would break `\b`.
    pattern: /(?<![A-Za-z0-9_-])eyJ[A-Za-z0-9_-]{12,}\.[A-Za-z0-9_-]{12,}\.[A-Za-z0-9_-]{16,}(?![A-Za-z0-9_-])/g,
    accept: (value) => isJwtHeader(value.split(".")[0]),
  },
  {
    kind: "BEARER",
    // `Authorization: Bearer <token>` in curl lines and header dumps. Markers contain `[`,
    // which is outside the class, so an already-redacted header cannot re-match.
    pattern: /\bBearer\s+(?<token>[A-Za-z0-9._~+/=-]{20,})/gi,
    group: "token",
  },
];

export interface Detection {
  kind: string;
  value: string;
}

/** Every detector hit in `text`, deduplicated by value, in document order. */
export function detectSecrets(text: string, detectors: readonly Detector[] = DETECTORS): Detection[] {
  const seen = new Set<string>();
  const out: Detection[] = [];
  for (const detector of detectors) {
    detector.pattern.lastIndex = 0;
    for (const match of text.matchAll(detector.pattern)) {
      const value = detector.group ? match.groups?.[detector.group] : match[0];
      if (!value || seen.has(value)) continue;
      if (detector.accept && !detector.accept(value)) continue;
      seen.add(value);
      out.push({ kind: detector.kind, value });
    }
  }
  return out;
}
