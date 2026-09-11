/**
 * Harvest exact secret values the host actually knows about.
 *
 * Port of palst's `known_secrets.py` (itself a port of pi-share-hf's
 * `secrets.ts`): instead of guessing at secrets with token-shape regexes,
 * collect the exact values from the places they are defined and redact only
 * those. Shape-based detection (`detectors.ts`) is the backstop for values
 * that never went through an env var.
 *
 * Sources, in collection order (duplicate values collapse to the first name
 * that introduced them, so this order decides attribution):
 *
 * 1. Env files: `.env` / `.env.*` in the working directory (minus example /
 *    sample / template variants) plus any paths listed in
 *    `PI_REDACT_ENV_FILES` (`path.delimiter`-separated). `export NAME=value`
 *    and bare `NAME=value` are both accepted; an unquoted `#` starts a comment.
 * 2. The live process environment.
 * 3. Assignment lines observed in tool output (`env`, `cat .env`) — see
 *    {@link parseAssignments}; the extension feeds these in at `tool_result`.
 *
 * A value only counts when the variable NAME looks sensitive (contains KEY /
 * TOKEN / SECRET / PASSWORD / PWD / COOKIE — the pi-share-hf heuristic) and the
 * name does not end in a suffix that marks it as a *pointer* to a secret
 * (`_FILE`, `_PATH`, `_DIR`, `_URL`, `_SOCK`): `SOPS_AGE_SSH_PRIVATE_KEY_FILE`
 * holds a path, and redacting that path everywhere would shred every
 * transcript that mentions it.
 *
 * Deliberate deviation from palst: the minimum value length is 8, not 5.
 * palst redacts archived transcripts where TruffleHog backstops it and a false
 * positive costs little; here a false positive rewrites live model input
 * (`TOKENIZERS_PARALLELISM=false` would otherwise erase every "false" the model
 * sees). Real credentials are essentially never shorter than 8 characters.
 */

import { readdirSync, readFileSync } from "node:fs";
import { delimiter, join } from "node:path";

export const ENV_FILES_VAR = "PI_REDACT_ENV_FILES";

const SENSITIVE_NAME_TOKENS = ["KEY", "TOKEN", "SECRET", "PASSWORD", "PWD", "COOKIE"];

/** Shell-managed cwd variables: substring-match PWD but hold a directory. */
const NON_SECRET_EXACT_NAMES = new Set(["PWD", "OLDPWD"]);

/** Suffixes marking a variable as a *reference* to a secret, not the secret itself. */
const POINTER_SUFFIXES = ["_FILE", "_PATH", "_DIR", "_URL", "_SOCK"];

export const MIN_VALUE_LENGTH = 8;

/** Templates and docs stubs whose values are placeholders, never credentials. */
const NON_SECRET_ENV_FILE_SUFFIXES = [".example", ".sample", ".template", ".dist"];

const ASSIGNMENT_PATTERN = new RegExp(
  [
    String.raw`^\s*`,
    String.raw`(?:export\s+)?`, // `export NAME=...` or bare `NAME=...`
    String.raw`(?<name>[A-Za-z_][A-Za-z0-9_]*)`, // shell identifier
    "=",
    String.raw`(?<value>`,
    String.raw`"(?<dquoted>[^"]*)"`, // double-quoted value
    String.raw`|'(?<squoted>[^']*)'`, // single-quoted value
    String.raw`|(?<bare>[^\s#]+)`, // unquoted: up to whitespace / comment
    ")",
  ].join(""),
);

/**
 * Placeholder values a README or `.env.example` would carry. Redacting
 * `your-api-key-here` everywhere is harmless but noisy; skip the obvious ones.
 */
const PLACEHOLDER_PATTERN = new RegExp(
  [
    "^(?:",
    "<.*>", // <your-key>
    String.raw`|\$\{?[A-Za-z_][A-Za-z0-9_]*\}?`, // ${OTHER_VAR} / $OTHER_VAR (shell reference)
    "|.*(?:your[_-]|example|changeme|placeholder|replace[_-]?me|xxxx|dummy).*",
    String.raw`|(.)\1+`, // one character repeated
    ")$",
  ].join(""),
  "i",
);

export interface KnownSecret {
  /** Env-var name — safe to surface; only the value is sensitive. */
  readonly name: string;
  readonly value: string;
}

export function looksSensitiveName(name: string): boolean {
  const upper = name.toUpperCase();
  if (NON_SECRET_EXACT_NAMES.has(upper)) return false;
  if (POINTER_SUFFIXES.some((suffix) => upper.endsWith(suffix))) return false;
  return SENSITIVE_NAME_TOKENS.some((token) => upper.includes(token));
}

/** True when a value is long enough and not an obvious placeholder. */
export function isPlausibleSecretValue(value: string): boolean {
  if (value.length < MIN_VALUE_LENGTH) return false;
  return !PLACEHOLDER_PATTERN.test(value);
}

/**
 * Extract `(name, value)` assignments from shell / dotenv text.
 *
 * Only assignments whose name {@link looksSensitiveName} and whose value
 * {@link isPlausibleSecretValue} are returned; the caller decides attribution.
 */
export function parseAssignments(text: string): KnownSecret[] {
  const out: KnownSecret[] = [];
  for (const line of text.split("\n")) {
    const match = ASSIGNMENT_PATTERN.exec(line);
    if (!match?.groups) continue;
    const { name, dquoted, squoted, bare } = match.groups;
    const value = (dquoted ?? squoted ?? bare ?? "").trim();
    if (!looksSensitiveName(name) || !isPlausibleSecretValue(value)) continue;
    out.push({ name, value });
  }
  return out;
}

function readEnvFile(path: string): KnownSecret[] {
  let text: string;
  try {
    text = readFileSync(path, "utf8");
  } catch {
    return [];
  }
  return parseAssignments(text);
}

/** `.env` and `.env.*` in `cwd`, minus example/sample/template variants. */
export function discoverEnvFiles(cwd: string): string[] {
  let names: string[];
  try {
    names = readdirSync(cwd);
  } catch {
    return [];
  }
  return names
    .filter((name) => name === ".env" || name.startsWith(".env."))
    .filter((name) => !NON_SECRET_ENV_FILE_SUFFIXES.some((suffix) => name.endsWith(suffix)))
    .sort()
    .map((name) => join(cwd, name));
}

/** Paths from `PI_REDACT_ENV_FILES`, `path.delimiter`-separated. */
export function configuredEnvFiles(env: NodeJS.ProcessEnv): string[] {
  const raw = env[ENV_FILES_VAR];
  if (!raw) return [];
  return raw
    .split(delimiter)
    .map((p) => p.trim())
    .filter(Boolean);
}

export interface HarvestOptions {
  cwd: string;
  env: NodeJS.ProcessEnv;
}

/**
 * Gather every exact secret value from env files and the process environment.
 *
 * Returns secrets with duplicate values collapsed to the first name that
 * introduced them. Ordering by length for replacement is the vault's job, not
 * a property callers should rely on here.
 */
export function harvestKnownSecrets({ cwd, env }: HarvestOptions): KnownSecret[] {
  const candidates: KnownSecret[] = [];
  for (const path of [...discoverEnvFiles(cwd), ...configuredEnvFiles(env)]) {
    candidates.push(...readEnvFile(path));
  }
  for (const name of Object.keys(env).sort()) {
    const value = env[name]?.trim() ?? "";
    if (looksSensitiveName(name) && isPlausibleSecretValue(value)) {
      candidates.push({ name, value });
    }
  }
  const seen = new Set<string>();
  const out: KnownSecret[] = [];
  for (const secret of candidates) {
    if (seen.has(secret.value)) continue;
    seen.add(secret.value);
    out.push(secret);
  }
  return out;
}
