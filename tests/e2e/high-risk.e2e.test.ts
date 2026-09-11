/**
 * Cached end-to-end tests for the high-risk scenarios.
 *
 * Each scenario drives a real pi session with pi-redact loaded, behind the
 * recording proxy. Provider responses come from a committed cassette
 * (`cassettes/<scenario>.json`), so the default run is offline, deterministic
 * and free; the assertions are still made against the bytes the session put
 * on the wire and the effects of the restored values (files written, the
 * local check server authenticating).
 *
 *   pnpm test:e2e                      # replay (default; PI_REDACT_E2E=replay)
 *   PI_REDACT_E2E=record pnpm test:e2e # re-record every cassette against the API
 *   PI_REDACT_E2E=record pnpm test:e2e -t echo-env   # re-record one
 *
 * Determinism comes from `redteam/scenarios.ts`: fixed fake secrets, a fixed
 * cwd per scenario, a fixed check-server port, and a fixed marker salt
 * (`PI_REDACT_SALT`) so detected-value markers match between record and replay.
 */

import { resolve } from "node:path";

import { afterAll, beforeAll, describe, expect, it } from "vitest";

import { SALT_VAR } from "../../extensions/redact.ts";
import { loadCassette, type ProxyMode, startLoggingProxy } from "../../redteam/proxy.ts";
import { runScenario, verdict } from "../../redteam/runner.ts";
import { FIXED_SALT, HIGH_RISK } from "../../redteam/scenarios.ts";

const MODEL_ID = "claude-haiku-4-5";
const CASSETTE_DIR = resolve(import.meta.dirname, "cassettes");

function modeFromEnv(): ProxyMode {
  const raw = process.env.PI_REDACT_E2E ?? "replay";
  if (raw === "replay" || raw === "record" || raw === "live") return raw;
  throw new Error(`PI_REDACT_E2E must be replay, record or live (got ${raw})`);
}

const mode = modeFromEnv();
const previousSalt = process.env[SALT_VAR];
const previousKey = process.env.ANTHROPIC_API_KEY;

beforeAll(() => {
  process.env[SALT_VAR] = FIXED_SALT;
  // Replay never reaches the API, but pi's model runtime still wants a key to build the request.
  if (mode === "replay" && !process.env.ANTHROPIC_API_KEY) process.env.ANTHROPIC_API_KEY = "replay-only";
});

afterAll(() => {
  if (previousSalt === undefined) delete process.env[SALT_VAR];
  else process.env[SALT_VAR] = previousSalt;
  if (previousKey === undefined) delete process.env.ANTHROPIC_API_KEY;
  else process.env.ANTHROPIC_API_KEY = previousKey;
});

describe(`high-risk scenarios (${mode})`, () => {
  for (const scenario of HIGH_RISK) {
    it(scenario.name, { timeout: mode === "replay" ? 60_000 : 300_000 }, async () => {
      const file = resolve(CASSETTE_DIR, `${scenario.name}.json`);
      // Recording starts clean so a cassette never accumulates entries from an earlier run.
      const cassette = mode === "record" ? { file, entries: [] } : loadCassette(file);
      const proxy = await startLoggingProxy({ mode, cassette });
      try {
        const result = await runScenario(scenario, { modelId: MODEL_ID, proxy });
        const summary = [
          `verdict: ${verdict(result)}`,
          result.error ? `error: ${result.error}` : undefined,
          ...result.leaks.map((l) => `leak: ${l.secret} as ${l.spelling} in request #${l.seq}`),
          ...result.checks.filter((c) => !c.pass).map((c) => `check failed: ${c.name} — ${c.detail}`),
        ]
          .filter(Boolean)
          .join("\n");
        expect(result.error, summary).toBeUndefined();
        expect(result.leaks, summary).toEqual([]);
        expect(result.checks.filter((c) => !c.pass), summary).toEqual([]);
        expect(result.requests, "the scenario must actually talk to the model").toBeGreaterThan(0);
        if (mode === "replay") expect(result.replayed, "every request must be served from the cassette").toBe(result.requests);
      } finally {
        await proxy.close();
      }
    });
  }
});
