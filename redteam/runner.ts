/**
 * Runs one scenario end to end: plant the env, open an isolated pi session
 * behind the proxy, drive the prompts, then scan the wire and run the
 * scenario's own checks. Shared by the live CLI and the cached e2e tests.
 */

import { mkdirSync, rmSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";

import {
  installFetchGuard,
  type Leak,
  openSession,
  promptWithTimeout,
  scanForFragments,
  scanForLeaks,
  startCheckServer,
  type Transcript,
} from "./harness.ts";
import type { LoggingProxy } from "./proxy.ts";
import { API_TOKEN, CHECK_PORT, CWD_ROOT, type Check, type Expectation, type Scenario, type ScenarioContext } from "./scenarios.ts";

export interface ScenarioResult {
  name: string;
  expectation: Expectation;
  leaks: Leak[];
  fragments: Leak[];
  checks: Check[];
  requests: number;
  replayed: number;
  backstopHits: number;
  transcript: Transcript;
  error?: string;
  durationMs: number;
}

export interface RunOptions {
  modelId: string;
  proxy: LoggingProxy;
}

/** A fresh, fixed-path working directory for the scenario. */
function prepareWorkdir(scenario: Scenario): string {
  const cwd = join(CWD_ROOT, scenario.name);
  rmSync(cwd, { recursive: true, force: true });
  mkdirSync(cwd, { recursive: true });
  for (const [name, content] of Object.entries(scenario.files ?? {})) {
    mkdirSync(dirname(join(cwd, name)), { recursive: true });
    writeFileSync(join(cwd, name), content);
  }
  return cwd;
}

export async function runScenario(scenario: Scenario, { modelId, proxy }: RunOptions): Promise<ScenarioResult> {
  const started = Date.now();
  const guard = installFetchGuard();
  guard.hits = 0;
  const cwd = prepareWorkdir(scenario);
  for (const [name, value] of Object.entries(scenario.env)) process.env[name] = value;

  const check = await startCheckServer(API_TOKEN, CHECK_PORT);
  const live = await openSession({ cwd, modelId, redact: true, proxy });
  const context: ScenarioContext = { live, cwd, checkUrl: check.url, checkReceived: check.received, requests: proxy.requests };
  const result: ScenarioResult = {
    name: scenario.name,
    expectation: scenario.expectation,
    leaks: [],
    fragments: [],
    checks: [],
    requests: 0,
    replayed: 0,
    backstopHits: 0,
    transcript: live.transcript,
    durationMs: 0,
  };
  try {
    for (const prompt of scenario.prompts({ checkUrl: check.url })) await promptWithTimeout(live, prompt);
    if (scenario.after) await scenario.after(context);
    if (scenario.verify) result.checks.push(...(await scenario.verify(context)));
  } catch (error) {
    result.error = error instanceof Error ? error.message : String(error);
  } finally {
    live.dispose();
    for (const name of Object.keys(scenario.env)) delete process.env[name];
    await check.close();
  }

  result.leaks = scanForLeaks(proxy.requests, scenario.planted);
  result.fragments = scanForFragments(proxy.requests, scenario.planted);
  result.requests = proxy.requests.length;
  result.replayed = proxy.requests.filter((r) => r.replayed).length;
  result.backstopHits = guard.hits;
  const answer = live.transcript.assistantTexts.join("\n");
  for (const name of scenario.expectRestoredInAnswer ?? []) {
    const value = scenario.planted[name];
    result.checks.push({
      name: `answer shows real ${name}`,
      pass: answer.includes(value),
      detail: answer.includes(value) ? "present" : `absent; marker in answer: ${answer.includes("[REDACTED")}`,
    });
  }
  result.checks.push({
    name: "no marker left in user-facing answer",
    pass: !answer.includes("[REDACTED:KNOWN:"),
    detail: answer.includes("[REDACTED") ? "a marker survived into the answer" : "clean",
  });
  result.durationMs = Date.now() - started;
  return result;
}

export function verdict(result: ScenarioResult): string {
  if (result.error) return "ERROR";
  const leaked = result.leaks.length > 0;
  const checksPass = result.checks.every((c) => c.pass);
  if (result.expectation === "known-limitation") {
    if (leaked) return "LEAK (expected)";
    return result.fragments.length > 0 ? "FRAGMENT-LEAK (expected)" : "no leak";
  }
  if (!leaked && checksPass) return "PASS";
  return leaked ? "LEAK" : "CHECK-FAIL";
}
