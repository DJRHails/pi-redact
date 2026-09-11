/**
 * Red-team runner: drives real model calls through the logging proxy with
 * pi-redact loaded and asserts that no spelling of any planted secret reaches
 * the wire, while the task the secret was needed for still succeeds.
 *
 *   node redteam/run.ts [--model claude-haiku-4-5] [--only name,name] [--repeat N]
 *
 * Writes `redteam/results/<timestamp>/report.md` plus one JSON per scenario.
 * Scenarios live in `scenarios.ts`; the cached e2e tests reuse them.
 */

import { mkdirSync, writeFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { parseArgs } from "node:util";

import { startLoggingProxy } from "./proxy.ts";
import { runScenario, type ScenarioResult, verdict } from "./runner.ts";
import { SCENARIOS } from "./scenarios.ts";

function reportFor(results: ScenarioResult[], modelId: string): string {
  const lines = [
    `# pi-redact red-team run — model ${modelId} — ${new Date().toISOString()}`,
    "",
    "| scenario | verdict | leaks | fragments | requests | backstop hits | checks | time |",
    "|---|---|---|---|---|---|---|---|",
  ];
  for (const r of results) {
    const checks = r.checks.map((c) => `${c.pass ? "✓" : "✗"} ${c.name}`).join("<br>") || "—";
    lines.push(`| ${r.name} | ${verdict(r)} | ${r.leaks.length} | ${r.fragments.length} | ${r.requests} | ${r.backstopHits} | ${checks} | ${(r.durationMs / 1000).toFixed(0)}s |`);
  }
  lines.push("", "## Details", "");
  for (const r of results) {
    lines.push(`### ${r.name}`, "", `Goal: ${SCENARIOS.find((s) => s.name === r.name)?.goal ?? ""}`, "");
    if (r.error) lines.push(`Error: ${r.error}`, "");
    for (const c of r.checks) lines.push(`- ${c.pass ? "PASS" : "FAIL"} ${c.name}: ${c.detail}`);
    for (const leak of r.leaks) lines.push(`- LEAK ${leak.secret} as ${leak.spelling} in request #${leak.seq}: \`${leak.context.replace(/\s+/g, " ")}\``);
    for (const leak of r.fragments) lines.push(`- FRAGMENT ${leak.secret} ${leak.spelling} in request #${leak.seq}`);
    lines.push("", `Tools: ${r.transcript.tools.map((t) => t.toolName).join(", ") || "none"}; turns ${r.transcript.usage.turns}; tokens in/out ${r.transcript.usage.input}/${r.transcript.usage.output}`, "");
    lines.push("Final answer:", "", "```", r.transcript.assistantTexts.at(-1) ?? "(none)", "```", "");
  }
  return lines.join("\n");
}

async function main(): Promise<void> {
  const { values } = parseArgs({
    options: {
      model: { type: "string", default: "claude-haiku-4-5" },
      only: { type: "string" },
      repeat: { type: "string", default: "1" },
    },
  });
  const modelId = values.model ?? "claude-haiku-4-5";
  const only = values.only?.split(",").map((s) => s.trim()).filter(Boolean);
  const repeat = Number(values.repeat ?? "1");
  const selected = SCENARIOS.filter((s) => !only || only.includes(s.name));
  const outDir = resolve(import.meta.dirname, "results", new Date().toISOString().replace(/[:.]/g, "-"));
  mkdirSync(outDir, { recursive: true });

  const results: ScenarioResult[] = [];
  for (let round = 0; round < repeat; round += 1) {
    for (const scenario of selected) {
      process.stdout.write(`[${round + 1}/${repeat}] ${scenario.name} … `);
      const proxy = await startLoggingProxy();
      const result = await runScenario(scenario, { modelId, proxy });
      await proxy.close();
      results.push(result);
      process.stdout.write(`${verdict(result)} (${result.leaks.length} leaks, ${result.requests} requests, ${(result.durationMs / 1000).toFixed(0)}s)\n`);
      writeFileSync(join(outDir, `${scenario.name}-${round + 1}.json`), JSON.stringify(result, null, 2));
    }
  }
  const report = reportFor(results, modelId);
  writeFileSync(join(outDir, "report.md"), report);
  console.log(`\nreport: ${join(outDir, "report.md")}`);
  const hardFailures = results.filter((r) => r.expectation === "no-leak" && verdict(r) !== "PASS");
  process.exitCode = hardFailures.length === 0 ? 0 : 1;
}

await main();
