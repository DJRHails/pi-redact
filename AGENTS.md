# pi-redact

A pi extension that redacts credentials before requests reach the model provider and restores them in the response. See README.md for the user-facing description.

## Layout

```
extensions/redact.ts   — the extension: hook wiring, system-prompt line, /redact command
src/known-secrets.ts   — harvest exact values from env, .env files, tool output (palst known_secrets.py port)
src/detectors.ts       — structural credential regexes (palst pii_rules.py credential subset + vendor prefixes)
src/vault.ts           — session-scoped marker↔value table, exact-value replacement both ways, payload deep walk
src/fetch-guard.ts     — globalThis.fetch wrapper: backstop for provider calls that bypass before_provider_request
tests/                 — vitest unit tests over src/ (no pi runtime needed)
redteam/               — live harness: logging proxy + SDK-driven scenarios (run.ts) and with/without comparison (degrade.ts)
```

`package.json` `pi.extensions` points at `extensions/`, so **only** entry files go there; helpers live in `src/` and are imported with explicit `.ts` extensions (pi loads TypeScript through jiti, node runs the harness with type stripping).

## Invariants worth knowing before changing anything

- **Replacement is exact-value, longest-first, both spellings.** The vault builds one alternation over every registered value and its JSON-escaped form. Never add pattern *rewriting*; add a detector instead.
- **Markers are the only thing that crosses the wire.** `[REDACTED:KNOWN:<NAME>]` for harvested values, `[REDACTED:<KIND>:<8-hex>]` for detected ones. `MARKER_PATTERN` in `vault.ts` is the single definition; restoration leaves unknown markers untouched.
- **Never rewrite signed or binary strings.** `shouldSkipString` in `vault.ts` skips `signature`/`thinkingSignature` keys and base64 image data. A changed byte in a thinking block invalidates the provider signature.
- **`before_provider_request` does not fire for compaction, branch summaries, or `complete()` side-calls** (pi 0.85.1: `compaction.js` builds request options without `onPayload`). That is why the fetch guard exists. If pi grows a universal hook, prefer it and delete the guard.
- **`session_start` only fires after `bindExtensions()`.** The CLI modes call it; raw SDK sessions must too (the harness does). The extension also harvests and refreshes hosts in `before_agent_start` so it never depends on that event alone.
- **Nothing persists.** The vault (salt included) lives for one session in memory. Do not write values to disk, logs, errors, or the `/redact` output.
- **Minimum value length is 8, not palst's 5.** Deliberate: false positives rewrite live model input here. Document any further deviation from palst in the module docstring.

## Working on it

```sh
pnpm install
pnpm check            # oxlint + tsc --noEmit + vitest
node redteam/run.ts --repeat 3                 # needs ANTHROPIC_API_KEY; ~1 min on haiku
node redteam/degrade.ts --repeat 3             # with/without comparison on ordinary tasks
```

Red-team results land in `redteam/results/` (gitignored). Planted secrets are random per run and never real credentials, but the wire logs are still not for committing.

When changing the system-prompt paragraph, re-run at least `echo-env`, `pasted-shape`, `header-roundtrip` on Haiku **and** Sonnet: the failure mode that has actually occurred is the model refusing to repeat the user's own credential back to them, not a leak.

## Conventions

- Single-purpose modules; keep the pure logic in `src/` importable without pi.
- Conventional Commits.
- No build step, no transpilation, no runtime dependencies (pi installs git packages with `npm install --omit=dev`).
