# pi-redact

A pi extension that redacts credentials before requests reach the model provider and restores them in the response. See README.md for the user-facing description.

## Layout

```
extensions/redact.ts   — the extension: hook wiring, system-prompt line, /redact command
src/known-secrets.ts   — harvest exact values from env, .env files, tool output (palst known_secrets.py port)
src/detectors.ts       — structural credential regexes (palst pii_rules.py credential subset + vendor prefixes)
src/vault.ts           — session-scoped marker↔value table, exact-value replacement both ways, payload deep walk
src/fetch-guard.ts     — globalThis.fetch wrapper: backstop for provider calls that bypass before_provider_request
tests/*.test.ts        — vitest unit tests over src/ (no pi runtime needed)
tests/e2e/             — cached end-to-end tests: every HIGH_RISK scenario replayed from cassettes/<scenario>.json
redteam/scenarios.ts   — the scenario definitions (fixed fake secrets, fixed cwd + check port, deterministic commands)
redteam/runner.ts      — runs one scenario: plant env, open session behind the proxy, prompt, scan wire, verify
redteam/proxy.ts       — recording reverse proxy: live | record | replay, cassette keyed by SHA-256 of the request body with checkout/tmp/home paths normalised
redteam/harness.ts     — isolated pi session (SDK), leak scanner (raw/JSON/base64/url/character-separated), check server
redteam/run.ts         — live red-team CLI → redteam/results/<ts>/report.md
redteam/degrade.ts     — same ordinary tasks with/without the extension
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
pnpm check            # oxlint + tsc --noEmit + vitest (unit + e2e replay, offline, ~2 s)
pnpm test:e2e:record  # re-record every cassette against the API (needs ANTHROPIC_API_KEY; ~1 min on haiku)
node redteam/run.ts --repeat 3                 # live red-team incl. the known-limitation scenarios
node redteam/degrade.ts --repeat 3             # with/without comparison on ordinary tasks
```

**Anything that changes what goes on the wire invalidates the cassettes**: the system-prompt paragraph, the marker format, the harvest rules, a scenario's prompt or files, pi's own system prompt after a pi upgrade. Replay then fails with `cassette miss for request #N … re-record with PI_REDACT_E2E=record`; that is the expected signal, not a bug. Re-record (recording starts each cassette clean), read the answers in the record run for regressions, and commit the new cassettes. Cassette bodies carry markers only; `gitleaks dir tests/e2e/cassettes` should stay clean.

Keep scenario commands deterministic (no `ls -la`, `date`, `uname`, curl progress meters) or the second request of a chain will miss the cassette. The check server sits on the fixed port `CHECK_PORT`; only one e2e file may exist for that reason.

Red-team results land in `redteam/results/` (gitignored). Planted secrets are synthetic and never real credentials, but the wire logs are still not for committing.

When changing the system-prompt paragraph, re-run at least `echo-env`, `pasted-shape`, `header-roundtrip` live on Haiku **and** Sonnet before re-recording: the failure mode that has actually occurred is the model refusing to repeat the user's own credential back to them, not a leak.

## Conventions

- Single-purpose modules; keep the pure logic in `src/` importable without pi.
- Conventional Commits.
- No build step, no transpilation, no runtime dependencies (pi installs git packages with `npm install --omit=dev`). No `peerDependencies` on the pi packages either: npm 7+ auto-installs peers, which put a second full copy of pi-coding-agent into every installed clone. pi aliases those imports itself, and only types are imported here anyway.
- When testing the extension through `pi -p` from a non-interactive harness, redirect stdin from `/dev/null`: print mode drains a non-TTY stdin to EOF, and an open pipe that never closes looks exactly like a startup hang (an hour was lost to this on 2026-09-11).
