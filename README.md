# pi-redact

A [pi](https://github.com/earendil-works/pi-coding-agent) extension that keeps your credentials out of the model's context. Env secrets and shape-detected credentials are replaced with `[REDACTED:KIND:ID]` markers before any request leaves the process, and the markers are substituted back to the real values in the model's reply and tool calls before anything runs or is shown. The model only ever sees markers; your terminal, session file, and tools only ever see real values.

```
you:    Run `echo $GITHUB_TOKEN` and use it in a curl header.
wire:   [Tool result]: [REDACTED:KNOWN:GITHUB_TOKEN]
model:  curl -H "Authorization: Bearer [REDACTED:KNOWN:GITHUB_TOKEN]" …
tool:   curl -H "Authorization: Bearer ghp_actualValue…" …       ← restored before execution
```

## Install

```sh
pi install git:github.com/DJRHails/pi-redact
```

No configuration needed. `/redact` in a session shows what is being protected (names only, never values).

## What gets redacted

The process mirrors [palst](https://github.com/safety-research/palst)'s transcript redaction: exact-value replacement of secrets the host *knows*, backed by a small set of structural detectors.

**Known secrets** (`[REDACTED:KNOWN:<NAME>]`), harvested at session start and before every prompt:

- Process environment variables whose **name** contains `KEY`, `TOKEN`, `SECRET`, `PASSWORD`, `PWD` or `COOKIE` (the pi-share-hf heuristic). `PWD`/`OLDPWD` and names ending `_FILE`, `_PATH`, `_DIR`, `_URL`, `_SOCK` are skipped: they point *at* a secret rather than being one.
- `.env` and `.env.*` files in the working directory (minus `.example`/`.sample`/`.template`/`.dist`), plus any files listed in `PI_REDACT_ENV_FILES` (`:`-separated).
- Assignment lines that scroll past in `bash` or `read` tool output (`env`, `cat config/secrets.env`): learned on the spot and redacted from the very next request.

Values shorter than 8 characters, common configuration words (`production`, `disabled`, `localhost`, …) and obvious placeholders (`<your-key>`, `changeme`, `${OTHER_VAR}`) are ignored, so `FEATURE_TOKEN_ENABLED=True` or `SESSION_SECRET_MODE=production` reach the model as written. A value that *is* redacted but is not really a credential, say `INGEST_SECRET_HOST=hails.info`, still works: the model uses the marker inside the URL or command and the real value is substituted before the tool runs (the `hostname-placeholder` scenario checks exactly this). Duplicate values keep the first name that introduced them; a name reused for a different value becomes `NAME#2`.

**Detected credentials** (`[REDACTED:<KIND>:<hash>]`), for values that never passed through a named variable: PEM private-key blocks, AWS access key ids, GitHub tokens, Anthropic and OpenAI keys, Google API keys, Hugging Face tokens, Slack tokens, signed JWTs, and `Authorization: Bearer …` values. The hash is a salted SHA-256 prefix; the salt is minted per session, so the same credential yields the same marker for the whole session (prompt caches stay warm) and a different one anywhere else.

## How it hooks into pi

| direction | hook | what it does |
|---|---|---|
| out | `before_provider_request` | deep-walks the serialized payload (system prompt, messages, tool definitions) and redacts every string; skips signed thinking blocks and base64 image data |
| out | `globalThis.fetch` guard | backstop for provider calls that bypass the hook: compaction summaries, `/tree` branch summaries, and extensions that call `complete()` directly. Scoped to registered provider hosts and to bodies shaped like a chat request |
| in | `message_end` | restores markers in the assistant's text and tool-call arguments, so the stored message, the UI, and the tools see real values |
| in | `tool_call` | restores markers in the mutable tool input as belt-and-braces |
| — | `before_agent_start` | appends one paragraph to the system prompt telling the model what markers are and to use them verbatim |

The marker table lives in memory for one session and is never written to disk.

## Verification

`pnpm check` runs oxlint, `tsc --noEmit`, the unit suite (vault, harvesting, detectors, fetch guard) and the cached end-to-end suite.

**Cached end-to-end tests** (`tests/e2e`) drive a real pi session with the extension loaded, behind a recording proxy, for every high-risk scenario. Provider responses replay from committed cassettes, so the default run is offline, deterministic, and takes about two seconds; the assertions are still made against the bytes the session put on the wire and the effects of restored values (a file written, a local server authenticating). Cassettes hold only markers, never the planted values.

```sh
pnpm test:e2e                     # replay from tests/e2e/cassettes (default)
pnpm test:e2e:record              # re-record against the API (needs ANTHROPIC_API_KEY)
PI_REDACT_E2E=record pnpm test:e2e -t echo-env   # re-record one scenario
```

Determinism comes from `redteam/scenarios.ts`: fixed fake secrets, a fixed working directory per scenario, a fixed check-server port, and a fixed marker salt via `PI_REDACT_SALT` (unset in normal use, where the salt is random per session).

**Live red-team** runs the same scenarios plus the adversarial ones against the API and writes a report:

```sh
node redteam/run.ts --model claude-haiku-4-5 --repeat 3   # → redteam/results/<ts>/report.md
node redteam/degrade.ts --repeat 3                         # same tasks with/without the extension
```

Scenarios cover: env values printed by tools, a curl header round-trip against a local server that only accepts the real token, markers inside `write`-tool arguments, secrets learned from a file the model `cat`s, JSON-escaped passwords, credentials pasted into the prompt, vendor-shaped values under innocuous variable names, booleans and config words that must *not* be redacted, a redacted host:port used inside a URL, and forced compaction. Adversarial cases (base64 re-encoding, printing a value in halves, asking the model to reveal a marker character by character) are included and reported as known limitations.

## Limitations

- **Exact-value matching only.** A value a tool re-encodes (`| base64`, `| xxd`, `| fold -w1`, split in two with `${VAR:0:20}`) is no longer a literal match and will reach the model. palst has the same boundary and backstops it with TruffleHog on archived transcripts. Here the only defence is the model's judgement: in the red-team runs Haiku 4.5 complied with every such request, while Sonnet 5 refused the base64 request in one of two runs and the `fold -w1` request in two of four. Treat this as protection against *accidental* exposure (a `cat .env`, an `env` dump, a token in a log), not against a user or prompt injection determined to exfiltrate.
- **Fragments.** A secret printed in pieces leaks in pieces; the red-team report flags 8-character fragments and character-separated spellings so you can see when it happens.
- **Invented markers.** A model may write a marker that was never minted (`[REDACTED:GENERIC_SECRET:1]`). Restoration leaves unknown markers untouched, so the command runs with the literal marker text: safe, but the result is wrong and worth recognising.
- **Compaction summaries keep markers.** The summary text stored in the session contains markers, not values, since restoration only runs on the main loop's assistant messages. They are restored again whenever they later appear in a reply or tool call.
- **Header-carried API keys are untouched.** The provider's own key travels in request headers, which the extension deliberately does not rewrite.
- **Model chattiness.** Haiku 4.5 tends to append a sentence explaining the redaction even when told not to. Sonnet 5 and Opus follow the instruction.

## Development

```sh
pnpm install
pnpm check
```

Extension entry: `extensions/redact.ts`. Pure logic lives in `src/` (`known-secrets.ts`, `detectors.ts`, `vault.ts`, `fetch-guard.ts`) and is what the unit tests import. pi loads the TypeScript directly; there is no build step.

## License

MIT
