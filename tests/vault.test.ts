import { describe, expect, it } from "vitest";

import { MARKER_PATTERN, RedactionVault, valueSpellings } from "../src/vault.ts";

const TOKEN = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij";
const PASSWORD = 'pa"ss\\word-with-escapes';

function vaultWith(...secrets: Array<[string, string]>): RedactionVault {
  const vault = new RedactionVault({ salt: Buffer.alloc(32, 1) });
  for (const [name, value] of secrets) vault.addKnown({ name, value });
  return vault;
}

describe("valueSpellings", () => {
  it("adds the JSON-escaped form only when it differs", () => {
    expect(valueSpellings("plain")).toEqual(["plain"]);
    expect(valueSpellings(PASSWORD)).toEqual([PASSWORD, String.raw`pa\"ss\\word-with-escapes`]);
  });
});

describe("RedactionVault.redactText", () => {
  it("replaces known values with named markers and restores them", () => {
    const vault = vaultWith(["GITHUB_TOKEN", TOKEN]);
    const redacted = vault.redactText(`curl -H "Authorization: token ${TOKEN}" https://api.github.com`);
    expect(redacted).toBe('curl -H "Authorization: token [REDACTED:KNOWN:GITHUB_TOKEN]" https://api.github.com');
    expect(redacted).not.toContain(TOKEN);
    expect(vault.restoreText(redacted)).toContain(TOKEN);
  });

  it("matches the JSON-escaped spelling inside serialized text", () => {
    const vault = vaultWith(["DB_PASSWORD", PASSWORD]);
    const serialized = JSON.stringify({ password: PASSWORD, note: PASSWORD });
    const redacted = vault.redactText(serialized);
    expect(redacted).toBe('{"password":"[REDACTED:KNOWN:DB_PASSWORD]","note":"[REDACTED:KNOWN:DB_PASSWORD]"}');
  });

  it("replaces longest values first so an embedded secret never splits a longer one", () => {
    const short = "shortsecret1";
    const long = `https://user:${short}@example.com/path`;
    const vault = vaultWith(["SHORT_TOKEN", short], ["LONG_URL_TOKEN", long]);
    expect(vault.redactText(`see ${long} and ${short}`)).toBe(
      "see [REDACTED:KNOWN:LONG_URL_TOKEN] and [REDACTED:KNOWN:SHORT_TOKEN]",
    );
  });

  it("keeps the first name for a duplicate value and suffixes a reused name", () => {
    const vault = vaultWith(["A_TOKEN", "value-one-1"], ["B_TOKEN", "value-one-1"], ["A_TOKEN", "value-two-2"]);
    expect(vault.size).toBe(2);
    expect(vault.redactText("value-one-1 value-two-2")).toBe("[REDACTED:KNOWN:A_TOKEN] [REDACTED:KNOWN:A_TOKEN#2]");
    expect(vault.restoreText("[REDACTED:KNOWN:A_TOKEN#2]/[REDACTED:KNOWN:A_TOKEN]")).toBe("value-two-2/value-one-1");
  });

  it("mints stable salted markers for detected values and remembers them", () => {
    const vault = vaultWith();
    const first = vault.redactText(`key: ${TOKEN}`);
    const second = vault.redactText(`again ${TOKEN}`);
    const marker = first.slice("key: ".length);
    expect(marker).toMatch(/^\[REDACTED:GITHUB:[0-9a-f]{8}\]$/);
    expect(second).toBe(`again ${marker}`);
    expect(vault.restoreText(second)).toBe(`again ${TOKEN}`);
    expect(vault.size).toBe(1);
  });

  it("uses a different hash under a different salt", () => {
    const a = new RedactionVault({ salt: Buffer.alloc(32, 1) }).redactText(TOKEN);
    const b = new RedactionVault({ salt: Buffer.alloc(32, 2) }).redactText(TOKEN);
    expect(a).not.toBe(b);
  });

  it("is idempotent over already-redacted text and leaves unknown markers alone", () => {
    const vault = vaultWith(["GITHUB_TOKEN", TOKEN]);
    const once = vault.redactText(TOKEN);
    expect(vault.redactText(once)).toBe(once);
    expect(vault.restoreText("[REDACTED:KNOWN:NOT_IN_VAULT] stays")).toBe("[REDACTED:KNOWN:NOT_IN_VAULT] stays");
  });

  it("counts replacements and restorations", () => {
    const vault = vaultWith(["GITHUB_TOKEN", TOKEN]);
    vault.restoreText(vault.redactText(`${TOKEN} ${TOKEN}`));
    expect(vault.stats).toEqual({ redacted: 2, restored: 2 });
  });

  it("rejects an empty value, which would otherwise match everywhere", () => {
    expect(() => vaultWith(["EMPTY_TOKEN", ""])).toThrow(/empty value/);
  });
});

describe("RedactionVault deep walks", () => {
  const image = "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNkYPhfDwAChwGA60e6kgAAAABJRU5ErkJggg==";

  it("redacts every string in a payload except signed and binary blocks", () => {
    const vault = vaultWith(["GITHUB_TOKEN", TOKEN]);
    const payload = {
      model: "claude-haiku-4-5",
      system: [{ type: "text", text: `token ${TOKEN}` }],
      messages: [
        {
          role: "user",
          content: [
            { type: "text", text: `use ${TOKEN}` },
            { type: "image", source: { type: "base64", media_type: "image/png", data: image } },
            { type: "thinking", thinking: `t ${TOKEN}`, signature: `sig-${TOKEN}` },
            { type: "image_url", image_url: { url: `data:image/png;base64,${image}` } },
          ],
        },
      ],
      tools: [{ name: "bash", description: `never ${TOKEN}`, input_schema: { properties: { command: { type: "string" } } } }],
    };
    const redacted = vault.redactValue(payload);
    const serialized = JSON.stringify(redacted);
    expect(serialized).not.toContain(`token ${TOKEN}`);
    expect(serialized).not.toContain(`use ${TOKEN}`);
    expect(serialized).not.toContain(`t ${TOKEN}`);
    expect(serialized).not.toContain(`never ${TOKEN}`);
    expect(redacted.messages[0].content[2]).toMatchObject({ signature: `sig-${TOKEN}` });
    expect(redacted.messages[0].content[1]).toMatchObject({ source: { data: image } });
    expect(redacted.messages[0].content[3]).toMatchObject({ image_url: { url: `data:image/png;base64,${image}` } });
    expect(payload.system[0].text, "input is not mutated").toContain(TOKEN);
  });

  it("restores markers in place inside a mutable tool input", () => {
    const vault = vaultWith(["GITHUB_TOKEN", TOKEN]);
    const input = { command: "gh auth login --with-token <<< [REDACTED:KNOWN:GITHUB_TOKEN]", nested: { list: ["[REDACTED:KNOWN:GITHUB_TOKEN]"] } };
    vault.restoreInPlace(input);
    expect(input.command).toBe(`gh auth login --with-token <<< ${TOKEN}`);
    expect(input.nested.list[0]).toBe(TOKEN);
  });

  it("redacts a serialized JSON body structurally and a non-JSON body textually", () => {
    const vault = vaultWith(["DB_PASSWORD", PASSWORD]);
    const body = JSON.stringify({ messages: [{ role: "user", content: `pw ${PASSWORD}` }] });
    expect(JSON.parse(vault.redactSerialized(body))).toEqual({
      messages: [{ role: "user", content: "pw [REDACTED:KNOWN:DB_PASSWORD]" }],
    });
    expect(vault.redactSerialized(`plain ${PASSWORD}`)).toBe("plain [REDACTED:KNOWN:DB_PASSWORD]");
  });
});

describe("MARKER_PATTERN", () => {
  it("matches both marker shapes and nothing looser", () => {
    const matches = (text: string): string[] => {
      MARKER_PATTERN.lastIndex = 0;
      return [...text.matchAll(MARKER_PATTERN)].map((m) => m[0]);
    };
    expect(matches("[REDACTED:KNOWN:API_KEY] [REDACTED:GITHUB:0badf00d] [REDACTED:KNOWN:A#2]")).toHaveLength(3);
    expect(matches("[REDACTED] [redacted:known:x] [REDACTED:KNOWN:]")).toEqual([]);
  });
});
