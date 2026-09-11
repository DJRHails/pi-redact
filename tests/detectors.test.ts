import { describe, expect, it } from "vitest";

import { detectSecrets } from "../src/detectors.ts";

const JWT_HEADER = Buffer.from(JSON.stringify({ alg: "HS256", typ: "JWT" })).toString("base64url");
const JWT_PAYLOAD = Buffer.from(JSON.stringify({ sub: "1234567890", name: "Test" })).toString("base64url");
const JWT = `${JWT_HEADER}.${JWT_PAYLOAD}.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c`;
// Assembled at runtime so the literal never sits in the file: GitHub push protection
// rejects a commit containing a Slack-shaped token even in a test fixture.
const SLACK_TOKEN = ["xoxb", "1234567890", "1234567890123", "abcdefghijklmnopqrstuvwx"].join("-");

describe("detectSecrets", () => {
  it("finds vendor-prefixed credentials by kind", () => {
    const text = [
      "aws: AKIAIOSFODNN7EXAMPLE",
      "gh: ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij",
      "fine-grained: github_pat_11ABCDEFG0123456789_abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789",
      "anthropic: sk-ant-api03-abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789",
      "openai: sk-proj-abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOP",
      "google: AIzaSyA1234567890abcdefghijklmnopqrstuv",
      "hf: hf_abcdefghijklmnopqrstuvwxyzABCDEFGHIJ",
      `slack: ${SLACK_TOKEN}`,
      `jwt: ${JWT}`,
      "curl -H 'Authorization: Bearer opaque.bearer.token-value-12345'",
    ].join("\n");
    const kinds = detectSecrets(text).map((d) => d.kind);
    expect(kinds).toEqual([
      "AWS",
      "GITHUB",
      "GITHUB",
      "ANTHROPIC",
      "OPENAI",
      "GOOGLE",
      "HUGGINGFACE",
      "SLACK",
      "JWT",
      "BEARER",
    ]);
  });

  it("attributes sk-ant- keys to Anthropic, not the generic OpenAI rule", () => {
    const value = "sk-ant-api03-abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    expect(detectSecrets(`key=${value}`)).toEqual([{ kind: "ANTHROPIC", value }]);
  });

  it("captures a whole PEM block", () => {
    const pem = "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAA\nQyNTUxOQAAACA=\n-----END OPENSSH PRIVATE KEY-----";
    expect(detectSecrets(`file:\n${pem}\ndone`)).toEqual([{ kind: "PRIVATE_KEY", value: pem }]);
  });

  it("rejects JWT-shaped strings whose header is not a JWT header", () => {
    const bogus = `eyJub3RhandGhlYWRlcnh4.${JWT_PAYLOAD}.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c`;
    expect(detectSecrets(bogus)).toEqual([]);
  });

  it("captures only the token from a Bearer header and skips already-redacted ones", () => {
    expect(detectSecrets("Authorization: Bearer abcdefghijklmnopqrstuvwxyz")).toEqual([
      { kind: "BEARER", value: "abcdefghijklmnopqrstuvwxyz" },
    ]);
    expect(detectSecrets("Authorization: Bearer [REDACTED:KNOWN:GITHUB_TOKEN]")).toEqual([]);
  });

  it("ignores ordinary prose and short prefixes", () => {
    expect(detectSecrets("The sk-8 sneaker and the AKIA prefix are not keys; bearer of bad news.")).toEqual([]);
  });
});
