import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { delimiter, join } from "node:path";

import { describe, expect, it } from "vitest";

import {
  ENV_FILES_VAR,
  discoverEnvFiles,
  harvestKnownSecrets,
  isPlausibleSecretValue,
  looksSensitiveName,
  parseAssignments,
} from "../src/known-secrets.ts";

describe("looksSensitiveName", () => {
  it("matches the pi-share-hf name tokens case-insensitively", () => {
    for (const name of ["API_KEY", "github_token", "DbSecret", "PASSWORD", "DB_PWD", "SESSION_COOKIE"]) {
      expect(looksSensitiveName(name), name).toBe(true);
    }
  });

  it("rejects shell cwd variables and pointer-suffixed names", () => {
    for (const name of ["PWD", "OLDPWD", "SOPS_AGE_SSH_PRIVATE_KEY_FILE", "KEY_PATH", "TOKEN_URL", "SSH_KEY_DIR"]) {
      expect(looksSensitiveName(name), name).toBe(false);
    }
  });

  it("ignores names with no sensitive token", () => {
    expect(looksSensitiveName("HOME")).toBe(false);
    expect(looksSensitiveName("GANTRY_TASK")).toBe(false);
  });
});

describe("isPlausibleSecretValue", () => {
  it("drops short values that would shred ordinary text", () => {
    expect(isPlausibleSecretValue("false")).toBe(false);
    expect(isPlausibleSecretValue("1234567")).toBe(false);
    expect(isPlausibleSecretValue("12345678")).toBe(true);
  });

  it("leaves booleans and configuration words alone even under a sensitive name", () => {
    for (const value of ["True", "false", "production", "Disabled", "localhost"]) {
      expect(isPlausibleSecretValue(value), value).toBe(false);
    }
    expect(parseAssignments("FEATURE_TOKEN_ENABLED=True\nSESSION_SECRET_MODE=production\nAPI_KEY_HOST=hails.info")).toEqual([
      { name: "API_KEY_HOST", value: "hails.info" },
    ]);
  });

  it("drops obvious placeholders and shell references", () => {
    for (const value of ["<your-key>", "your_api_key_here", "changeme-now", "xxxxxxxxxxxx", "${OTHER_VAR}", "$OTHER_VAR"]) {
      expect(isPlausibleSecretValue(value), value).toBe(false);
    }
    expect(isPlausibleSecretValue("ghp_realLookingToken1234567890")).toBe(true);
  });
});

describe("parseAssignments", () => {
  it("accepts export, bare, quoted and comment-terminated forms", () => {
    const text = [
      "export API_KEY=plain-value-1",
      "DB_PASSWORD='single quoted' # trailing comment",
      'GITHUB_TOKEN="double # not a comment"',
      "SESSION_SECRET=bare-value # comment",
      "NOT_SENSITIVE=some-long-value",
      "SHORT_TOKEN=abc",
      "# API_KEY=commented-out-value",
    ].join("\n");
    expect(parseAssignments(text)).toEqual([
      { name: "API_KEY", value: "plain-value-1" },
      { name: "DB_PASSWORD", value: "single quoted" },
      { name: "GITHUB_TOKEN", value: "double # not a comment" },
      { name: "SESSION_SECRET", value: "bare-value" },
    ]);
  });

  it("parses `env` output with leading whitespace and no export", () => {
    expect(parseAssignments("  HF_TOKEN=hf_abcdefghijklmnopqrstuvwxyz0123456789\n")).toEqual([
      { name: "HF_TOKEN", value: "hf_abcdefghijklmnopqrstuvwxyz0123456789" },
    ]);
  });
});

describe("harvestKnownSecrets", () => {
  it("collects cwd .env files, configured files and the environment, first name wins", () => {
    const cwd = mkdtempSync(join(tmpdir(), "pi-redact-"));
    writeFileSync(join(cwd, ".env"), "FILE_TOKEN=from-dotenv-file\nSHARED_SECRET=same-value-twice\n");
    writeFileSync(join(cwd, ".env.example"), "EXAMPLE_TOKEN=should-be-ignored-entirely\n");
    const extra = join(cwd, "extra.conf");
    writeFileSync(extra, "export EXTRA_PASSWORD=from-extra-file\n");

    const env: NodeJS.ProcessEnv = {
      [ENV_FILES_VAR]: [extra, join(cwd, "missing.conf")].join(delimiter),
      ENV_API_KEY: "  from-process-env  ",
      DUPLICATE_SECRET: "same-value-twice",
      HOME: "/home/someone",
      TOKENIZERS_PARALLELISM: "false",
    };

    const secrets = harvestKnownSecrets({ cwd, env });
    expect(secrets).toEqual([
      { name: "FILE_TOKEN", value: "from-dotenv-file" },
      { name: "SHARED_SECRET", value: "same-value-twice" },
      { name: "EXTRA_PASSWORD", value: "from-extra-file" },
      { name: "ENV_API_KEY", value: "from-process-env" },
    ]);
    expect(discoverEnvFiles(cwd)).toEqual([join(cwd, ".env")]);
  });

  it("returns nothing for an unreadable cwd", () => {
    expect(harvestKnownSecrets({ cwd: "/nonexistent/dir", env: {} })).toEqual([]);
  });
});
