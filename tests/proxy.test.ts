import { homedir, tmpdir } from "node:os";
import { resolve } from "node:path";

import { describe, expect, it, vi } from "vitest";

import { type MachineRoot, normaliseMachinePaths, requestKey } from "../redteam/proxy.ts";

const PATH = "/v1/messages?beta=true";
const CHECKOUT = resolve(import.meta.dirname, "..");

function systemPrompt(repo: string, tmp: string): string {
  return JSON.stringify({
    system: `Docs: ${repo}/node_modules/pi/README.md\nCurrent working directory: ${tmp}/pi-redact-e2e/echo-env`,
  });
}

function rootsOf(repo: string, tmp: string, home: string): MachineRoot[] {
  return [
    { dir: repo, placeholder: "<repo>" },
    { dir: tmp, placeholder: "<tmp>" },
    { dir: home, placeholder: "<home>" },
  ];
}

describe("requestKey", () => {
  it("is the same for one request recorded on two machines at different paths", () => {
    const recorder = rootsOf("/home/dev/work/pi-redact", "/tmp", "/home/dev");
    const clone = rootsOf("/Users/someone/src/pi-redact", "/var/folders/xy/T", "/Users/someone");
    const recorded = requestKey(PATH, systemPrompt("/home/dev/work/pi-redact", "/tmp"), recorder);
    const replayed = requestKey(PATH, systemPrompt("/Users/someone/src/pi-redact", "/var/folders/xy/T"), clone);
    expect(replayed).toBe(recorded);
  });

  it("normalises this checkout and temp dir by default", () => {
    const here = requestKey(PATH, systemPrompt(CHECKOUT, tmpdir()));
    expect(here).toBe(requestKey(PATH, systemPrompt("<repo>", "<tmp>")));
  });

  it("still distinguishes requests that differ outside the machine paths", () => {
    const roots = rootsOf("/r", "/t", "/h");
    expect(requestKey(PATH, `${systemPrompt("/r", "/t")}a`, roots)).not.toBe(
      requestKey(PATH, `${systemPrompt("/r", "/t")}b`, roots),
    );
  });
});

describe("normaliseMachinePaths", () => {
  it("prefers the checkout over a home dir that contains it", () => {
    const roots = rootsOf("/home/d/projects/pi-redact", "/tmp", "/home/d");
    expect(normaliseMachinePaths("/home/d/projects/pi-redact/x and /home/d/.config", roots)).toBe(
      "<repo>/x and <home>/.config",
    );
  });

  it("only replaces whole path segments", () => {
    const roots = rootsOf("/home/d/pi-redact", "/tmp", "/home/d");
    expect(normaliseMachinePaths("/tmpfoo /tmp/a /home/d/pi-redact-old", roots)).toBe(
      "/tmpfoo <tmp>/a <home>/pi-redact-old",
    );
  });

  it("never treats the filesystem root as a machine root", () => {
    expect(normaliseMachinePaths("/usr/bin and /tmp/x", rootsOf("/r", "/tmp", "/"))).toBe("/usr/bin and <tmp>/x");
  });

  it("covers the home dir of the running machine", () => {
    expect(normaliseMachinePaths(`${homedir()}/.pi/agent`)).not.toContain(homedir());
  });

  it("treats /tmp and TMPDIR alike, so a replayed reply naming the recorder's /tmp cwd still matches", () => {
    vi.stubEnv("TMPDIR", "/var/folders/xy/T");
    try {
      expect(normaliseMachinePaths("cwd /var/folders/xy/T/pi-redact-e2e, reply /tmp/pi-redact-e2e")).toBe(
        "cwd <tmp>/pi-redact-e2e, reply <tmp>/pi-redact-e2e",
      );
    } finally {
      vi.unstubAllEnvs();
    }
  });
});
