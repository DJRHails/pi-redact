import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    include: ["tests/**/*.test.ts"],
    // Each file gets its own process: the extension patches `globalThis.fetch`
    // and pi loads extension modules through jiti, so shared workers would
    // leak state between the unit suite and the e2e sessions.
    pool: "forks",
  },
});
