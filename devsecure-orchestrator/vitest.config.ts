// Author: Jeremy Quadri
// vitest.config.ts — Test configuration for DevSecure v4.0 unit tests.
import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    environment: "node",
    globals: true,
    include: ["src/__tests__/**/*.test.ts"],
  },
});
