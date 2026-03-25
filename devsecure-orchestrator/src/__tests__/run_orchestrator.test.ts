// Author: Jeremy Quadri
// src/__tests__/run_orchestrator.test.ts — Unit tests for the GitHub Actions entry script.

import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { readFileSync } from "fs";
import { load as loadYaml } from "js-yaml";
import { runOrchestrator } from "../orchestrator";
import type { OrchestratorResult } from "../orchestrator";
import type { SuppressionEntry } from "../types";

// ---------------------------------------------------------------------------
// Module mocks (hoisted before imports by vitest)
// ---------------------------------------------------------------------------

vi.mock("fs", () => ({
  readFileSync: vi.fn(),
}));

vi.mock("js-yaml", () => ({
  load: vi.fn(),
}));

vi.mock("../orchestrator", () => ({
  runOrchestrator: vi.fn(),
}));

// Import the function-under-test AFTER mocks are registered
const { main } = await import("../../scripts/run-orchestrator");

// ---------------------------------------------------------------------------
// Typed mock handles
// ---------------------------------------------------------------------------

const mockReadFileSync  = vi.mocked(readFileSync);
const mockLoadYaml      = vi.mocked(loadYaml);
const mockRunOrchestrator = vi.mocked(runOrchestrator);

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

const EMPTY_SARIF = JSON.stringify({
  version: "2.1.0",
  runs: [{ tool: { driver: { name: "test", rules: [] } }, results: [] }],
});

const CHANGED_FILES_TEXT = "src/foo.ts\nsrc/bar.ts\n";

function makeSuccessResult(): OrchestratorResult {
  return {
    dispatch_result: {
      success:       true,
      status:        200,
      request_id:    "req-abc-123",
      latency_ms:    45,
      error_message: null,
    },
    pipeline_stats:        [],
    total_raw_findings:    3,
    total_after_filtering: 2,
    total_escalations:     0,
  };
}

function makeFailResult(): OrchestratorResult {
  return {
    ...makeSuccessResult(),
    dispatch_result: {
      success:       false,
      status:        503,
      request_id:    null,
      latency_ms:    12,
      error_message: "Service Unavailable",
    },
  };
}

/** Default readFileSync mock: returns SARIF for .sarif paths, file list otherwise. */
function defaultReadFileSyncImpl(path: Parameters<typeof readFileSync>[0]): string {
  const p = String(path);
  if (p.endsWith("opengrep.sarif")) return EMPTY_SARIF;
  if (p.endsWith("bearer.sarif"))   return EMPTY_SARIF;
  return CHANGED_FILES_TEXT;
}

// ---------------------------------------------------------------------------
// Test environment helpers
// ---------------------------------------------------------------------------

type EnvSnapshot = Record<string, string | undefined>;

const ENV_KEYS = [
  "OPENGREP_SARIF", "BEARER_SARIF", "CHANGED_FILES", "SUPPRESSIONS_FILE",
  "DEVSECURE_WORKER_URL", "DEVSECURE_API_TOKEN", "PR_REF", "COMMIT_SHA",
  "REPOSITORY", "OPENGREP_VERSION", "BEARER_VERSION",
] as const;

function snapshotEnv(): EnvSnapshot {
  return Object.fromEntries(ENV_KEYS.map((k) => [k, process.env[k]]));
}

function restoreEnv(snapshot: EnvSnapshot): void {
  for (const k of ENV_KEYS) {
    if (snapshot[k] === undefined) delete process.env[k];
    else process.env[k] = snapshot[k];
  }
}

function setDefaultEnv(): void {
  process.env.OPENGREP_SARIF        = "/tmp/results/opengrep.sarif";
  process.env.BEARER_SARIF          = "/tmp/results/bearer.sarif";
  process.env.CHANGED_FILES         = "/tmp/changed_files.txt";
  process.env.SUPPRESSIONS_FILE     = "";
  process.env.DEVSECURE_WORKER_URL  = "https://worker.example.com/remediate";
  process.env.DEVSECURE_API_TOKEN   = "test-api-token";
  process.env.PR_REF                = "42";
  process.env.COMMIT_SHA            = "deadbeef1234";
  process.env.REPOSITORY            = "org/repo";
  process.env.OPENGREP_VERSION      = "1.96.0";
  process.env.BEARER_VERSION        = "2.3.0";
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe("run-orchestrator entry script", () => {
  let envSnapshot: EnvSnapshot;
  // Typed as vi.fn return to avoid the `never` return-type constraint on process.exit
  let exitSpy: ReturnType<typeof vi.fn>;

  beforeEach(() => {
    envSnapshot = snapshotEnv();
    setDefaultEnv();

    // Prevent process.exit from actually exiting during tests
    exitSpy = vi.spyOn(process, "exit").mockImplementation(
      (() => undefined) as () => never,
    );

    // Default mock implementations
    (mockReadFileSync as ReturnType<typeof vi.fn>).mockImplementation(
      defaultReadFileSyncImpl,
    );
    mockRunOrchestrator.mockResolvedValue(makeSuccessResult());
  });

  afterEach(() => {
    restoreEnv(envSnapshot);
    vi.restoreAllMocks();
  });

  // ── Test 1 ──────────────────────────────────────────────────────────────
  it("Reads SARIF files from environment variable paths", async () => {
    await main();

    expect(mockReadFileSync).toHaveBeenCalledWith(
      "/tmp/results/opengrep.sarif",
      "utf-8",
    );
    expect(mockReadFileSync).toHaveBeenCalledWith(
      "/tmp/results/bearer.sarif",
      "utf-8",
    );
  });

  // ── Test 2 ──────────────────────────────────────────────────────────────
  it("Parses changed files from newline-separated text file", async () => {
    await main();

    expect(mockRunOrchestrator).toHaveBeenCalledWith(
      expect.objectContaining({
        changed_files: ["src/foo.ts", "src/bar.ts"],
      }),
    );
  });

  // ── Test 3 ──────────────────────────────────────────────────────────────
  it("Uses empty suppressions array when SUPPRESSIONS_FILE is empty", async () => {
    process.env.SUPPRESSIONS_FILE = "";

    await main();

    expect(mockLoadYaml).not.toHaveBeenCalled();
    expect(mockRunOrchestrator).toHaveBeenCalledWith(
      expect.objectContaining({ suppressions: [] }),
    );
  });

  // ── Test 4 ──────────────────────────────────────────────────────────────
  it("Parses YAML suppressions file when SUPPRESSIONS_FILE is set", async () => {
    process.env.SUPPRESSIONS_FILE = ".devsecure-ignore.yml";

    const fakeSuppressions: SuppressionEntry[] = [
      {
        rule_id:      "semgrep.sql.injection",
        cwe_id:       "CWE-89",
        file_pattern: "tests/fixtures/**",
        reason:       "Test fixture — not production code",
        approved_by:  "@security-lead",
        expires_at:   null,
        created_at:   "2026-01-01T00:00:00.000Z",
      },
    ];

    (mockReadFileSync as ReturnType<typeof vi.fn>).mockImplementation(
      (path: Parameters<typeof readFileSync>[0]) => {
        const p = String(path);
        if (p === ".devsecure-ignore.yml") return "- rule_id: semgrep.sql.injection";
        return defaultReadFileSyncImpl(path as Parameters<typeof readFileSync>[0]);
      },
    );
    mockLoadYaml.mockReturnValue(fakeSuppressions as unknown as ReturnType<typeof loadYaml>);

    await main();

    expect(mockReadFileSync).toHaveBeenCalledWith(".devsecure-ignore.yml", "utf-8");
    expect(mockLoadYaml).toHaveBeenCalledWith("- rule_id: semgrep.sql.injection");
    expect(mockRunOrchestrator).toHaveBeenCalledWith(
      expect.objectContaining({ suppressions: fakeSuppressions }),
    );
  });

  // ── Test 5 ──────────────────────────────────────────────────────────────
  it("Calls process.exit(1) when dispatch fails", async () => {
    mockRunOrchestrator.mockResolvedValue(makeFailResult());

    await main();

    expect(exitSpy).toHaveBeenCalledWith(1);
  });

  // ── Test 6 ──────────────────────────────────────────────────────────────
  it("Exits cleanly (code 0) on successful dispatch", async () => {
    mockRunOrchestrator.mockResolvedValue(makeSuccessResult());

    await main();

    expect(exitSpy).not.toHaveBeenCalledWith(1);
  });
});
