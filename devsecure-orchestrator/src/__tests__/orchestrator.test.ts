// Author: Jeremy Quadri
// src/__tests__/orchestrator.test.ts — Unit tests for runOrchestrator (direct).

import { describe, it, expect, vi, beforeEach } from "vitest";
import { runOrchestrator } from "../orchestrator";

// ---------------------------------------------------------------------------
// Module mocks
// ---------------------------------------------------------------------------

vi.mock("../parsers/index", () => ({
  parseSarifToFindings: vi.fn().mockReturnValue([]),
}));

vi.mock("../filters/index", () => ({
  runPreFilterPipeline: vi.fn(),
  buildL2BatchPayload:  vi.fn(),
  dispatchToL2:         vi.fn(),
}));

import { runPreFilterPipeline, buildL2BatchPayload, dispatchToL2 } from "../filters/index";

const mockRunPreFilterPipeline = vi.mocked(runPreFilterPipeline);
const mockBuildL2BatchPayload  = vi.mocked(buildL2BatchPayload);
const mockDispatchToL2         = vi.mocked(dispatchToL2);

// ---------------------------------------------------------------------------
// Fixture
// ---------------------------------------------------------------------------

const BASE_INPUT = {
  opengrep_sarif: {},
  bearer_sarif:   {},
  changed_files:  ["src/foo.ts"],
  suppressions:   [],
  config: {
    worker_url:       "https://worker.example.com",
    api_token:        "tok-test",
    pr_ref:           "42",
    commit_sha:       "abc123",
    repository:       "org/repo",
    scanner_versions: { opengrep: "1.0.0", bearer: "2.0.0" },
  },
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe("runOrchestrator — empty batch early exit", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("Returns gracefully without calling buildL2BatchPayload when both arrays are empty", async () => {
    mockRunPreFilterPipeline.mockResolvedValue({
      normalized_findings: [],
      escalation_payloads: [],
      pipeline_stats:      [],
      total_input:         0,
      total_output:        0,
    });

    const result = await runOrchestrator(BASE_INPUT);

    expect(mockBuildL2BatchPayload).not.toHaveBeenCalled();
    expect(mockDispatchToL2).not.toHaveBeenCalled();
    expect(result.total_after_filtering).toBe(0);
    expect(result.total_escalations).toBe(0);
    expect(result.dispatch_result.success).toBe(true);
    expect(result.dispatch_result.status).toBe(204);
  });

  it("Logs the clean-exit audit message when no findings or escalations remain", async () => {
    const logSpy = vi.spyOn(console, "log");

    mockRunPreFilterPipeline.mockResolvedValue({
      normalized_findings: [],
      escalation_payloads: [],
      pipeline_stats:      [],
      total_input:         0,
      total_output:        0,
    });

    await runOrchestrator(BASE_INPUT);

    const logArg  = logSpy.mock.calls[0]?.[0] as string | undefined;
    expect(logArg).toBeDefined();
    const parsed = JSON.parse(logArg!) as Record<string, unknown>;
    expect(parsed["audit"]).toBe("pipeline_complete");
    expect(parsed["message"]).toBe("No findings or escalations to dispatch. Exiting cleanly.");

    logSpy.mockRestore();
  });

  it("Proceeds to dispatch when findings are present", async () => {
    mockRunPreFilterPipeline.mockResolvedValue({
      normalized_findings: [{ id: "f1" } as never],
      escalation_payloads: [],
      pipeline_stats:      [],
      total_input:         1,
      total_output:        1,
    });

    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    mockBuildL2BatchPayload.mockReturnValue({} as any);
    mockDispatchToL2.mockResolvedValue({
      success: true, status: 200, request_id: "req-1", latency_ms: 10, error_message: null,
    });

    await runOrchestrator(BASE_INPUT);

    expect(mockBuildL2BatchPayload).toHaveBeenCalledOnce();
    expect(mockDispatchToL2).toHaveBeenCalledOnce();
  });

  it("Proceeds to dispatch when only escalations are present", async () => {
    mockRunPreFilterPipeline.mockResolvedValue({
      normalized_findings: [],
      escalation_payloads: [{ id: "e1" } as never],
      pipeline_stats:      [],
      total_input:         1,
      total_output:        0,
    });

    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    mockBuildL2BatchPayload.mockReturnValue({} as any);
    mockDispatchToL2.mockResolvedValue({
      success: true, status: 200, request_id: "req-2", latency_ms: 5, error_message: null,
    });

    await runOrchestrator(BASE_INPUT);

    expect(mockBuildL2BatchPayload).toHaveBeenCalledOnce();
    expect(mockDispatchToL2).toHaveBeenCalledOnce();
  });
});
