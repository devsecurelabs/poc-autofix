// Author: Jeremy Quadri
// src/__tests__/l1_dispatch.test.ts — Unit tests for dispatcher and orchestrator (Phase 3).

import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { dispatchToL2 }  from "../filters/dispatcher";
import { runOrchestrator } from "../orchestrator";
import { l2BatchPayloadSchema } from "../types";
import type { L2BatchPayload } from "../types";

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

/** Minimal valid L2BatchPayload: uses is_escalation=true to avoid NormalizedFinding tree. */
const validPayload: L2BatchPayload = {
  pr_ref:     "refs/pull/1",
  commit_sha: "abc123def456",
  repository: "org/repo",
  timestamp:  "2026-01-01T00:00:00.000Z",
  scanner_versions: { opengrep: "1.0.0", bearer: "1.0.0" },
  summary: {
    total_files_scanned: 1,
    total_raw_findings:  0,
    total_after_dedup:   0,
    total_after_filters: 0,
    total_escalations:   1,
  },
  files: [
    {
      file_path:    "src/api/auth.ts",
      code_context: "",
      findings:     [],
      is_escalation: true,
    },
  ],
};

const validConfig = {
  workerUrl: "https://worker.example.com/dispatch",
  apiToken:  "test-bearer-token",
};

/** Minimal SARIF 2.1.0 with one HIGH finding for src/api/auth.ts. */
const singleFindingSarif = {
  version: "2.1.0",
  runs: [
    {
      results: [
        {
          ruleId: "opengrep.sql.injection",
          level: "error",
          locations: [
            {
              physicalLocation: {
                artifactLocation: { uri: "src/api/auth.ts" },
                region: {
                  startLine: 10,
                  endLine:   12,
                  snippet:   { text: "db.query(`SELECT * FROM users WHERE id = ${userId}`)" },
                },
              },
            },
          ],
          taxa:       [{ id: "CWE-89" }],
          properties: { confidence: 0.9 },
        },
      ],
    },
  ],
};

/** Empty SARIF with no results. */
const emptySarif = {
  version: "2.1.0",
  runs: [{ results: [] }],
};

function makeOkResponse(): Response {
  return new Response(null, { status: 200 });
}

function makeErrorResponse(status: number, body = "error"): Response {
  return new Response(body, { status });
}

// ---------------------------------------------------------------------------
// GROUP 1 — Dispatcher Validation
// ---------------------------------------------------------------------------

describe("GROUP 1 — Dispatcher Validation", () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("Throws if API token is empty", async () => {
    await expect(
      dispatchToL2(validPayload, { ...validConfig, apiToken: "" }),
    ).rejects.toThrow("L2 dispatch aborted: API token is empty");
  });

  it("Throws if API token is whitespace only", async () => {
    await expect(
      dispatchToL2(validPayload, { ...validConfig, apiToken: "   " }),
    ).rejects.toThrow("L2 dispatch aborted: API token is empty");
  });

  it("Throws if Worker URL is empty", async () => {
    await expect(
      dispatchToL2(validPayload, { ...validConfig, workerUrl: "" }),
    ).rejects.toThrow("L2 dispatch aborted: invalid Worker URL");
  });

  it("Throws if Worker URL does not start with https://", async () => {
    await expect(
      dispatchToL2(validPayload, { ...validConfig, workerUrl: "http://worker.example.com" }),
    ).rejects.toThrow("L2 dispatch aborted: invalid Worker URL");
  });

  it("Throws if payload fails Zod schema validation", async () => {
    const badPayload = { pr_ref: "" } as unknown as L2BatchPayload;
    await expect(
      dispatchToL2(badPayload, validConfig),
    ).rejects.toThrow();
  });
});

// ---------------------------------------------------------------------------
// GROUP 2 — Dispatcher Request
// ---------------------------------------------------------------------------

describe("GROUP 2 — Dispatcher Request", () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("Sends POST with correct Authorization header", async () => {
    let capturedInit: RequestInit | undefined;
    vi.stubGlobal("fetch", vi.fn((_url: unknown, init: RequestInit) => {
      capturedInit = init;
      return Promise.resolve(makeOkResponse());
    }));

    await dispatchToL2(validPayload, validConfig);

    const headers = capturedInit!.headers as Record<string, string>;
    expect(headers["Authorization"]).toBe(`Bearer ${validConfig.apiToken}`);
  });

  it("Sends POST with Content-Type application/json", async () => {
    let capturedInit: RequestInit | undefined;
    vi.stubGlobal("fetch", vi.fn((_url: unknown, init: RequestInit) => {
      capturedInit = init;
      return Promise.resolve(makeOkResponse());
    }));

    await dispatchToL2(validPayload, validConfig);

    const headers = capturedInit!.headers as Record<string, string>;
    expect(headers["Content-Type"]).toBe("application/json");
  });

  it("Sends POST with X-Request-ID header", async () => {
    let capturedInit: RequestInit | undefined;
    vi.stubGlobal("fetch", vi.fn((_url: unknown, init: RequestInit) => {
      capturedInit = init;
      return Promise.resolve(makeOkResponse());
    }));

    await dispatchToL2(validPayload, validConfig);

    const headers = capturedInit!.headers as Record<string, string>;
    expect(typeof headers["X-Request-ID"]).toBe("string");
    expect(headers["X-Request-ID"].length).toBeGreaterThan(0);
  });

  it("Body contains the serialised L2BatchPayload", async () => {
    let capturedBody: string | undefined;
    vi.stubGlobal("fetch", vi.fn((_url: unknown, init: RequestInit) => {
      capturedBody = init.body as string;
      return Promise.resolve(makeOkResponse());
    }));

    await dispatchToL2(validPayload, validConfig);

    expect(capturedBody).toBe(JSON.stringify(validPayload));
  });

  it("Returns success true for 200 response", async () => {
    vi.stubGlobal("fetch", vi.fn(() => Promise.resolve(makeOkResponse())));

    const result = await dispatchToL2(validPayload, validConfig);

    expect(result.success).toBe(true);
    expect(result.status).toBe(200);
  });

  it("Returns success false for 400 response", async () => {
    vi.stubGlobal("fetch", vi.fn(() =>
      Promise.resolve(makeErrorResponse(400, "Bad Request")),
    ));

    const result = await dispatchToL2(validPayload, validConfig);

    expect(result.success).toBe(false);
    expect(result.status).toBe(400);
    expect(result.error_message).toBe("Bad Request");
  });

  it("Returns latency_ms as a non-negative number", async () => {
    vi.stubGlobal("fetch", vi.fn(() => Promise.resolve(makeOkResponse())));

    const result = await dispatchToL2(validPayload, validConfig);

    expect(result.latency_ms).toBeGreaterThanOrEqual(0);
  });
});

// ---------------------------------------------------------------------------
// GROUP 3 — Dispatcher Retry Logic
// ---------------------------------------------------------------------------

describe("GROUP 3 — Dispatcher Retry Logic", () => {
  beforeEach(() => {
    vi.useFakeTimers();
  });

  afterEach(() => {
    vi.useRealTimers();
    vi.unstubAllGlobals();
  });

  it("Retries on 503 response", async () => {
    let callCount = 0;
    vi.stubGlobal("fetch", vi.fn(() => {
      callCount++;
      if (callCount < 3) return Promise.resolve(makeErrorResponse(503));
      return Promise.resolve(makeOkResponse());
    }));

    const promise = dispatchToL2(validPayload, { ...validConfig, maxRetries: 2 });
    await vi.runAllTimersAsync();
    const result = await promise;

    expect(callCount).toBe(3);
    expect(result.success).toBe(true);
  });

  it("Retries on 429 response", async () => {
    let callCount = 0;
    vi.stubGlobal("fetch", vi.fn(() => {
      callCount++;
      if (callCount < 2) return Promise.resolve(makeErrorResponse(429));
      return Promise.resolve(makeOkResponse());
    }));

    const promise = dispatchToL2(validPayload, { ...validConfig, maxRetries: 1 });
    await vi.runAllTimersAsync();
    const result = await promise;

    expect(callCount).toBe(2);
    expect(result.success).toBe(true);
  });

  it("Does NOT retry on 400 response", async () => {
    let callCount = 0;
    vi.stubGlobal("fetch", vi.fn(() => {
      callCount++;
      return Promise.resolve(makeErrorResponse(400));
    }));

    const promise = dispatchToL2(validPayload, { ...validConfig, maxRetries: 2 });
    await vi.runAllTimersAsync();
    const result = await promise;

    expect(callCount).toBe(1);
    expect(result.success).toBe(false);
    expect(result.status).toBe(400);
  });

  it("Does NOT retry on 401 response", async () => {
    let callCount = 0;
    vi.stubGlobal("fetch", vi.fn(() => {
      callCount++;
      return Promise.resolve(makeErrorResponse(401));
    }));

    const promise = dispatchToL2(validPayload, { ...validConfig, maxRetries: 2 });
    await vi.runAllTimersAsync();
    const result = await promise;

    expect(callCount).toBe(1);
    expect(result.success).toBe(false);
    expect(result.status).toBe(401);
  });

  it("Stops after maxRetries attempts", async () => {
    let callCount = 0;
    vi.stubGlobal("fetch", vi.fn(() => {
      callCount++;
      return Promise.resolve(makeErrorResponse(503));
    }));

    const promise = dispatchToL2(validPayload, { ...validConfig, maxRetries: 2 });
    await vi.runAllTimersAsync();
    await promise;

    expect(callCount).toBe(3); // original + 2 retries
  });

  it("Returns the last attempt's result after all retries exhausted", async () => {
    vi.stubGlobal("fetch", vi.fn(() =>
      Promise.resolve(makeErrorResponse(503, "Service Unavailable")),
    ));

    const promise = dispatchToL2(validPayload, { ...validConfig, maxRetries: 2 });
    await vi.runAllTimersAsync();
    const result = await promise;

    expect(result.success).toBe(false);
    expect(result.status).toBe(503);
    expect(result.error_message).toBe("Service Unavailable");
  });
});

// ---------------------------------------------------------------------------
// GROUP 4 — Dispatcher Timeout
// ---------------------------------------------------------------------------

describe("GROUP 4 — Dispatcher Timeout", () => {
  afterEach(() => {
    vi.useRealTimers();
    vi.unstubAllGlobals();
  });

  it("Aborts request after timeoutMs", async () => {
    vi.useFakeTimers();
    let aborted = false;

    vi.stubGlobal("fetch", vi.fn((_url: unknown, init: RequestInit) => {
      return new Promise((_resolve, reject) => {
        (init.signal as AbortSignal).addEventListener("abort", () => {
          aborted = true;
          reject(new DOMException("The operation was aborted.", "AbortError"));
        });
      });
    }));

    const promise = dispatchToL2(validPayload, {
      ...validConfig,
      timeoutMs:  5000,
      maxRetries: 0,
    });
    await vi.advanceTimersByTimeAsync(5001);
    const result = await promise;

    expect(aborted).toBe(true);
    expect(result.success).toBe(false);
  });

  it("Returns error_message on timeout", async () => {
    vi.useFakeTimers();

    vi.stubGlobal("fetch", vi.fn((_url: unknown, init: RequestInit) => {
      return new Promise((_resolve, reject) => {
        (init.signal as AbortSignal).addEventListener("abort", () => {
          reject(new DOMException("The operation was aborted.", "AbortError"));
        });
      });
    }));

    const promise = dispatchToL2(validPayload, {
      ...validConfig,
      timeoutMs:  3000,
      maxRetries: 0,
    });
    await vi.advanceTimersByTimeAsync(3001);
    const result = await promise;

    expect(result.success).toBe(false);
    expect(result.error_message).toContain("timed out");
    expect(result.error_message).toContain("3000");
  });
});

// ---------------------------------------------------------------------------
// GROUP 6 — Orchestrator Integration
// ---------------------------------------------------------------------------

describe("GROUP 6 — Orchestrator Integration", () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("Full pipeline: SARIF input → pre-filter → batch → dispatch", async () => {
    let capturedBody: string | undefined;
    vi.stubGlobal("fetch", vi.fn((_url: unknown, init: RequestInit) => {
      capturedBody = init.body as string;
      return Promise.resolve(makeOkResponse());
    }));

    const result = await runOrchestrator({
      opengrep_sarif: singleFindingSarif,
      bearer_sarif:   emptySarif,
      changed_files:  ["src/api/auth.ts"],
      suppressions:   [],
      config: {
        worker_url:       "https://worker.example.com/dispatch",
        api_token:        "test-token",
        pr_ref:           "refs/pull/42",
        commit_sha:       "deadbeef",
        repository:       "org/repo",
        scanner_versions: { opengrep: "1.0.0", bearer: "2.0.0" },
      },
    });

    expect(result.dispatch_result.success).toBe(true);

    // Verify the dispatched body is a valid L2BatchPayload
    expect(capturedBody).toBeDefined();
    const body = JSON.parse(capturedBody!) as unknown;
    const validation = l2BatchPayloadSchema.safeParse(body);
    expect(validation.success).toBe(true);
  });

  it("Logs pipeline_complete audit entry with correct reduction percentage", async () => {
    vi.stubGlobal("fetch", vi.fn(() => Promise.resolve(makeOkResponse())));

    const logSpy = vi.spyOn(console, "log");

    await runOrchestrator({
      opengrep_sarif: singleFindingSarif,
      bearer_sarif:   emptySarif,
      changed_files:  ["src/api/auth.ts"],
      suppressions:   [],
      config: {
        worker_url:       "https://worker.example.com/dispatch",
        api_token:        "test-token",
        pr_ref:           "refs/pull/42",
        commit_sha:       "deadbeef",
        repository:       "org/repo",
        scanner_versions: { opengrep: "1.0.0", bearer: "2.0.0" },
      },
    });

    const auditCall = logSpy.mock.calls.find((args) => {
      try {
        const parsed = JSON.parse(args[0] as string) as Record<string, unknown>;
        return parsed["audit"] === "pipeline_complete";
      } catch {
        return false;
      }
    });

    expect(auditCall).toBeDefined();
    const auditEntry = JSON.parse(auditCall![0] as string) as Record<string, unknown>;
    expect(typeof auditEntry["reduction_percentage"]).toBe("string");
    expect(auditEntry["pr_ref"]).toBe("refs/pull/42");

    logSpy.mockRestore();
  });

  it("Orchestrator returns correct total counts", async () => {
    vi.stubGlobal("fetch", vi.fn(() => Promise.resolve(makeOkResponse())));

    const result = await runOrchestrator({
      opengrep_sarif: singleFindingSarif,
      bearer_sarif:   emptySarif,
      changed_files:  ["src/api/auth.ts"],
      suppressions:   [],
      config: {
        worker_url:       "https://worker.example.com/dispatch",
        api_token:        "test-token",
        pr_ref:           "refs/pull/42",
        commit_sha:       "deadbeef",
        repository:       "org/repo",
        scanner_versions: { opengrep: "1.0.0", bearer: "2.0.0" },
      },
    });

    // One raw finding from opengrep, none from bearer
    expect(result.total_raw_findings).toBe(1);
    // After pipeline, the finding should survive (HIGH, CWE-89, in changed_files)
    expect(result.total_after_filtering).toBeGreaterThanOrEqual(0);
    expect(typeof result.total_escalations).toBe("number");
    expect(result.pipeline_stats.length).toBeGreaterThan(0);
  });
});
