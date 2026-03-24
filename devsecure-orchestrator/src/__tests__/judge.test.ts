// Author: Jeremy Quadri
// src/__tests__/judge.test.ts — Unit tests for the Adversarial Judge (Requirement 9).

import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { judgeEvaluationSchema } from "../types";
import type { JudgeEvaluation, JudgeEvaluationInput } from "../types";
import { routeJudgeResult, evaluateWithJudge } from "../index";

// ---------------------------------------------------------------------------
// Shared test fixtures
// ---------------------------------------------------------------------------

const BASE_EVALUATION: JudgeEvaluation = {
  verdict:    "PASS",
  confidence: 0.90,
  risk_flags: ["boundary_change"],
  evidence:   "The fix correctly sanitizes output.",
  comments:   "Apply consistent escaping across all rendering paths.",
};

const BASE_INPUT: JudgeEvaluationInput = {
  patch_diff: "- return user_input\n+ return escape(user_input)",
  original_finding: {
    cwe_id:         "CWE-89",
    cwe_name:       "SQL Injection",
    description:    "User input concatenated directly into SQL query.",
    file_path:      "api/users.ts",
    line_start:     42,
    line_end:       44,
    source_scanner: "opengrep",
  },
  detection_signal: "CONVERGED",
  file_path:        "api/users.ts",
};

// Minimal Env mock — only the fields evaluateWithJudge needs.
// eslint-disable-next-line @typescript-eslint/no-explicit-any
const MOCK_ENV = { JUDGE_API_KEY: "test-key", JUDGE_MODEL: "gpt-4o-mini" } as any;

// ---------------------------------------------------------------------------
// Helper: build a mock fetch that returns a given LLM response string.
// ---------------------------------------------------------------------------
function mockFetchReturning(content: string) {
  return vi.fn().mockResolvedValue({
    ok:   true,
    json: () =>
      Promise.resolve({ choices: [{ message: { content } }] }),
    text: () => Promise.resolve(content),
  });
}

// ---------------------------------------------------------------------------
// GROUP 1 — Routing Logic Tests
// ---------------------------------------------------------------------------

describe("GROUP 1 — Routing Logic", () => {
  it("PASS with confidence 0.90 routes to AUTO_MERGE with null ticket_payload", () => {
    const result = routeJudgeResult(
      { ...BASE_EVALUATION, verdict: "PASS", confidence: 0.90 },
      BASE_INPUT,
    );
    expect(result.action).toBe("AUTO_MERGE");
    expect(result.ticket_payload).toBeNull();
  });

  it("PASS with confidence 0.80 routes to SOFT_PASS_REVIEW with ticket_payload", () => {
    const result = routeJudgeResult(
      { ...BASE_EVALUATION, verdict: "PASS", confidence: 0.80 },
      BASE_INPUT,
    );
    expect(result.action).toBe("SOFT_PASS_REVIEW");
    expect(result.ticket_payload).not.toBeNull();
  });

  it("PASS with confidence 0.60 routes to LOW_CONFIDENCE_PASS with ticket_payload", () => {
    const result = routeJudgeResult(
      { ...BASE_EVALUATION, verdict: "PASS", confidence: 0.60 },
      BASE_INPUT,
    );
    expect(result.action).toBe("LOW_CONFIDENCE_PASS");
    expect(result.ticket_payload).not.toBeNull();
  });

  it("FAIL with any confidence routes to JUDGE_REJECTED with ticket_payload", () => {
    const result = routeJudgeResult(
      { ...BASE_EVALUATION, verdict: "FAIL", confidence: 0.95 },
      BASE_INPUT,
    );
    expect(result.action).toBe("JUDGE_REJECTED");
    expect(result.ticket_payload).not.toBeNull();
  });

  it("UNCERTAIN with confidence 0.40 routes to SENIOR_REVIEW_REQUIRED", () => {
    const result = routeJudgeResult(
      { ...BASE_EVALUATION, verdict: "UNCERTAIN", confidence: 0.40 },
      BASE_INPUT,
    );
    expect(result.action).toBe("SENIOR_REVIEW_REQUIRED");
  });

  it("UNCERTAIN with confidence 0.60 routes to STANDARD_REVIEW", () => {
    const result = routeJudgeResult(
      { ...BASE_EVALUATION, verdict: "UNCERTAIN", confidence: 0.60 },
      BASE_INPUT,
    );
    expect(result.action).toBe("STANDARD_REVIEW");
  });
});

// ---------------------------------------------------------------------------
// GROUP 2 — Zod Schema Validation Tests
// ---------------------------------------------------------------------------

describe("GROUP 2 — Zod Schema Validation", () => {
  it("Valid evaluation passes schema validation", () => {
    const result = judgeEvaluationSchema.safeParse(BASE_EVALUATION);
    expect(result.success).toBe(true);
  });

  it("verdict 'MAYBE' fails schema validation", () => {
    const result = judgeEvaluationSchema.safeParse({
      ...BASE_EVALUATION, verdict: "MAYBE",
    });
    expect(result.success).toBe(false);
  });

  it("confidence -0.1 fails schema validation", () => {
    const result = judgeEvaluationSchema.safeParse({
      ...BASE_EVALUATION, confidence: -0.1,
    });
    expect(result.success).toBe(false);
  });

  it("confidence 1.5 fails schema validation", () => {
    const result = judgeEvaluationSchema.safeParse({
      ...BASE_EVALUATION, confidence: 1.5,
    });
    expect(result.success).toBe(false);
  });

  it("empty risk_flags array fails schema validation", () => {
    const result = judgeEvaluationSchema.safeParse({
      ...BASE_EVALUATION, risk_flags: [],
    });
    expect(result.success).toBe(false);
  });

  it("evidence over 500 chars fails schema validation", () => {
    const result = judgeEvaluationSchema.safeParse({
      ...BASE_EVALUATION, evidence: "x".repeat(501),
    });
    expect(result.success).toBe(false);
  });

  it("comments over 2000 chars fails schema validation", () => {
    const result = judgeEvaluationSchema.safeParse({
      ...BASE_EVALUATION, comments: "x".repeat(2001),
    });
    expect(result.success).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// GROUP 3 — Parse & Sanitisation Tests
// ---------------------------------------------------------------------------

describe("GROUP 3 — Parse & Sanitisation", () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("Malformed JSON response returns UNCERTAIN with json_parse_error flag", async () => {
    vi.stubGlobal("fetch", mockFetchReturning("not valid json {{{"));
    const result = await evaluateWithJudge(BASE_INPUT, MOCK_ENV);
    expect(result.verdict).toBe("UNCERTAIN");
    expect(result.confidence).toBe(0.0);
    expect(result.risk_flags).toContain("json_parse_error");
  });

  it("Valid JSON but invalid schema returns UNCERTAIN with schema_validation_error flag", async () => {
    vi.stubGlobal("fetch", mockFetchReturning(JSON.stringify({
      verdict: "MAYBE",   // invalid
      confidence: 0.8,
      risk_flags: ["boundary_change"],
      evidence:   "looks fine",
      comments:   "ok",
    })));
    const result = await evaluateWithJudge(BASE_INPUT, MOCK_ENV);
    expect(result.verdict).toBe("UNCERTAIN");
    expect(result.risk_flags).toContain("schema_validation_error");
  });

  it("HTML tags in evidence field are stripped after parsing", async () => {
    vi.stubGlobal("fetch", mockFetchReturning(JSON.stringify({
      ...BASE_EVALUATION,
      evidence: "<b>bold</b> text",
    })));
    const result = await evaluateWithJudge(BASE_INPUT, MOCK_ENV);
    expect(result.evidence).toBe("bold text");
  });

  it("HTML tags in comments field are stripped after parsing", async () => {
    vi.stubGlobal("fetch", mockFetchReturning(JSON.stringify({
      ...BASE_EVALUATION,
      comments: "<script>alert('xss')</script>safe comment",
    })));
    const result = await evaluateWithJudge(BASE_INPUT, MOCK_ENV);
    expect(result.comments).not.toContain("<script>");
    expect(result.comments).toContain("safe comment");
  });

  it("Evidence is truncated to 500 chars after sanitisation", async () => {
    vi.stubGlobal("fetch", mockFetchReturning(JSON.stringify({
      ...BASE_EVALUATION,
      evidence: "a".repeat(500),    // exactly 500 chars — passes Zod, then truncated
      comments: BASE_EVALUATION.comments,
    })));
    const result = await evaluateWithJudge(BASE_INPUT, MOCK_ENV);
    expect(result.evidence.length).toBeLessThanOrEqual(500);
  });

  it("Comments are truncated to 2000 chars after sanitisation", async () => {
    vi.stubGlobal("fetch", mockFetchReturning(JSON.stringify({
      ...BASE_EVALUATION,
      evidence: BASE_EVALUATION.evidence,
      comments: "c".repeat(2000),   // exactly 2000 chars — passes Zod, then truncated
    })));
    const result = await evaluateWithJudge(BASE_INPUT, MOCK_ENV);
    expect(result.comments.length).toBeLessThanOrEqual(2000);
  });
});

// ---------------------------------------------------------------------------
// GROUP 4 — Ticket Payload Tests
// ---------------------------------------------------------------------------

describe("GROUP 4 — Ticket Payload", () => {
  it("JUDGE_REJECTED generates ticket with severity critical", () => {
    const result = routeJudgeResult(
      { ...BASE_EVALUATION, verdict: "FAIL" },
      BASE_INPUT,
    );
    expect(result.ticket_payload?.severity).toBe("critical");
  });

  it("SENIOR_REVIEW_REQUIRED generates ticket with severity high", () => {
    const result = routeJudgeResult(
      { ...BASE_EVALUATION, verdict: "UNCERTAIN", confidence: 0.30 },
      BASE_INPUT,
    );
    expect(result.ticket_payload?.severity).toBe("high");
  });

  it("SOFT_PASS_REVIEW generates ticket with severity medium", () => {
    const result = routeJudgeResult(
      { ...BASE_EVALUATION, verdict: "PASS", confidence: 0.75 },
      BASE_INPUT,
    );
    expect(result.ticket_payload?.severity).toBe("medium");
  });

  it("Ticket markdown_body contains all required sections", () => {
    const result = routeJudgeResult(
      { ...BASE_EVALUATION, verdict: "FAIL" },
      BASE_INPUT,
    );
    const body = result.ticket_payload!.markdown_body;
    expect(body).toContain("**Verdict:**");
    expect(body).toContain("**Routing:**");
    expect(body).toContain("**Detection Signal:**");
    expect(body).toContain("**CWE:**");
    expect(body).toContain("### Risk Flags");
    expect(body).toContain("### Evidence");
    expect(body).toContain("### Recommended Actions");
    expect(body).toContain("DevSecure L3 Adversarial Judge");
  });

  it("AUTO_MERGE returns null ticket_payload", () => {
    const result = routeJudgeResult(
      { ...BASE_EVALUATION, verdict: "PASS", confidence: 0.95 },
      BASE_INPUT,
    );
    expect(result.action).toBe("AUTO_MERGE");
    expect(result.ticket_payload).toBeNull();
  });
});

// ---------------------------------------------------------------------------
// GROUP 5 — Detection Signal Integration Tests
// ---------------------------------------------------------------------------

describe("GROUP 5 — Detection Signal Integration", () => {
  it("CONVERGED signal is passed through to ticket_payload", () => {
    const input: JudgeEvaluationInput = { ...BASE_INPUT, detection_signal: "CONVERGED" };
    const result = routeJudgeResult(
      { ...BASE_EVALUATION, verdict: "FAIL" },
      input,
    );
    expect(result.ticket_payload?.detection_signal).toBe("CONVERGED");
  });

  it("DATAFLOW_ONLY signal is passed through to ticket_payload", () => {
    const input: JudgeEvaluationInput = { ...BASE_INPUT, detection_signal: "DATAFLOW_ONLY" };
    const result = routeJudgeResult(
      { ...BASE_EVALUATION, verdict: "FAIL" },
      input,
    );
    expect(result.ticket_payload?.detection_signal).toBe("DATAFLOW_ONLY");
  });

  it("NO_DETECTION_ESCALATION signal is passed through to ticket_payload", () => {
    const input: JudgeEvaluationInput = { ...BASE_INPUT, detection_signal: "NO_DETECTION_ESCALATION" };
    const result = routeJudgeResult(
      { ...BASE_EVALUATION, verdict: "FAIL" },
      input,
    );
    expect(result.ticket_payload?.detection_signal).toBe("NO_DETECTION_ESCALATION");
  });
});
