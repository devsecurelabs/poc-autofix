// Author: Jeremy Quadri
// src/__tests__/l1_models.test.ts — Unit tests for L1 Detection Plane data models (Phase 1).

import { describe, it, expect } from "vitest";

import {
  CRITICAL_CWE_BYPASS,
  HIGH_RISK_FILE_PATTERNS,
  EXCLUDED_PATHS,
  EXCLUDED_FILE_PATTERNS,
  DEDUP_PROXIMITY_LINES,
} from "../constants";

import {
  rawScannerFindingSchema,
  suppressionEntrySchema,
  normalizedFindingSchema,
  batchedFilePayloadSchema,
  l2BatchPayloadSchema,
  preFilterStatsSchema,
} from "../types";

import type {
  NormalizedFinding,
  JudgeEvaluationInput,
  DetectionSignal,
} from "../types";

// ---------------------------------------------------------------------------
// Shared mock factories
// ---------------------------------------------------------------------------

function makeRawFinding(overrides: Partial<ReturnType<typeof baseRawFinding>> = {}) {
  return { ...baseRawFinding(), ...overrides };
}

function baseRawFinding(): {
  id:             string;
  source_scanner: "opengrep" | "bearer";
  file_path:      string;
  line_start:     number;
  line_end:       number;
  cwe_id:         string;
  cwe_category:   string;
  rule_id:        string;
  severity:       "INFO" | "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
  confidence:     number;
  snippet:        string;
  snippet_hash:   string;
  metadata:       Record<string, unknown>;
} {
  return {
    id:             "finding-001",
    source_scanner: "opengrep",
    file_path:      "src/api/users.ts",
    line_start:     42,
    line_end:       44,
    cwe_id:         "CWE-89",
    cwe_category:   "injection",
    rule_id:        "opengrep.sql.injection",
    severity:       "HIGH",
    confidence:     0.87,
    snippet:        "const query = `SELECT * FROM users WHERE id = ${userId}`;",
    snippet_hash:   "abc123def456",
    metadata:       { sink: "db.query", source: "req.params" },
  };
}

function makeNormalizedFinding(overrides: Partial<NormalizedFinding> = {}): NormalizedFinding {
  return {
    dedup_hash:        "dedup-hash-001",
    file_path:         "src/api/users.ts",
    line_start:        42,
    line_end:          44,
    cwe_id:            "CWE-89",
    cwe_category:      "injection",
    detection_signal:  "CONVERGED",
    max_severity:      "HIGH",
    max_confidence:    0.87,
    original_findings: [baseRawFinding()],
    ...overrides,
  };
}

// ---------------------------------------------------------------------------
// GROUP 1 — Constants Validation
// ---------------------------------------------------------------------------

describe("GROUP 1 — Constants Validation", () => {
  it("CRITICAL_CWE_BYPASS contains exactly 11 unique CWE IDs", () => {
    expect(CRITICAL_CWE_BYPASS).toHaveLength(11);
  });

  it("CRITICAL_CWE_BYPASS includes CWE-89 (SQL Injection)", () => {
    expect(CRITICAL_CWE_BYPASS).toContain("CWE-89");
  });

  it("CRITICAL_CWE_BYPASS includes CWE-918 (SSRF)", () => {
    expect(CRITICAL_CWE_BYPASS).toContain("CWE-918");
  });

  it("CRITICAL_CWE_BYPASS has no duplicates", () => {
    const unique = new Set(CRITICAL_CWE_BYPASS);
    expect(unique.size).toBe(CRITICAL_CWE_BYPASS.length);
  });

  it("HIGH_RISK_FILE_PATTERNS includes authentication patterns (auth, login)", () => {
    expect(HIGH_RISK_FILE_PATTERNS).toContain("auth");
    expect(HIGH_RISK_FILE_PATTERNS).toContain("login");
  });

  it("HIGH_RISK_FILE_PATTERNS includes database patterns (db, query, repository)", () => {
    expect(HIGH_RISK_FILE_PATTERNS).toContain("db");
    expect(HIGH_RISK_FILE_PATTERNS).toContain("query");
    expect(HIGH_RISK_FILE_PATTERNS).toContain("repository");
  });

  it("HIGH_RISK_FILE_PATTERNS includes crypto patterns (crypto, cipher)", () => {
    expect(HIGH_RISK_FILE_PATTERNS).toContain("crypto");
    expect(HIGH_RISK_FILE_PATTERNS).toContain("cipher");
  });

  it("HIGH_RISK_FILE_PATTERNS includes input validation patterns (parser, sanitize)", () => {
    expect(HIGH_RISK_FILE_PATTERNS).toContain("parser");
    expect(HIGH_RISK_FILE_PATTERNS).toContain("sanitize");
  });

  it("HIGH_RISK_FILE_PATTERNS includes API patterns (route, controller, middleware)", () => {
    expect(HIGH_RISK_FILE_PATTERNS).toContain("route");
    expect(HIGH_RISK_FILE_PATTERNS).toContain("controller");
    expect(HIGH_RISK_FILE_PATTERNS).toContain("middleware");
  });

  it("EXCLUDED_PATHS includes /node_modules/", () => {
    expect(EXCLUDED_PATHS).toContain("/node_modules/");
  });

  it("EXCLUDED_PATHS includes /test/ and /tests/ and /__tests__/", () => {
    expect(EXCLUDED_PATHS).toContain("/test/");
    expect(EXCLUDED_PATHS).toContain("/tests/");
    expect(EXCLUDED_PATHS).toContain("/__tests__/");
  });

  it("EXCLUDED_PATHS includes /fixtures/", () => {
    expect(EXCLUDED_PATHS).toContain("/fixtures/");
  });

  it("EXCLUDED_FILE_PATTERNS includes *.test.ts and *.spec.ts", () => {
    expect(EXCLUDED_FILE_PATTERNS).toContain("*.test.ts");
    expect(EXCLUDED_FILE_PATTERNS).toContain("*.spec.ts");
  });

  it("EXCLUDED_FILE_PATTERNS includes *.generated.* and *.min.js", () => {
    expect(EXCLUDED_FILE_PATTERNS).toContain("*.generated.*");
    expect(EXCLUDED_FILE_PATTERNS).toContain("*.min.js");
  });

  it("DEDUP_PROXIMITY_LINES is 5", () => {
    expect(DEDUP_PROXIMITY_LINES).toBe(5);
  });
});

// ---------------------------------------------------------------------------
// GROUP 2 — RawScannerFinding Schema
// ---------------------------------------------------------------------------

describe("GROUP 2 — RawScannerFinding Schema", () => {
  it("Valid OpenGrep finding passes validation", () => {
    const result = rawScannerFindingSchema.safeParse(makeRawFinding({ source_scanner: "opengrep" }));
    expect(result.success).toBe(true);
  });

  it("Valid Bearer finding passes validation", () => {
    const result = rawScannerFindingSchema.safeParse(makeRawFinding({
      source_scanner: "bearer",
      rule_id:        "bearer.sql-injection",
      metadata:       { sink_name: "rawQuery", source_name: "request.body.id" },
    }));
    expect(result.success).toBe(true);
  });

  it("Finding with confidence 1.5 fails validation", () => {
    const result = rawScannerFindingSchema.safeParse(makeRawFinding({ confidence: 1.5 }));
    expect(result.success).toBe(false);
  });

  it("Finding with confidence -0.1 fails validation", () => {
    const result = rawScannerFindingSchema.safeParse(makeRawFinding({ confidence: -0.1 }));
    expect(result.success).toBe(false);
  });

  it("Finding with source_scanner 'unknown' fails validation", () => {
    const result = rawScannerFindingSchema.safeParse(makeRawFinding({ source_scanner: "unknown" as never }));
    expect(result.success).toBe(false);
  });

  it("Finding with empty snippet fails validation", () => {
    const result = rawScannerFindingSchema.safeParse(makeRawFinding({ snippet: "" }));
    expect(result.success).toBe(false);
  });

  it("Finding with severity 'UNKNOWN' fails validation", () => {
    const result = rawScannerFindingSchema.safeParse(makeRawFinding({ severity: "UNKNOWN" as never }));
    expect(result.success).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// GROUP 3 — SuppressionEntry Schema
// ---------------------------------------------------------------------------

const baseSuppressionEntry = {
  rule_id:      "opengrep.sql.injection",
  cwe_id:       "CWE-89",
  file_pattern: "tests/fixtures/**",
  reason:       "Test fixture — not production code",
  approved_by:  "@security-lead",
  expires_at:   "2026-12-31T00:00:00.000Z",
  created_at:   "2026-01-01T00:00:00.000Z",
};

describe("GROUP 3 — SuppressionEntry Schema", () => {
  it("Valid suppression entry with expiry passes validation", () => {
    const result = suppressionEntrySchema.safeParse(baseSuppressionEntry);
    expect(result.success).toBe(true);
  });

  it("Valid suppression entry with null expiry passes validation", () => {
    const result = suppressionEntrySchema.safeParse({ ...baseSuppressionEntry, expires_at: null });
    expect(result.success).toBe(true);
  });

  it("Valid suppression entry with null rule_id and null cwe_id passes validation (matches everything for a path)", () => {
    const result = suppressionEntrySchema.safeParse({
      ...baseSuppressionEntry,
      rule_id: null,
      cwe_id:  null,
    });
    expect(result.success).toBe(true);
  });

  it("Suppression entry with empty reason fails validation", () => {
    const result = suppressionEntrySchema.safeParse({ ...baseSuppressionEntry, reason: "" });
    expect(result.success).toBe(false);
  });

  it("Suppression entry with empty approved_by fails validation", () => {
    const result = suppressionEntrySchema.safeParse({ ...baseSuppressionEntry, approved_by: "" });
    expect(result.success).toBe(false);
  });

  it("Suppression entry with invalid datetime for expires_at fails validation", () => {
    const result = suppressionEntrySchema.safeParse({ ...baseSuppressionEntry, expires_at: "not-a-date" });
    expect(result.success).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// GROUP 4 — NormalizedFinding Schema
// ---------------------------------------------------------------------------

describe("GROUP 4 — NormalizedFinding Schema", () => {
  it("Valid CONVERGED finding with two original findings passes validation", () => {
    const result = normalizedFindingSchema.safeParse(makeNormalizedFinding({
      detection_signal:  "CONVERGED",
      original_findings: [
        baseRawFinding(),
        makeRawFinding({ id: "finding-002", source_scanner: "bearer" }),
      ],
    }));
    expect(result.success).toBe(true);
  });

  it("Valid PATTERN_ONLY finding with one original finding passes validation", () => {
    const result = normalizedFindingSchema.safeParse(makeNormalizedFinding({
      detection_signal:  "PATTERN_ONLY",
      original_findings: [baseRawFinding()],
    }));
    expect(result.success).toBe(true);
  });

  it("Finding with empty original_findings array fails validation", () => {
    const result = normalizedFindingSchema.safeParse(makeNormalizedFinding({ original_findings: [] }));
    expect(result.success).toBe(false);
  });

  it("Finding with invalid detection_signal 'UNKNOWN' fails validation", () => {
    const result = normalizedFindingSchema.safeParse(makeNormalizedFinding({
      detection_signal: "UNKNOWN" as never,
    }));
    expect(result.success).toBe(false);
  });

  it("max_confidence above 1.0 fails validation", () => {
    const result = normalizedFindingSchema.safeParse(makeNormalizedFinding({ max_confidence: 1.1 }));
    expect(result.success).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// GROUP 5 — BatchedFilePayload Schema
// ---------------------------------------------------------------------------

const basePayload = {
  file_path:     "src/api/users.ts",
  code_context:  "const query = `SELECT * FROM users WHERE id = ${userId}`;",
  findings:      [makeNormalizedFinding()],
  is_escalation: false,
};

describe("GROUP 5 — BatchedFilePayload Schema", () => {
  it("Valid payload with findings and is_escalation false passes validation", () => {
    const result = batchedFilePayloadSchema.safeParse(basePayload);
    expect(result.success).toBe(true);
  });

  it("Valid escalation payload with empty findings and is_escalation true passes validation", () => {
    const result = batchedFilePayloadSchema.safeParse({
      ...basePayload,
      findings:      [],
      is_escalation: true,
    });
    expect(result.success).toBe(true);
  });

  it("Non-escalation payload with empty findings fails validation with message 'Non-escalation payloads must contain at least one finding'", () => {
    const result = batchedFilePayloadSchema.safeParse({ ...basePayload, findings: [], is_escalation: false });
    expect(result.success).toBe(false);
    if (!result.success) {
      const messages = result.error.issues.map((i) => i.message);
      expect(messages).toContain("Non-escalation payloads must contain at least one finding");
    }
  });

  it("Payload with is_escalation true and findings present passes validation (escalation can also have findings)", () => {
    const result = batchedFilePayloadSchema.safeParse({ ...basePayload, is_escalation: true });
    expect(result.success).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// GROUP 6 — L2BatchPayload Schema
// ---------------------------------------------------------------------------

const validBatch = {
  pr_ref:     "refs/pull/142",
  commit_sha: "a1b2c3d4e5f6",
  repository: "org/repo-name",
  timestamp:  "2026-03-24T12:00:00.000Z",
  scanner_versions: { opengrep: "1.2.3", bearer: "4.5.6" },
  summary: {
    total_files_scanned: 12,
    total_raw_findings:  8,
    total_after_dedup:   6,
    total_after_filters: 5,
    total_escalations:   1,
  },
  files: [basePayload],
};

describe("GROUP 6 — L2BatchPayload Schema", () => {
  it("Valid complete batch payload passes validation", () => {
    const result = l2BatchPayloadSchema.safeParse(validBatch);
    expect(result.success).toBe(true);
  });

  it("Batch payload with empty files array fails validation", () => {
    const result = l2BatchPayloadSchema.safeParse({ ...validBatch, files: [] });
    expect(result.success).toBe(false);
  });

  it("Batch payload with invalid timestamp fails validation", () => {
    const result = l2BatchPayloadSchema.safeParse({ ...validBatch, timestamp: "not-a-timestamp" });
    expect(result.success).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// GROUP 7 — PreFilterStats Schema
// ---------------------------------------------------------------------------

describe("GROUP 7 — PreFilterStats Schema", () => {
  it("Valid stats where removed_count equals input minus output passes validation", () => {
    const result = preFilterStatsSchema.safeParse({
      step:          "dedup",
      input_count:   10,
      output_count:  7,
      removed_count: 3,
      removed_ids:   ["finding-001", "finding-002", "finding-003"],
    });
    expect(result.success).toBe(true);
  });

  it("Stats where removed_count does not equal input minus output fails validation", () => {
    const result = preFilterStatsSchema.safeParse({
      step:          "dedup",
      input_count:   10,
      output_count:  7,
      removed_count: 4, // should be 3
      removed_ids:   [],
    });
    expect(result.success).toBe(false);
    if (!result.success) {
      const messages = result.error.issues.map((i) => i.message);
      expect(messages).toContain("removed_count must equal input_count minus output_count");
    }
  });

  it("Stats with negative input_count fails validation", () => {
    const result = preFilterStatsSchema.safeParse({
      step:          "path_filter",
      input_count:   -1,
      output_count:  0,
      removed_count: 0,
      removed_ids:   [],
    });
    expect(result.success).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// GROUP 8 — Type Compatibility
// ---------------------------------------------------------------------------

describe("GROUP 8 — Type Compatibility", () => {
  it("DetectionSignal type is shared between NormalizedFinding and JudgeEvaluationInput", () => {
    // Assign a DetectionSignal value and verify it satisfies both interfaces' field types.
    // This is a compile-time check enforced by TypeScript — if it compiles, the types are compatible.
    const signal: DetectionSignal = "CONVERGED";

    const normalized: Pick<NormalizedFinding, "detection_signal"> = { detection_signal: signal };
    const judgeInput: Pick<JudgeEvaluationInput, "detection_signal"> = { detection_signal: signal };

    expect(normalized.detection_signal).toBe("CONVERGED");
    expect(judgeInput.detection_signal).toBe("CONVERGED");
  });
});
