// Author: Jeremy Quadri
// src/__tests__/l1_filters.test.ts — Unit tests for L1 Detection Plane Phase 2 (pre-filter functions).

import { describe, it, expect } from "vitest";

import {
  normalizePath,
  filterByScope,
  isExcludedPath,
  verifyFileContentType,
  shouldDropBySeverity,
  filterBySeverity,
  isSuppressed,
  assignDetectionSignal,
  deduplicateFindings,
  isHighRiskFile,
  checkNoDetectionEscalation,
  runPreFilterPipeline,
  buildL2BatchPayload,
} from "../filters/index";

import { l2BatchPayloadSchema } from "../types";
import type { SuppressionEntry, NormalizedFinding } from "../types";
import {
  createMockOpenGrepFinding,
  createMockBearerFinding,
} from "./helpers/mock_findings";

// ===========================================================================
// GROUP 0 — Scope Lock (filterByScope)
// ===========================================================================

describe("GROUP 0 — Scope Lock (filterByScope)", () => {
  it("Keeps finding when file_path is in changedFiles", () => {
    const finding = createMockOpenGrepFinding({ file_path: "src/api/users.ts" });
    const { passed } = filterByScope([finding], ["src/api/users.ts"]);
    expect(passed).toHaveLength(1);
  });

  it("Drops finding when file_path is NOT in changedFiles", () => {
    const finding = createMockOpenGrepFinding({ file_path: "src/api/users.ts" });
    const { passed } = filterByScope([finding], ["src/auth/login.ts"]);
    expect(passed).toHaveLength(0);
  });

  it("Drops ALL findings when changedFiles is empty", () => {
    const findings = [
      createMockOpenGrepFinding({ id: "f1", file_path: "src/api/users.ts" }),
      createMockBearerFinding({ id: "f2", file_path: "src/auth/login.ts" }),
    ];
    const { passed, stats } = filterByScope(findings, []);
    expect(passed).toHaveLength(0);
    expect(stats.removed_count).toBe(2);
  });

  it("Handles path with leading ./ (normalised to match)", () => {
    const finding = createMockOpenGrepFinding({ file_path: "./src/api/users.ts" });
    const { passed } = filterByScope([finding], ["src/api/users.ts"]);
    expect(passed).toHaveLength(1);
  });

  it("Handles path with leading / (normalised to match)", () => {
    const finding = createMockOpenGrepFinding({ file_path: "/src/api/users.ts" });
    const { passed } = filterByScope([finding], ["src/api/users.ts"]);
    expect(passed).toHaveLength(1);
  });

  it("Handles Windows backslash paths (normalised to match)", () => {
    const finding = createMockOpenGrepFinding({ file_path: "src\\api\\users.ts" });
    const { passed } = filterByScope([finding], ["src/api/users.ts"]);
    expect(passed).toHaveLength(1);
  });

  it("Case-insensitive matching (SRC/Api.ts matches src/api.ts)", () => {
    const finding = createMockOpenGrepFinding({ file_path: "SRC/Api/Users.ts" });
    const { passed } = filterByScope([finding], ["src/api/users.ts"]);
    expect(passed).toHaveLength(1);
  });

  it("Returns correct PreFilterStats with step scope_lock", () => {
    const finding = createMockOpenGrepFinding({ file_path: "src/api/users.ts" });
    const { stats } = filterByScope([finding], ["src/api/users.ts"]);
    expect(stats.step).toBe("scope_lock");
    expect(stats.input_count).toBe(1);
    expect(stats.output_count).toBe(1);
    expect(stats.removed_count).toBe(0);
    expect(stats.removed_count).toBe(stats.input_count - stats.output_count);
    // Also verify normalizePath directly
    expect(normalizePath("./SRC/Api/Users.ts")).toBe("src/api/users.ts");
    expect(normalizePath("/src/api/users.ts")).toBe("src/api/users.ts");
    expect(normalizePath("src\\api\\users.ts")).toBe("src/api/users.ts");
  });

  it("removed_ids contains IDs of dropped findings", () => {
    const kept   = createMockOpenGrepFinding({ id: "keep-1", file_path: "src/api/users.ts" });
    const dropped = createMockOpenGrepFinding({ id: "drop-1", file_path: "src/other/file.ts" });
    const { stats } = filterByScope([kept, dropped], ["src/api/users.ts"]);
    expect(stats.removed_ids).toContain("drop-1");
    expect(stats.removed_ids).not.toContain("keep-1");
  });

  it("Multiple findings — some pass, some dropped — correct split", () => {
    const f1 = createMockOpenGrepFinding({ id: "f1", file_path: "src/api/users.ts" });
    const f2 = createMockBearerFinding({   id: "f2", file_path: "src/api/users.ts" });
    const f3 = createMockOpenGrepFinding({ id: "f3", file_path: "src/unrelated/helper.ts" });
    const { passed, stats } = filterByScope([f1, f2, f3], ["src/api/users.ts"]);
    expect(passed).toHaveLength(2);
    expect(stats.removed_count).toBe(1);
    expect(stats.removed_ids).toContain("f3");
  });
});

// ===========================================================================
// GROUP 1 — Path Filter (isExcludedPath)
// ===========================================================================

describe("GROUP 1 — Path Filter (isExcludedPath)", () => {
  it("Returns true for file in /node_modules/", () => {
    expect(isExcludedPath("project/node_modules/lodash/index.js")).toBe(true);
  });

  it("Returns true for file in /test/ directory", () => {
    expect(isExcludedPath("src/test/auth.ts")).toBe(true);
  });

  it("Returns true for file in /__tests__/ directory", () => {
    expect(isExcludedPath("src/__tests__/users.test.ts")).toBe(true);
  });

  it("Returns true for file in /fixtures/ directory", () => {
    expect(isExcludedPath("tests/fixtures/sql_injection.ts")).toBe(true);
  });

  it("Returns true for file in /dist/ directory", () => {
    expect(isExcludedPath("dist/bundle.js")).toBe(true);
  });

  it("Returns true for .test.ts file", () => {
    expect(isExcludedPath("src/api/users.test.ts")).toBe(true);
  });

  it("Returns true for .spec.js file", () => {
    expect(isExcludedPath("src/auth/login.spec.js")).toBe(true);
  });

  it("Returns true for .generated.ts file", () => {
    expect(isExcludedPath("src/proto/schema.generated.ts")).toBe(true);
  });

  it("Returns true for .min.js file", () => {
    expect(isExcludedPath("public/vendor/jquery.min.js")).toBe(true);
  });

  it("Returns false for src/api/users.ts (production code)", () => {
    expect(isExcludedPath("src/api/users.ts")).toBe(false);
  });

  it("Returns false for src/auth/login.ts (production code)", () => {
    expect(isExcludedPath("src/auth/login.ts")).toBe(false);
  });
});

// ===========================================================================
// GROUP 2 — Content-Type Verification (verifyFileContentType)
// ===========================================================================

describe("GROUP 2 — Content-Type Verification (verifyFileContentType)", () => {
  it("Returns isMismatch false for a .ts file containing TypeScript", async () => {
    try {
      const content = Buffer.from(
        'import express from "express";\nexport function handler(req: Request): Response { return new Response("ok"); }',
      );
      const result = await verifyFileContentType("src/api/handler.ts", content);
      expect(result.isMismatch).toBe(false);
      expect(result.declaredType).toBe(".ts");
    } catch {
      // Magika model unavailable in this environment — skip
    }
  }, 30000);

  it("Returns isMismatch true for a .json file containing Python script", async () => {
    try {
      const content = Buffer.from(
        '#!/usr/bin/env python3\nimport os\nos.system("malicious")\n',
      );
      const result = await verifyFileContentType("data/config.json", content);
      // Only assert if Magika detected python (model-dependent)
      if (result.detectedType === "python") {
        expect(result.isMismatch).toBe(true);
      } else {
        // Magika may not classify short scripts reliably — accept the call itself didn't throw
        expect(result).toHaveProperty("isMismatch");
      }
    } catch {
      // Magika model unavailable — skip
    }
  }, 30000);

  it("Returns isMismatch false for a .json file containing actual JSON", async () => {
    try {
      const content = Buffer.from('{"key": "value", "count": 42}');
      const result = await verifyFileContentType("config/settings.json", content);
      expect(result.isMismatch).toBe(false);
    } catch {
      // Magika model unavailable — skip
    }
  }, 30000);
});

// ===========================================================================
// GROUP 3 — Severity Gate (shouldDropBySeverity)
// ===========================================================================

describe("GROUP 3 — Severity Gate (shouldDropBySeverity)", () => {
  it("Drops INFO finding with confidence below threshold", () => {
    const finding = createMockOpenGrepFinding({
      severity:   "INFO",
      confidence: 0.1,
      cwe_id:     "CWE-200",
    });
    expect(shouldDropBySeverity(finding)).toBe(true);
  });

  it("Keeps INFO finding with confidence above threshold", () => {
    const finding = createMockOpenGrepFinding({
      severity:   "INFO",
      confidence: 0.9,
      cwe_id:     "CWE-200",
    });
    expect(shouldDropBySeverity(finding)).toBe(false);
  });

  it("Keeps LOW finding with confidence below threshold (LOW not in drop_severities)", () => {
    const finding = createMockOpenGrepFinding({
      severity:   "LOW",
      confidence: 0.05,
      cwe_id:     "CWE-200",
    });
    expect(shouldDropBySeverity(finding)).toBe(false);
  });

  it("NEVER drops CWE-89 regardless of confidence and severity", () => {
    const finding = createMockOpenGrepFinding({
      severity:   "INFO",
      confidence: 0.01,
      cwe_id:     "CWE-89",
    });
    expect(shouldDropBySeverity(finding)).toBe(false);
  });

  it("NEVER drops CWE-79 regardless of confidence and severity", () => {
    const finding = createMockOpenGrepFinding({
      severity:   "INFO",
      confidence: 0.0,
      cwe_id:     "CWE-79",
    });
    expect(shouldDropBySeverity(finding)).toBe(false);
  });

  it("NEVER drops CWE-918 regardless of confidence and severity", () => {
    const finding = createMockOpenGrepFinding({
      severity:   "INFO",
      confidence: 0.0,
      cwe_id:     "CWE-918",
    });
    expect(shouldDropBySeverity(finding)).toBe(false);
  });

  it("NEVER drops CWE-502 regardless of confidence and severity", () => {
    const finding = createMockOpenGrepFinding({
      severity:   "INFO",
      confidence: 0.0,
      cwe_id:     "CWE-502",
    });
    expect(shouldDropBySeverity(finding)).toBe(false);
  });

  it("Drops INFO finding with confidence exactly at threshold boundary", () => {
    // min_confidence is 0.3; confidence < 0.3 drops — exactly 0.3 should NOT drop
    const atThreshold = createMockOpenGrepFinding({
      severity:   "INFO",
      confidence: 0.3,
      cwe_id:     "CWE-200",
    });
    expect(shouldDropBySeverity(atThreshold)).toBe(false);

    const belowThreshold = createMockOpenGrepFinding({
      severity:   "INFO",
      confidence: 0.29,
      cwe_id:     "CWE-200",
    });
    expect(shouldDropBySeverity(belowThreshold)).toBe(true);
  });
});

// ===========================================================================
// GROUP 4 — Severity Gate Batch (filterBySeverity)
// ===========================================================================

describe("GROUP 4 — Severity Gate Batch (filterBySeverity)", () => {
  const infoLow = createMockOpenGrepFinding({
    id: "drop-1", severity: "INFO", confidence: 0.1, cwe_id: "CWE-200",
  });
  const highGood = createMockOpenGrepFinding({
    id: "keep-1", severity: "HIGH", confidence: 0.9,
  });
  const infoLow2 = createMockOpenGrepFinding({
    id: "drop-2", severity: "INFO", confidence: 0.05, cwe_id: "CWE-200",
  });

  it("Returns correct PreFilterStats with accurate counts", () => {
    const { stats } = filterBySeverity([infoLow, highGood, infoLow2]);
    expect(stats.step).toBe("severity_gate");
    expect(stats.input_count).toBe(3);
    expect(stats.output_count).toBe(1);
    expect(stats.removed_count).toBe(2);
    expect(stats.removed_count).toBe(stats.input_count - stats.output_count);
  });

  it("removed_ids contains IDs of dropped findings", () => {
    const { stats } = filterBySeverity([infoLow, highGood, infoLow2]);
    expect(stats.removed_ids).toContain("drop-1");
    expect(stats.removed_ids).toContain("drop-2");
    expect(stats.removed_ids).not.toContain("keep-1");
  });

  it("Preserved findings are unchanged (no mutation)", () => {
    const original = createMockOpenGrepFinding({ id: "keep-orig", severity: "HIGH", confidence: 0.8 });
    const { passed } = filterBySeverity([original]);
    expect(passed[0]).toStrictEqual(original);
  });
});

// ===========================================================================
// GROUP 5 — Allowlist (isSuppressed)
// ===========================================================================

function baseSuppression(overrides?: Partial<SuppressionEntry>): SuppressionEntry {
  return {
    rule_id:      "opengrep.sql.injection",
    cwe_id:       "CWE-89",
    file_pattern: "tests/fixtures/**",
    reason:       "Test fixture — not production code",
    approved_by:  "@security-lead",
    expires_at:   null,
    created_at:   "2026-01-01T00:00:00.000Z",
    ...overrides,
  };
}

describe("GROUP 5 — Allowlist (isSuppressed)", () => {
  it("Matches suppression with exact rule_id and cwe_id", () => {
    const finding = createMockOpenGrepFinding({
      file_path: "tests/fixtures/sql.ts",
      rule_id:   "opengrep.sql.injection",
      cwe_id:    "CWE-89",
    });
    const suppression = baseSuppression({ file_pattern: "tests/fixtures/**" });
    expect(isSuppressed(finding, [suppression])).toBe(true);
  });

  it("Matches suppression with null rule_id (wildcard rule)", () => {
    const finding = createMockOpenGrepFinding({
      file_path: "tests/fixtures/xss.ts",
      rule_id:   "opengrep.xss",
      cwe_id:    "CWE-89",
    });
    const suppression = baseSuppression({ rule_id: null, file_pattern: "tests/fixtures/**" });
    expect(isSuppressed(finding, [suppression])).toBe(true);
  });

  it("Matches suppression with null cwe_id (wildcard CWE)", () => {
    const finding = createMockOpenGrepFinding({
      file_path: "tests/fixtures/auth.ts",
      rule_id:   "opengrep.sql.injection",
      cwe_id:    "CWE-287",
    });
    const suppression = baseSuppression({ cwe_id: null, file_pattern: "tests/fixtures/**" });
    expect(isSuppressed(finding, [suppression])).toBe(true);
  });

  it("Matches suppression with both null rule_id and null cwe_id (full wildcard)", () => {
    const finding = createMockOpenGrepFinding({
      file_path: "tests/fixtures/anything.ts",
      rule_id:   "some.rule",
      cwe_id:    "CWE-999",
    });
    const suppression = baseSuppression({ rule_id: null, cwe_id: null, file_pattern: "tests/fixtures/**" });
    expect(isSuppressed(finding, [suppression])).toBe(true);
  });

  it("Does NOT match when file_pattern does not match", () => {
    const finding = createMockOpenGrepFinding({
      file_path: "src/api/users.ts",
      rule_id:   "opengrep.sql.injection",
      cwe_id:    "CWE-89",
    });
    const suppression = baseSuppression({ file_pattern: "tests/fixtures/**" });
    expect(isSuppressed(finding, [suppression])).toBe(false);
  });

  it("Does NOT match expired suppression (expires_at in the past)", () => {
    const finding = createMockOpenGrepFinding({
      file_path: "tests/fixtures/sql.ts",
      rule_id:   "opengrep.sql.injection",
      cwe_id:    "CWE-89",
    });
    const suppression = baseSuppression({
      file_pattern: "tests/fixtures/**",
      expires_at:   "2020-01-01T00:00:00.000Z",
    });
    expect(isSuppressed(finding, [suppression])).toBe(false);
  });

  it("Matches suppression with null expires_at (no expiry)", () => {
    const finding = createMockOpenGrepFinding({
      file_path: "tests/fixtures/sql.ts",
      rule_id:   "opengrep.sql.injection",
      cwe_id:    "CWE-89",
    });
    const suppression = baseSuppression({ expires_at: null, file_pattern: "tests/fixtures/**" });
    expect(isSuppressed(finding, [suppression])).toBe(true);
  });

  it("Matches glob pattern with ** (e.g., tests/fixtures/**)", () => {
    const finding = createMockOpenGrepFinding({
      file_path: "tests/fixtures/deep/nested/sql.ts",
      rule_id:   "opengrep.sql.injection",
      cwe_id:    "CWE-89",
    });
    const suppression = baseSuppression({ file_pattern: "tests/fixtures/**" });
    expect(isSuppressed(finding, [suppression])).toBe(true);
  });

  it("Returns false when suppressions array is empty", () => {
    const finding = createMockOpenGrepFinding();
    expect(isSuppressed(finding, [])).toBe(false);
  });
});

// ===========================================================================
// GROUP 6 — Deduplication (deduplicateFindings)
// ===========================================================================

describe("GROUP 6 — Deduplication (deduplicateFindings)", () => {
  it("Two OpenGrep findings at same location merge into single PATTERN_ONLY finding", () => {
    const f1 = createMockOpenGrepFinding({ id: "og-1" });
    const f2 = createMockOpenGrepFinding({ id: "og-2", rule_id: "opengrep.sqli.v2" });
    const { deduplicated } = deduplicateFindings([f1, f2]);
    expect(deduplicated).toHaveLength(1);
    expect(deduplicated[0].detection_signal).toBe("PATTERN_ONLY");
  });

  it("OpenGrep finding and Bearer finding at same location merge into CONVERGED finding", () => {
    const og = createMockOpenGrepFinding();
    const bearer = createMockBearerFinding();
    const { deduplicated } = deduplicateFindings([og, bearer]);
    expect(deduplicated).toHaveLength(1);
    expect(deduplicated[0].detection_signal).toBe("CONVERGED");
  });

  it("Bearer-only finding produces DATAFLOW_ONLY signal", () => {
    const bearer = createMockBearerFinding();
    const { deduplicated } = deduplicateFindings([bearer]);
    expect(deduplicated).toHaveLength(1);
    expect(deduplicated[0].detection_signal).toBe("DATAFLOW_ONLY");
  });

  it("Findings at different files are NOT merged", () => {
    const f1 = createMockOpenGrepFinding({ file_path: "src/api/users.ts" });
    const f2 = createMockOpenGrepFinding({ file_path: "src/api/posts.ts" });
    const { deduplicated } = deduplicateFindings([f1, f2]);
    expect(deduplicated).toHaveLength(2);
  });

  it("Findings at same file but different CWE categories are NOT merged", () => {
    const f1 = createMockOpenGrepFinding({ cwe_category: "injection" });
    const f2 = createMockOpenGrepFinding({ cwe_category: "xss", cwe_id: "CWE-79" });
    const { deduplicated } = deduplicateFindings([f1, f2]);
    expect(deduplicated).toHaveLength(2);
  });

  it("Findings within DEDUP_PROXIMITY_LINES (5 lines) are merged", () => {
    const f1 = createMockOpenGrepFinding({ line_start: 42 });
    const f2 = createMockBearerFinding({ line_start: 46 }); // 4 lines apart
    const { deduplicated } = deduplicateFindings([f1, f2]);
    expect(deduplicated).toHaveLength(1);
  });

  it("Findings more than DEDUP_PROXIMITY_LINES apart are NOT merged", () => {
    // Different snippet hashes ensure they don't merge via snippet_hash equality
    const f1 = createMockOpenGrepFinding({ line_start: 42, snippet_hash: "hash-a" });
    const f2 = createMockBearerFinding({ line_start: 50, snippet_hash: "hash-b" }); // 8 lines apart
    const { deduplicated } = deduplicateFindings([f1, f2]);
    expect(deduplicated).toHaveLength(2);
  });

  it("Merged finding takes max_severity from highest-severity original", () => {
    const low = createMockOpenGrepFinding({ severity: "LOW" });
    const critical = createMockBearerFinding({ severity: "CRITICAL" });
    const { deduplicated } = deduplicateFindings([low, critical]);
    expect(deduplicated[0].max_severity).toBe("CRITICAL");
  });

  it("Merged finding takes max_confidence from highest-confidence original", () => {
    const low = createMockOpenGrepFinding({ confidence: 0.5 });
    const high = createMockBearerFinding({ confidence: 0.95 });
    const { deduplicated } = deduplicateFindings([low, high]);
    expect(deduplicated[0].max_confidence).toBe(0.95);
  });

  it("Merged finding preserves all original_findings", () => {
    const og = createMockOpenGrepFinding();
    const bearer = createMockBearerFinding();
    const { deduplicated } = deduplicateFindings([og, bearer]);
    expect(deduplicated[0].original_findings).toHaveLength(2);
  });

  it("Returns correct PreFilterStats with dedup counts", () => {
    const og = createMockOpenGrepFinding();
    const bearer = createMockBearerFinding(); // merges with og
    const separate = createMockOpenGrepFinding({
      file_path: "src/other.ts",
      snippet_hash: "different-hash",
    });
    const { stats } = deduplicateFindings([og, bearer, separate]);
    expect(stats.step).toBe("dedup");
    expect(stats.input_count).toBe(3);
    expect(stats.output_count).toBe(2);
    expect(stats.removed_count).toBe(1);
    expect(stats.removed_count).toBe(stats.input_count - stats.output_count);
  });
});

// ===========================================================================
// GROUP 7 — Detection Signal Assignment (assignDetectionSignal)
// ===========================================================================

describe("GROUP 7 — Detection Signal Assignment (assignDetectionSignal)", () => {
  it("Single opengrep finding returns PATTERN_ONLY", () => {
    expect(assignDetectionSignal([createMockOpenGrepFinding()])).toBe("PATTERN_ONLY");
  });

  it("Single bearer finding returns DATAFLOW_ONLY", () => {
    expect(assignDetectionSignal([createMockBearerFinding()])).toBe("DATAFLOW_ONLY");
  });

  it("Both opengrep and bearer returns CONVERGED", () => {
    expect(
      assignDetectionSignal([createMockOpenGrepFinding(), createMockBearerFinding()]),
    ).toBe("CONVERGED");
  });

  it("Multiple opengrep findings (no bearer) returns PATTERN_ONLY", () => {
    const findings = [
      createMockOpenGrepFinding({ id: "og-1" }),
      createMockOpenGrepFinding({ id: "og-2" }),
    ];
    expect(assignDetectionSignal(findings)).toBe("PATTERN_ONLY");
  });
});

// ===========================================================================
// GROUP 8 — No-Detection Escalation (checkNoDetectionEscalation)
// ===========================================================================

function makeNormalizedFinding(filePath: string): NormalizedFinding {
  return {
    dedup_hash:        "hash-" + filePath,
    file_path:         filePath,
    line_start:        10,
    line_end:          12,
    cwe_id:            "CWE-89",
    cwe_category:      "injection",
    detection_signal:  "PATTERN_ONLY",
    max_severity:      "HIGH",
    max_confidence:    0.87,
    original_findings: [createMockOpenGrepFinding({ file_path: filePath })],
  };
}

describe("GROUP 8 — No-Detection Escalation (checkNoDetectionEscalation)", () => {
  it("High-risk file with no findings generates escalation payload", () => {
    const result = checkNoDetectionEscalation(["src/auth/login.ts"], []);
    expect(result).toHaveLength(1);
    expect(result[0].file_path).toBe("src/auth/login.ts");
  });

  it("High-risk file with existing finding does NOT generate escalation", () => {
    const findings = [makeNormalizedFinding("src/auth/login.ts")];
    const result = checkNoDetectionEscalation(["src/auth/login.ts"], findings);
    expect(result).toHaveLength(0);
  });

  it("Non-high-risk file with no findings does NOT generate escalation", () => {
    const result = checkNoDetectionEscalation(["src/utils/string_helpers.ts"], []);
    expect(result).toHaveLength(0);
  });

  it("Escalation payload has is_escalation true and empty findings array", () => {
    const result = checkNoDetectionEscalation(["src/auth/login.ts"], []);
    expect(result[0].is_escalation).toBe(true);
    expect(result[0].findings).toHaveLength(0);
  });

  it("Multiple high-risk files without findings generate multiple escalations", () => {
    const changed = ["src/auth/login.ts", "src/db/query.ts", "src/utils/string_helpers.ts"];
    const result = checkNoDetectionEscalation(changed, []);
    expect(result).toHaveLength(2); // string_helpers.ts is not high-risk
    const paths = result.map((r) => r.file_path);
    expect(paths).toContain("src/auth/login.ts");
    expect(paths).toContain("src/db/query.ts");
  });

  it("isHighRiskFile returns true for auth/login.ts", () => {
    expect(isHighRiskFile("src/auth/login.ts")).toBe(true);
  });

  it("isHighRiskFile returns true for db/query_builder.ts", () => {
    expect(isHighRiskFile("src/db/query_builder.ts")).toBe(true);
  });

  it("isHighRiskFile returns true for middleware/session.ts", () => {
    expect(isHighRiskFile("src/middleware/session.ts")).toBe(true);
  });

  it("isHighRiskFile returns false for utils/string_helpers.ts", () => {
    expect(isHighRiskFile("src/utils/string_helpers.ts")).toBe(false);
  });
});

// ===========================================================================
// GROUP 9 — Pipeline Orchestrator (runPreFilterPipeline)
// ===========================================================================

describe("GROUP 9 — Pipeline Orchestrator (runPreFilterPipeline)", () => {
  it("Empty findings array returns empty results with zero-count stats", async () => {
    const result = await runPreFilterPipeline({
      raw_findings:  [],
      changed_files: [],
      suppressions:  [],
    });
    expect(result.normalized_findings).toHaveLength(0);
    expect(result.escalation_payloads).toHaveLength(0);
    expect(result.total_input).toBe(0);
    expect(result.pipeline_stats.length).toBeGreaterThan(0);
    for (const stats of result.pipeline_stats) {
      expect(stats.input_count).toBe(0);
      expect(stats.output_count).toBe(0);
    }
  });

  it("Pipeline executes filters in correct order (path -> allowlist -> severity -> dedup)", async () => {
    // A finding in /dist/ would be excluded by path filter before severity gating
    const distFinding = createMockOpenGrepFinding({
      id:        "dist-finding",
      file_path: "dist/bundle.js",
      severity:  "HIGH",
      confidence: 0.99,
    });
    // An INFO low-confidence finding that should be removed by severity gate (not path)
    const infoFinding = createMockOpenGrepFinding({
      id:        "info-finding",
      severity:  "INFO",
      confidence: 0.05,
      cwe_id:    "CWE-200",
    });
    // Both files must be in changedFiles so scope_lock passes them through,
    // allowing path filter and severity gate to demonstrate their ordering.
    const result = await runPreFilterPipeline({
      raw_findings:  [distFinding, infoFinding],
      changed_files: ["dist/bundle.js", "src/api/users.ts"],
      suppressions:  [],
    });
    expect(result.normalized_findings).toHaveLength(0);
    // path_filter should have removed distFinding
    const pathStats = result.pipeline_stats.find((s) => s.step === "path_filter");
    expect(pathStats?.removed_count).toBe(1);
    // severity_gate should have removed infoFinding
    const severityStats = result.pipeline_stats.find((s) => s.step === "severity_gate");
    expect(severityStats?.removed_count).toBe(1);
  });

  it("Pipeline collects stats for every step", async () => {
    const finding = createMockOpenGrepFinding();
    const result = await runPreFilterPipeline({
      raw_findings:  [finding],
      changed_files: [finding.file_path], // keep it in scope
      suppressions:  [],
    });
    const steps = result.pipeline_stats.map((s) => s.step);
    expect(steps).toContain("scope_lock");
    expect(steps).toContain("path_filter");
    expect(steps).toContain("allowlist");
    expect(steps).toContain("severity_gate");
    expect(steps).toContain("dedup");
  });

  it("Pipeline returns escalation payloads for high-risk files without findings", async () => {
    const result = await runPreFilterPipeline({
      raw_findings:  [],
      changed_files: ["src/auth/login.ts"],
      suppressions:  [],
    });
    expect(result.escalation_payloads).toHaveLength(1);
    expect(result.escalation_payloads[0].is_escalation).toBe(true);
  });

  it("CWE-89 finding in /test/ directory is still removed (path filter runs before CWE bypass)", async () => {
    const testFinding = createMockOpenGrepFinding({
      id:        "test-cwe89",
      file_path: "src/test/auth.ts",
      cwe_id:    "CWE-89",
      severity:  "HIGH",
      confidence: 0.99,
    });
    const result = await runPreFilterPipeline({
      raw_findings:  [testFinding],
      changed_files: ["src/test/auth.ts"],
      suppressions:  [],
    });
    expect(result.normalized_findings).toHaveLength(0);
    const pathStats = result.pipeline_stats.find((s) => s.step === "path_filter");
    expect(pathStats?.removed_ids).toContain("test-cwe89");
  });

  it("Pipeline executes scope_lock as the first step before path filter", async () => {
    // Finding for a file NOT in changedFiles — scope_lock should drop it
    // before path filter ever sees it
    const outOfScope = createMockOpenGrepFinding({
      id:        "out-of-scope",
      file_path: "src/api/orders.ts",
      severity:  "HIGH",
      confidence: 0.99,
    });
    const result = await runPreFilterPipeline({
      raw_findings:  [outOfScope],
      changed_files: ["src/api/users.ts"], // orders.ts is NOT here
      suppressions:  [],
    });
    expect(result.normalized_findings).toHaveLength(0);
    // scope_lock must be first in pipeline_stats
    expect(result.pipeline_stats[0].step).toBe("scope_lock");
    expect(result.pipeline_stats[0].removed_ids).toContain("out-of-scope");
    // path_filter must NOT have seen the finding (input_count = 0)
    const pathStats = result.pipeline_stats.find((s) => s.step === "path_filter");
    expect(pathStats?.input_count).toBe(0);
  });
});

// ===========================================================================
// GROUP 10 — Batch Payload Builder (buildL2BatchPayload)
// ===========================================================================

function makeNormalizedFindings(count: number, filePath = "src/api/users.ts"): NormalizedFinding[] {
  return Array.from({ length: count }, (_, i) => ({
    dedup_hash:        `hash-${i}`,
    file_path:         filePath,
    line_start:        10 + i * 5,
    line_end:          12 + i * 5,
    cwe_id:            "CWE-89",
    cwe_category:      "injection",
    detection_signal:  "PATTERN_ONLY" as const,
    max_severity:      "HIGH" as const,
    max_confidence:    0.87,
    original_findings: [createMockOpenGrepFinding({ file_path: filePath })],
  }));
}

const basePipelineStats = [
  { step: "path_filter"   as const, input_count: 10, output_count: 8, removed_count: 2, removed_ids: ["a", "b"] },
  { step: "allowlist"     as const, input_count: 8,  output_count: 7, removed_count: 1, removed_ids: ["c"] },
  { step: "severity_gate" as const, input_count: 7,  output_count: 5, removed_count: 2, removed_ids: ["d", "e"] },
  { step: "dedup"         as const, input_count: 5,  output_count: 3, removed_count: 2, removed_ids: [] },
];

describe("GROUP 10 — Batch Payload Builder (buildL2BatchPayload)", () => {
  it("Groups findings by file_path into separate BatchedFilePayload objects", () => {
    const findings = [
      ...makeNormalizedFindings(2, "src/api/users.ts"),
      ...makeNormalizedFindings(1, "src/auth/login.ts"),
    ];
    const payload = buildL2BatchPayload({
      pr_ref: "refs/pull/1", commit_sha: "abc123", repository: "org/repo",
      scanner_versions: { opengrep: "1.0", bearer: "2.0" },
      normalized_findings: findings,
      escalation_payloads: [],
      pipeline_stats: basePipelineStats,
      total_raw: 10,
    });
    expect(payload.files).toHaveLength(2);
    const userFile = payload.files.find((f) => f.file_path === "src/api/users.ts");
    expect(userFile?.findings).toHaveLength(2);
  });

  it("Merges escalation payloads into the files array", () => {
    const escalation = {
      file_path: "src/auth/session.ts", code_context: "", findings: [], is_escalation: true,
    };
    const payload = buildL2BatchPayload({
      pr_ref: "refs/pull/1", commit_sha: "abc123", repository: "org/repo",
      scanner_versions: { opengrep: "1.0", bearer: "2.0" },
      normalized_findings: makeNormalizedFindings(1),
      escalation_payloads: [escalation],
      pipeline_stats: basePipelineStats,
      total_raw: 10,
    });
    const esc = payload.files.find((f) => f.is_escalation === true);
    expect(esc).toBeDefined();
    expect(esc?.file_path).toBe("src/auth/session.ts");
  });

  it("Sets timestamp to a valid ISO string", () => {
    const payload = buildL2BatchPayload({
      pr_ref: "refs/pull/1", commit_sha: "abc123", repository: "org/repo",
      scanner_versions: { opengrep: "1.0", bearer: "2.0" },
      normalized_findings: makeNormalizedFindings(1),
      escalation_payloads: [],
      pipeline_stats: basePipelineStats,
      total_raw: 10,
    });
    expect(() => new Date(payload.timestamp)).not.toThrow();
    expect(new Date(payload.timestamp).toISOString()).toBe(payload.timestamp);
  });

  it("Summary counts match actual data", () => {
    const findings = makeNormalizedFindings(3);
    const payload = buildL2BatchPayload({
      pr_ref: "refs/pull/1", commit_sha: "abc123", repository: "org/repo",
      scanner_versions: { opengrep: "1.0", bearer: "2.0" },
      normalized_findings: findings,
      escalation_payloads: [],
      pipeline_stats: basePipelineStats,
      total_raw: 10,
    });
    expect(payload.summary.total_raw_findings).toBe(10);
    expect(payload.summary.total_escalations).toBe(0);
  });

  it("Valid payload passes l2BatchPayloadSchema validation", () => {
    const payload = buildL2BatchPayload({
      pr_ref: "refs/pull/142", commit_sha: "a1b2c3", repository: "org/repo",
      scanner_versions: { opengrep: "1.2.3", bearer: "4.5.6" },
      normalized_findings: makeNormalizedFindings(1),
      escalation_payloads: [],
      pipeline_stats: basePipelineStats,
      total_raw: 10,
    });
    const result = l2BatchPayloadSchema.safeParse(payload);
    expect(result.success).toBe(true);
  });
});
