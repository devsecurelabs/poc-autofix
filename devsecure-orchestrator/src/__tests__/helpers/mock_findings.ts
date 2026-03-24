// Author: Jeremy Quadri
// src/__tests__/helpers/mock_findings.ts — Reusable mock factories for RawScannerFinding.

import type { RawScannerFinding } from "../../types";

export function createMockOpenGrepFinding(
  overrides?: Partial<RawScannerFinding>,
): RawScannerFinding {
  return {
    id:             "og-finding-001",
    source_scanner: "opengrep",
    file_path:      "src/api/users.ts",
    line_start:     42,
    line_end:       44,
    cwe_id:         "CWE-89",
    cwe_category:   "injection",
    rule_id:        "opengrep.sql.injection",
    severity:       "HIGH",
    confidence:     0.87,
    snippet:        "const q = `SELECT * FROM users WHERE id = ${userId}`;",
    snippet_hash:   "abc123def456",
    metadata:       { sink: "db.query", source: "req.params" },
    ...overrides,
  };
}

export function createMockBearerFinding(
  overrides?: Partial<RawScannerFinding>,
): RawScannerFinding {
  return {
    id:             "bearer-finding-001",
    source_scanner: "bearer",
    file_path:      "src/api/users.ts",
    line_start:     42,
    line_end:       44,
    cwe_id:         "CWE-89",
    cwe_category:   "injection",
    rule_id:        "bearer.sql-injection",
    severity:       "HIGH",
    confidence:     0.91,
    snippet:        "const q = `SELECT * FROM users WHERE id = ${userId}`;",
    snippet_hash:   "abc123def456",
    metadata:       { sink_name: "rawQuery", source_name: "request.body.id" },
    ...overrides,
  };
}
