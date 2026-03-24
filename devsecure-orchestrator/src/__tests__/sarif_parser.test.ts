// Author: Jeremy Quadri
// src/__tests__/sarif_parser.test.ts — Unit tests for SARIF 2.1.0 input parser (Phase 3).

import { describe, it, expect, vi } from "vitest";
import { parseSarifToFindings } from "../parsers/sarif_parser";

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

/** Minimal valid SARIF 2.1.0 with 2 results. */
const twoResultSarif = {
  version: "2.1.0",
  runs: [
    {
      results: [
        {
          ruleId: "opengrep.sql.injection",
          level:  "error",
          locations: [
            {
              physicalLocation: {
                artifactLocation: { uri: "src/api/users.ts" },
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
        {
          ruleId: "opengrep.xss",
          level:  "warning",
          locations: [
            {
              physicalLocation: {
                artifactLocation: { uri: "src/api/render.ts" },
                region: {
                  startLine: 5,
                  endLine:   7,
                  snippet:   { text: "res.send(userInput)" },
                },
              },
            },
          ],
          taxa:       [{ id: "CWE-79" }],
          properties: { confidence: 0.7 },
        },
      ],
    },
  ],
};

/** SARIF where CWE comes from properties.tags, not taxa. */
const tagsBasedCweSarif = {
  version: "2.1.0",
  runs: [
    {
      results: [
        {
          ruleId: "bearer.xss",
          level:  "warning",
          locations: [
            {
              physicalLocation: {
                artifactLocation: { uri: "src/views/page.ts" },
                region: {
                  startLine: 3,
                  snippet:   { text: "document.innerHTML = userInput" },
                },
              },
            },
          ],
          properties: { confidence: 0.8, tags: ["CWE-79", "xss", "dom"] },
        },
      ],
    },
  ],
};

/** SARIF where endLine is missing (should default to startLine). */
const noEndLineSarif = {
  version: "2.1.0",
  runs: [
    {
      results: [
        {
          ruleId: "opengrep.cmd-injection",
          level:  "error",
          locations: [
            {
              physicalLocation: {
                artifactLocation: { uri: "src/utils/exec.ts" },
                region: {
                  startLine: 20,
                  // endLine intentionally absent
                  snippet: { text: "exec(userCommand)" },
                },
              },
            },
          ],
          taxa: [{ id: "CWE-78" }],
          properties: { confidence: 0.85 },
        },
      ],
    },
  ],
};

/** SARIF where the snippet is missing (finding should be skipped). */
const noSnippetSarif = {
  version: "2.1.0",
  runs: [
    {
      results: [
        {
          ruleId: "opengrep.sql.injection",
          level:  "error",
          locations: [
            {
              physicalLocation: {
                artifactLocation: { uri: "src/db/query.ts" },
                region: {
                  startLine: 15,
                  endLine:   15,
                  // snippet intentionally absent
                },
              },
            },
          ],
          taxa: [{ id: "CWE-89" }],
          properties: { confidence: 0.9 },
        },
      ],
    },
  ],
};

/** SARIF with no results array. */
const emptyResultsSarif = {
  version: "2.1.0",
  runs: [{ results: [] }],
};

/** SARIF with no CWE in taxa or tags. */
const noCweSarif = {
  version: "2.1.0",
  runs: [
    {
      results: [
        {
          ruleId: "opengrep.generic",
          level:  "warning",
          locations: [
            {
              physicalLocation: {
                artifactLocation: { uri: "src/misc/helper.ts" },
                region: {
                  startLine: 8,
                  snippet:   { text: "someFunction(input)" },
                },
              },
            },
          ],
          properties: { confidence: 0.5 },
        },
      ],
    },
  ],
};

// ---------------------------------------------------------------------------
// GROUP 5 — SARIF Parser
// ---------------------------------------------------------------------------

describe("GROUP 5 — SARIF Parser", () => {
  it("Parses valid SARIF 2.1.0 output into RawScannerFinding array", () => {
    const findings = parseSarifToFindings(twoResultSarif, "opengrep");

    expect(findings).toHaveLength(2);
    expect(findings[0].source_scanner).toBe("opengrep");
    expect(findings[1].source_scanner).toBe("opengrep");
  });

  it("Extracts file_path from artifact location URI", () => {
    const findings = parseSarifToFindings(twoResultSarif, "opengrep");

    expect(findings[0].file_path).toBe("src/api/users.ts");
    expect(findings[1].file_path).toBe("src/api/render.ts");
  });

  it("Extracts line_start and line_end from region", () => {
    const findings = parseSarifToFindings(twoResultSarif, "opengrep");

    expect(findings[0].line_start).toBe(10);
    expect(findings[0].line_end).toBe(12);
    expect(findings[1].line_start).toBe(5);
    expect(findings[1].line_end).toBe(7);
  });

  it("Defaults line_end to line_start when endLine is missing", () => {
    const findings = parseSarifToFindings(noEndLineSarif, "opengrep");

    expect(findings).toHaveLength(1);
    expect(findings[0].line_start).toBe(20);
    expect(findings[0].line_end).toBe(20);
  });

  it("Extracts CWE ID from taxa", () => {
    const findings = parseSarifToFindings(twoResultSarif, "opengrep");

    expect(findings[0].cwe_id).toBe("CWE-89");
    expect(findings[1].cwe_id).toBe("CWE-79");
  });

  it("Extracts CWE ID from properties.tags", () => {
    const findings = parseSarifToFindings(tagsBasedCweSarif, "bearer");

    expect(findings).toHaveLength(1);
    expect(findings[0].cwe_id).toBe("CWE-79");
  });

  it("Defaults to CWE-UNKNOWN when no CWE found", () => {
    const findings = parseSarifToFindings(noCweSarif, "opengrep");

    expect(findings).toHaveLength(1);
    expect(findings[0].cwe_id).toBe("CWE-UNKNOWN");
  });

  it("Maps SARIF level 'error' to severity HIGH", () => {
    const findings = parseSarifToFindings(twoResultSarif, "opengrep");

    expect(findings[0].severity).toBe("HIGH"); // level: "error"
  });

  it("Maps SARIF level 'warning' to severity MEDIUM", () => {
    const findings = parseSarifToFindings(twoResultSarif, "opengrep");

    expect(findings[1].severity).toBe("MEDIUM"); // level: "warning"
  });

  it("Maps SARIF level 'note' to severity LOW", () => {
    const noteSarif = {
      version: "2.1.0",
      runs: [
        {
          results: [
            {
              ruleId: "opengrep.info",
              level:  "note",
              locations: [
                {
                  physicalLocation: {
                    artifactLocation: { uri: "src/utils/logger.ts" },
                    region: { startLine: 1, snippet: { text: "console.log(data)" } },
                  },
                },
              ],
              properties: { confidence: 0.4 },
            },
          ],
        },
      ],
    };

    const findings = parseSarifToFindings(noteSarif, "opengrep");
    expect(findings).toHaveLength(1);
    expect(findings[0].severity).toBe("LOW");
  });

  it("Skips results that fail schema validation (logs warning)", () => {
    const warnSpy = vi.spyOn(console, "warn");

    const findings = parseSarifToFindings(noSnippetSarif, "opengrep");

    // Finding with empty snippet fails rawScannerFindingSchema (snippet min(1))
    expect(findings).toHaveLength(0);
    expect(warnSpy).toHaveBeenCalled();

    const warnArg = warnSpy.mock.calls[0][0] as string;
    const parsed  = JSON.parse(warnArg) as Record<string, unknown>;
    expect(parsed["audit"]).toBe("sarif_parser_skip");

    warnSpy.mockRestore();
  });

  it("Returns empty array for SARIF with no results", () => {
    const findings = parseSarifToFindings(emptyResultsSarif, "opengrep");

    expect(findings).toHaveLength(0);
  });

  it("Handles missing snippet gracefully (no exception thrown)", () => {
    expect(() => parseSarifToFindings(noSnippetSarif, "opengrep")).not.toThrow();
  });
});
