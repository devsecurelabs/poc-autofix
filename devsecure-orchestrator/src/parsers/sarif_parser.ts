// Author: Jeremy Quadri
// src/parsers/sarif_parser.ts — SARIF 2.1.0 input parser for OpenGrep and Bearer output.
// Runs in the GitHub Actions (Node.js) execution environment.

import { createHash, randomUUID } from "node:crypto";
import { rawScannerFindingSchema } from "../types";
import type { RawScannerFinding } from "../types";

// ---------------------------------------------------------------------------
// CWE helpers
// ---------------------------------------------------------------------------

const CWE_PATTERN = /CWE-\d+/i;

/** Maps specific CWE IDs to human-readable category slugs. */
const CWE_CATEGORY_MAP: Record<string, string> = {
  "CWE-89":  "sql_injection",
  "CWE-564": "sql_injection",
  "CWE-79":  "xss",
  "CWE-78":  "command_injection",
  "CWE-77":  "command_injection",
  "CWE-22":  "path_traversal",
  "CWE-94":  "code_injection",
  "CWE-287": "authentication",
  "CWE-306": "authentication",
  "CWE-862": "authorization",
  "CWE-918": "ssrf",
  "CWE-502": "deserialization",
};

function deriveCweCategory(cweId: string): string {
  return CWE_CATEGORY_MAP[cweId.toUpperCase()] ?? "unknown";
}

/** Extracts the first CWE-xxx identifier from a SARIF result's taxa or properties.tags. */
function extractCweId(result: Record<string, unknown>): string {
  // 1. Try result.taxa[].id
  const taxa = result["taxa"];
  if (Array.isArray(taxa)) {
    for (const taxon of taxa) {
      if (typeof taxon === "object" && taxon !== null) {
        const id = (taxon as Record<string, unknown>)["id"];
        if (typeof id === "string") {
          const match = id.match(CWE_PATTERN);
          if (match) return match[0].toUpperCase();
        }
      }
    }
  }

  // 2. Try result.properties.tags[]
  const props = result["properties"];
  if (typeof props === "object" && props !== null) {
    const tags = (props as Record<string, unknown>)["tags"];
    if (Array.isArray(tags)) {
      for (const tag of tags) {
        if (typeof tag === "string") {
          const match = tag.match(CWE_PATTERN);
          if (match) return match[0].toUpperCase();
        }
      }
    }
  }

  return "CWE-UNKNOWN";
}

function mapSeverity(level: unknown): RawScannerFinding["severity"] {
  switch (level) {
    case "error":   return "HIGH";
    case "warning": return "MEDIUM";
    case "note":    return "LOW";
    case "none":    return "INFO";
    default:        return "MEDIUM";
  }
}

function computeSnippetHash(snippet: string): string {
  return createHash("sha256").update(snippet).digest("hex");
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * Parses a SARIF 2.1.0 JSON object into an array of RawScannerFinding.
 * Findings that fail schema validation are skipped with a warning log.
 *
 * @param sarifJson  Already-parsed SARIF JSON (type unknown — do not pre-cast).
 * @param sourceScanner  Which scanner produced this SARIF output.
 */
export function parseSarifToFindings(
  sarifJson: unknown,
  sourceScanner: "opengrep" | "bearer",
): RawScannerFinding[] {
  if (typeof sarifJson !== "object" || sarifJson === null) return [];

  const sarif = sarifJson as Record<string, unknown>;
  const runs  = sarif["runs"];
  if (!Array.isArray(runs) || runs.length === 0) return [];

  const run     = runs[0] as Record<string, unknown>;
  const results = run["results"];
  if (!Array.isArray(results) || results.length === 0) return [];

  const findings: RawScannerFinding[] = [];

  for (const rawResult of results) {
    if (typeof rawResult !== "object" || rawResult === null) continue;
    const r = rawResult as Record<string, unknown>;

    // ---------- Location extraction ----------
    const locations = r["locations"];
    if (!Array.isArray(locations) || locations.length === 0) continue;

    const loc0    = locations[0] as Record<string, unknown>;
    const physLoc = loc0["physicalLocation"] as Record<string, unknown> | undefined;
    if (!physLoc) continue;

    const artifactLoc = physLoc["artifactLocation"] as Record<string, unknown> | undefined;
    const region      = physLoc["region"]            as Record<string, unknown> | undefined;

    const filePath = typeof artifactLoc?.["uri"] === "string" ? artifactLoc["uri"] : null;
    if (!filePath) continue;

    const lineStart = typeof region?.["startLine"] === "number" ? (region["startLine"] as number) : 1;
    const lineEnd   = typeof region?.["endLine"]   === "number" ? (region["endLine"]   as number) : lineStart;

    // ---------- Snippet extraction ----------
    const snippetObj = region?.["snippet"] as Record<string, unknown> | undefined;
    const snippet    = typeof snippetObj?.["text"] === "string" ? (snippetObj["text"] as string) : "";

    // ---------- CWE extraction ----------
    const cweId      = extractCweId(r);
    const cweCategory = deriveCweCategory(cweId);

    // ---------- Rule ID ----------
    const ruleId = typeof r["ruleId"] === "string" ? r["ruleId"] : "unknown-rule";

    // ---------- Severity ----------
    const severity = mapSeverity(r["level"]);

    // ---------- Confidence + metadata ----------
    const props      = r["properties"] as Record<string, unknown> | undefined;
    const confidence = typeof props?.["confidence"] === "number" ? (props["confidence"] as number) : 0.5;

    const metadata: Record<string, unknown> = {};
    if (props) {
      for (const [k, v] of Object.entries(props)) {
        if (k !== "confidence") metadata[k] = v;
      }
    }

    // ---------- Assemble candidate ----------
    const candidate: RawScannerFinding = {
      id:             randomUUID(),
      source_scanner: sourceScanner,
      file_path:      filePath,
      line_start:     lineStart,
      line_end:       lineEnd,
      cwe_id:         cweId,
      cwe_category:   cweCategory,
      rule_id:        ruleId,
      severity,
      confidence,
      snippet,
      snippet_hash:   computeSnippetHash(snippet),
      metadata,
    };

    // ---------- Schema validation ----------
    const validation = rawScannerFindingSchema.safeParse(candidate);
    if (!validation.success) {
      console.warn(
        JSON.stringify({
          audit:     "sarif_parser_skip",
          reason:    validation.error.message,
          rule_id:   ruleId,
          file_path: filePath,
        }),
      );
      continue;
    }

    findings.push(validation.data);
  }

  return findings;
}
