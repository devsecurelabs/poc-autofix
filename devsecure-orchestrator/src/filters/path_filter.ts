// Author: Jeremy Quadri
// src/filters/path_filter.ts — Path-based filtering with content-type validation (Requirement 4).

import { Magika } from "magika";
import { EXCLUDED_PATHS, EXCLUDED_FILE_PATTERNS } from "../constants";
import type { RawScannerFinding, PreFilterStats } from "../types";

// ---------------------------------------------------------------------------
// Magika singleton — initialised once at module level
// ---------------------------------------------------------------------------

let _magika: Magika | null = null;

async function getMagika(): Promise<Magika> {
  if (_magika === null) {
    _magika = await Magika.create();
  }
  return _magika;
}

// ---------------------------------------------------------------------------
// 1a. Path exclusion check
// ---------------------------------------------------------------------------

/**
 * Returns true if filePath should be excluded based on path segments or file
 * extension patterns defined in EXCLUDED_PATHS and EXCLUDED_FILE_PATTERNS.
 */
export function isExcludedPath(filePath: string): boolean {
  // Normalise separators to forward slashes
  const normalised = filePath.replace(/\\/g, "/");

  // Directory-level exclusion: check for substring matches.
  // Prepend "/" so "dist/bundle.js" becomes "/dist/bundle.js" and matches "/dist/".
  const normalisedForCheck = "/" + normalised.replace(/^\//, "");
  for (const excluded of EXCLUDED_PATHS) {
    if (normalisedForCheck.includes(excluded)) {
      return true;
    }
  }

  // File-level exclusion: match glob patterns against filename
  const filename = normalised.split("/").pop() ?? normalised;

  for (const pattern of EXCLUDED_FILE_PATTERNS) {
    if (matchesGlobPattern(filename, pattern)) {
      return true;
    }
  }

  return false;
}

/**
 * Simple glob matcher for file-level patterns only.
 * Supports: *.ext, *.generated.*, *.min.js, etc.
 * Does NOT support path-level ** patterns (handled separately in isSuppressed).
 */
function matchesGlobPattern(filename: string, pattern: string): boolean {
  if (!pattern.includes("*")) {
    return filename === pattern;
  }

  // Convert glob to a regex: escape dots, replace * with [^/]*
  const regexStr = pattern
    .split("*")
    .map((part) => part.replace(/\./g, "\\."))
    .join(".*");

  const regex = new RegExp(`^${regexStr}$`);
  return regex.test(filename);
}

// ---------------------------------------------------------------------------
// 1b. Content-type verification via Magika
// ---------------------------------------------------------------------------

/**
 * Detects the actual content type of a file using Magika and compares it
 * against the declared file extension.
 * Returns isMismatch: true when the file contains script content but has a
 * data-format extension (e.g. Python code in a .json file).
 */
export async function verifyFileContentType(
  filePath: string,
  fileContent: Buffer,
): Promise<{ isMismatch: boolean; declaredType: string; detectedType: string }> {
  const SCRIPT_TYPES = [
    "python", "javascript", "php", "shell", "perl", "ruby",
    "typescript", "java", "csharp", "go", "c", "cpp",
  ];
  const DATA_EXTENSIONS = [
    ".json", ".txt", ".csv", ".xml", ".yaml", ".yml",
    ".md", ".log", ".conf", ".cfg", ".ini", ".env",
  ];

  const ext = "." + (filePath.split(".").pop() ?? "").toLowerCase();
  const magika = await getMagika();
  const result = await magika.identifyBytes(new Uint8Array(fileContent));
  const detectedType = result.prediction.output.label ?? "unknown";
  const isMismatch =
    SCRIPT_TYPES.includes(detectedType) && DATA_EXTENSIONS.includes(ext);

  return {
    isMismatch,
    declaredType: ext,
    detectedType,
  };
}

// ---------------------------------------------------------------------------
// 1c. Batch path filter
// ---------------------------------------------------------------------------

/**
 * Filters a list of raw findings by path. Findings from excluded paths are
 * removed. Returns surviving findings and audit stats.
 *
 * NOTE: Does NOT call verifyFileContentType — that is an independent async
 * step the orchestrator calls separately before confirming exclusions.
 */
export function filterByPath(findings: RawScannerFinding[]): {
  passed: RawScannerFinding[];
  stats: PreFilterStats;
} {
  const passed: RawScannerFinding[] = [];
  const removedIds: string[] = [];

  for (const finding of findings) {
    if (isExcludedPath(finding.file_path)) {
      removedIds.push(finding.id);
    } else {
      passed.push(finding);
    }
  }

  const stats: PreFilterStats = {
    step: "path_filter",
    input_count: findings.length,
    output_count: passed.length,
    removed_count: removedIds.length,
    removed_ids: removedIds,
  };

  return { passed, stats };
}
