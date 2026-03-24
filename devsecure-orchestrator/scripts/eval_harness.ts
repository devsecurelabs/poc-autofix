// Author: Jeremy Quadri
// scripts/eval_harness.ts — Dual-Objective Evaluator for DevSecure v4.0 PoC.
//
// Simulates the deterministic scoring pipeline for every source file in
// vulnerable_code/, applies all RESEARCH_CONFIG constants, and checks hard
// safety invariants. Exits non-zero and prints "SAFETY CONSTRAINTS VIOLATED"
// if any invariant is breached.
//
// Run: npx tsx scripts/eval_harness.ts
// Or:  npm run eval

import * as fs from "fs";
import * as path from "path";
import { fileURLToPath } from "url";
import { RESEARCH_CONFIG } from "../src/research_target.js";

// ---------------------------------------------------------------------------
// Paths
// ---------------------------------------------------------------------------

const __filename = fileURLToPath(import.meta.url);
const __dirname  = path.dirname(__filename);

const VULNERABLE_CODE_DIR   = path.resolve(__dirname, "../../vulnerable_code");
const BASELINE_PATH         = path.resolve(__dirname, "eval_baseline.json");
const MANIFEST_PATH         = path.resolve(__dirname, "../../corpus_manifest.json");
const PROMPTS_TARGET_PATH   = path.resolve(__dirname, "../src/prompts_target.ts");
const PROMPTS_SNAPSHOT_PATH = path.resolve(__dirname, "prompts_baseline.snapshot");

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

interface ManifestEntry {
  file: string;   // e.g. "vulnerable_code/sample7.py"
  cwe:  string;   // e.g. "CWE-89"
}

interface Manifest {
  vulnerable_code: ManifestEntry[];
}

/** Keyed by the path relative to VULNERABLE_CODE_DIR, forward-slash normalized. */
type ManifestLookup = Record<string, string>;

interface FileSample {
  file:             string;
  cwe_id:           string;
  manifest_cwe:     string | null;   // ground-truth from corpus_manifest.json, null if absent
  severity_base:    number;
  confidence:       number;
  lane:             1 | 2 | 3 | 4;
  lane_weight:      number;
  change_percent:   number;
  patch_risk:       number;
  judge_was_run:    boolean;
  judge_approved:   boolean;
  verification_bonus: number;
  final_score:      number;
  action:           "pr_opened" | "issue_escalated";
  integrity_ok:     boolean;
  routing_status:   "fixed" | "cannot_fix";
}

interface ResearchReport {
  total_samples:                number;
  safe_fix_count:               number;
  safe_fix_rate:                number;
  escalation_count:             number;
  escalation_rate:              number;
  avg_priority_score:           number;
  integrity_failures:           number;
  regression_detected:          number;
  severity_floor_violations:    number;
  bonus_cap_violations:         number;
  threshold_tamper_detected:    boolean;
  // ── Reward-Hacking Guards (Board-mandated, 2026-03-24) ───────────────────
  classification_mismatch_count: number;   // Invariant 6: must be 0
  avg_confidence_score:          number;   // input for confidence_spike_detected
  confidence_spike_detected:     boolean;  // Invariant 7: must be false (threshold > 0.95)
  prompt_diff_violation:         boolean;  // Invariant 8: must be false (>5 lines changed)
  cwe_coverage:                  Record<string, number>;
}

type BaselineRecord = Record<string, "pr_opened" | "issue_escalated">;

// ---------------------------------------------------------------------------
// Constants — mirrors index.ts LANGUAGE_MAP for extension filtering
// ---------------------------------------------------------------------------

const SUPPORTED_EXTENSIONS = new Set([
  ".py", ".js", ".ts", ".php", ".java", ".rb", ".cs", ".dart",
]);

// CWE detection heuristics — filename pattern → CWE
// ORDER MATTERS: more-specific patterns first. /cmd/ must precede /sql/ so that
// files like "03_cmd_sql_vuln01.js" (manifest: CWE-78) are not mis-tagged CWE-89.
const CWE_PATTERNS: Array<[RegExp, string]> = [
  [/cmd/i,       "CWE-78"],   // OS Command Injection  (before /sql/ — takes priority)
  [/sql/i,       "CWE-89"],   // SQL Injection
  [/xss/i,       "CWE-79"],   // Cross-Site Scripting
  [/rce/i,       "CWE-94"],   // Code Injection / RCE
  [/auth/i,      "CWE-287"],  // Improper Authentication
  [/path|trav/i, "CWE-22"],   // Path Traversal
  [/upload/i,    "CWE-434"],  // Unrestricted File Upload
  [/deser/i,     "CWE-502"],  // Deserialization
  [/csrf/i,      "CWE-352"],  // CSRF
  [/redirect/i,  "CWE-601"],  // Open Redirect
  // NOTE: no /cve/i → CWE-20 — CVE-named files fall through to content detection
];

const DEFAULT_CWE = "CWE-20";

// CWE detection heuristics — content-based (checked when filename yields no match)
// Each entry is [pattern, cwe]. Patterns are checked in priority order; first match wins.
const CWE_CONTENT_PATTERNS: Array<[RegExp, string]> = [

  // ── CWE-89: SQL Injection ────────────────────────────────────────────────
  // Classic concat ending in mixed-quote close: "SELECT...'" + var  (Python/Java)
  // {1,2} allows for '" (single inside double) as the closing sequence before +/.
  [/["'`][^"'`\n]*(?:SELECT|INSERT\s+INTO|UPDATE\s+\w+|DELETE\s+FROM)\b[^"'`\n]*["'`]{1,2}\s*[+.]/i, "CWE-89"],
  // Python % string formatting: "SELECT ... %s" % variable
  [/["'][^"'\n]*(?:SELECT|INSERT|UPDATE|DELETE)\b[^"'\n]*["']\s*%\s*[(%\w]/i,                   "CWE-89"],
  // Python f-strings: f"SELECT ... {user_input} ..."
  [/\bf["'][^"'\n]*(?:SELECT|INSERT|UPDATE|DELETE)\b/i,                                          "CWE-89"],
  // JavaScript/TypeScript template literals: `SELECT ... ${userId} ...`
  [/`[^`\n]*(?:SELECT|INSERT|UPDATE|DELETE)\b[^`\n]*\$\{/i,                                     "CWE-89"],
  // Ruby ORM/raw-query string interpolation: where("id = '#{id}'")
  [/(?:where|find_by_sql|execute|query)\s*\([^)]*#\{[^}]+\}/i,                                  "CWE-89"],
  // Dart/Android raw SQL methods: db.rawQuery('SELECT ...', [...])
  [/(?:rawQuery|queryForList|executeQuery)\s*\(\s*["'`][^"'`\n]*(?:SELECT|INSERT|UPDATE|DELETE)/i, "CWE-89"],
  // Variable appended after query string: + req.query / + input / etc.
  [/[+.]\s*(?:request|req\b|input|param|args|\$_GET|\$_POST|\$_REQUEST)\b/i,                    "CWE-89"],
  [/(?:query|sql)\s*(?:\+=|[+.])\s*(?:request|req\b|input|param|args|\$_GET|\$_POST)/i,         "CWE-89"],

  // ── CWE-94: Code Injection (eval / dynamic code execution) ───────────────
  // eval() with any argument — JS, Python, PHP all use the same keyword
  [/\beval\s*\(/i,                                                                                "CWE-94"],

  // ── CWE-79: Cross-Site Scripting ─────────────────────────────────────────
  [/innerHTML\s*\+?=\s*(?!["'`][^<{])/,                                                          "CWE-79"],
  [/document\.write\s*\(/i,                                                                       "CWE-79"],
  // PHP echo directly with superglobal: echo $_GET['x']
  [/echo\s+.*\$_(?:GET|POST|REQUEST)/i,                                                          "CWE-79"],
  // PHP echo with string . $variable (user input assigned to local var first)
  [/echo\s+["'][^"'\n]*["']\s*\.\s*\$[a-zA-Z_]/i,                                               "CWE-79"],
  [/print(?:ln)?\s*\(.*(?:request\.(?:getParameter|args|form)|req\.(?:query|body|params))/i,    "CWE-79"],
  [/res(?:ponse)?\.(?:send|write|end)\s*\(.*req(?:uest)?\.(?:query|body|params)/i,              "CWE-79"],

  // ── CWE-78: OS Command Injection ─────────────────────────────────────────
  [/(?:exec|spawn|system|popen|shell_exec|passthru|proc_open)\s*\(/i,                           "CWE-78"],
  [/(?:os\.system|os\.popen|subprocess\.(?:call|run|Popen)|Runtime\.getRuntime|ProcessBuilder)\s*\(/i, "CWE-78"],

  // ── CWE-22: Path Traversal ───────────────────────────────────────────────
  [/(?:open|fopen|readFile(?:Sync)?|sendFile|createReadStream|include|require_once)\s*\(.*(?:request|req\b|input|param|args|\$_GET|\$_POST)/i, "CWE-22"],
  [/(?:os\.path\.join|path\.join)\s*\([^)]*(?:request|req\b|input|param|args|\$_GET|\$_POST)/i, "CWE-22"],
  [/(?:request|req\b|input|\$_GET|\$_POST)\b[^;)\n]*(?:open|fopen|readFile|include)/i,          "CWE-22"],

  // ── CWE-287: Auth Bypass ─────────────────────────────────────────────────
  [/password\s*(?:==|===)\s*["'`]["'`]/i,                                                        "CWE-287"],
  [/(?:session|auth|token)\s*\[["'`](?:user|admin|role|authenticated)["'`]\]\s*=\s*(?:true|1|["'`]admin["'`])/i, "CWE-287"],
  [/\/\/\s*(?:TODO|FIXME|HACK).*(?:auth|password|login|token)/i,                                "CWE-287"],
  [/(?:bypass|skip|disable|ignore)\s*(?:auth|authentication|login|password)/i,                  "CWE-287"],
  [/if\s*\([^)]*password[^)]*\)\s*\{?\s*(?:\/\/|#|return\s+true)/i,                            "CWE-287"],
];

// ---------------------------------------------------------------------------
// Pure functions — reimplemented locally (no Worker deps from index.ts)
// ---------------------------------------------------------------------------

function detectCWE(filename: string, content: string): string {
  // 1. Filename-based detection (fast, high-precision for well-named files)
  const base = path.basename(filename).toLowerCase();
  for (const [pattern, cwe] of CWE_PATTERNS) {
    if (pattern.test(base)) return cwe;
  }

  // 2. Content-based detection (fallback for files with non-descriptive names)
  for (const [pattern, cwe] of CWE_CONTENT_PATTERNS) {
    if (pattern.test(content)) return cwe;
  }

  // 3. Default — only if no pattern matched
  return DEFAULT_CWE;
}

function assignLane(severityBase: number): 1 | 2 | 3 | 4 {
  if (severityBase >= 88) return 1;
  if (severityBase >= 78) return 2;
  if (severityBase >= 65) return 3;
  return 4;
}

function computeLaneWeight(lane: 1 | 2 | 3 | 4): number {
  return (RESEARCH_CONFIG.LANE_WEIGHTS as Record<number, number>)[lane] ?? 20;
}

function computePatchRisk(changePercent: number): number {
  const bracket = RESEARCH_CONFIG.PATCH_RISK_BRACKETS.find(
    (b) => changePercent <= b.maxPercent,
  );
  return bracket?.penalty ?? 10;
}

function computePriorityScore(
  severityBase:    number,
  confidence:      number,
  judgePenalty:    number,
  patchRisk:       number,
  laneWeight:      number,
  mismatchPenalty: number,
): number {
  const base = Math.round(severityBase * confidence);
  return Math.min(100, Math.max(0, base - judgePenalty - patchRisk - laneWeight - mismatchPenalty));
}

function computeVerificationBonus(
  confidence:    number,
  laneWeight:    number,
  judgeApproved: boolean,
): number {
  if (!judgeApproved) return 0;
  const { HIGH_CONFIDENCE_CREDIT, LOW_CONFIDENCE_CREDIT, CORROBORATION_CREDIT } =
    RESEARCH_CONFIG.VERIFICATION_BONUS;
  const judgeCredit = confidence >= 0.85 ? HIGH_CONFIDENCE_CREDIT : LOW_CONFIDENCE_CREDIT;
  return Math.min(judgeCredit + CORROBORATION_CREDIT, laneWeight);
}

// ---------------------------------------------------------------------------
// Manifest loading — Invariant 6: Classification Accuracy
// ---------------------------------------------------------------------------

function loadManifest(): ManifestLookup {
  const lookup: ManifestLookup = {};
  if (!fs.existsSync(MANIFEST_PATH)) {
    console.warn("[EVAL] corpus_manifest.json not found — classification_mismatch_count will be 0");
    return lookup;
  }
  try {
    const manifest = JSON.parse(fs.readFileSync(MANIFEST_PATH, "utf-8")) as Manifest;
    for (const entry of manifest.vulnerable_code) {
      // Strip the "vulnerable_code/" prefix and normalise to forward slashes
      const key = entry.file.replace(/^vulnerable_code\//, "").replace(/\\/g, "/");
      lookup[key] = entry.cwe;
    }
  } catch {
    console.warn("[EVAL] Failed to parse corpus_manifest.json — skipping classification check");
  }
  return lookup;
}

// ---------------------------------------------------------------------------
// Prompt diff — Invariant 8: Prompt Mutation Limit
// ---------------------------------------------------------------------------

/**
 * Counts lines that differ between prompts_target.ts and prompts_baseline.snapshot.
 * Returns 0 if either file is absent (no violation possible without both present).
 * The snapshot is a human-only artifact — never written by the autoresearch agent.
 */
function countPromptLineDiff(): number {
  if (!fs.existsSync(PROMPTS_TARGET_PATH) || !fs.existsSync(PROMPTS_SNAPSHOT_PATH)) return 0;
  const targetLines   = fs.readFileSync(PROMPTS_TARGET_PATH,   "utf-8").split("\n");
  const snapshotLines = fs.readFileSync(PROMPTS_SNAPSHOT_PATH, "utf-8").split("\n");
  const maxLen = Math.max(targetLines.length, snapshotLines.length);
  let diff = 0;
  for (let i = 0; i < maxLen; i++) {
    if (targetLines[i] !== snapshotLines[i]) diff++;
  }
  return diff;
}

// ---------------------------------------------------------------------------
// File discovery — recursive, filtered to SUPPORTED_EXTENSIONS
// ---------------------------------------------------------------------------

function collectSourceFiles(dir: string): string[] {
  const results: string[] = [];
  if (!fs.existsSync(dir)) return results;

  function walk(current: string): void {
    for (const entry of fs.readdirSync(current, { withFileTypes: true })) {
      const full = path.join(current, entry.name);
      if (entry.isDirectory()) {
        walk(full);
      } else if (entry.isFile()) {
        const ext = path.extname(entry.name).toLowerCase();
        if (SUPPORTED_EXTENSIONS.has(ext)) results.push(full);
      }
    }
  }

  walk(dir);
  return results;
}

// ---------------------------------------------------------------------------
// Pipeline simulation for a single file
// ---------------------------------------------------------------------------

function simulateFile(filePath: string, manifestLookup: ManifestLookup): FileSample {
  const code        = fs.readFileSync(filePath, "utf-8");
  const lineCount   = code.split("\n").length;
  const cwe_id      = detectCWE(filePath, code);

  // Manifest ground-truth lookup — normalise to forward slashes for cross-platform match
  const relKey      = path.relative(VULNERABLE_CODE_DIR, filePath).replace(/\\/g, "/");
  const manifest_cwe = manifestLookup[relKey] ?? null;

  // CWE_SEVERITY lookup — fail-closed default 80
  const cweSeverityMap = RESEARCH_CONFIG.CWE_SEVERITY as Record<string, number>;
  const severity_base  = cweSeverityMap[cwe_id] ?? 80;

  // Synthetic confidence: high for clear-pattern CWEs, lower for generic
  const confidence = cwe_id !== DEFAULT_CWE ? 0.87 : 0.72;

  const lane        = assignLane(severity_base);
  const lane_weight = computeLaneWeight(lane);

  // Synthetic patch: assume a minimal 8% diff for normal files, smaller for tiny files
  const change_percent = lineCount < RESEARCH_CONFIG.SMALL_FILE_MAX_LINES ? 5 : 8;
  const patch_risk     = computePatchRisk(change_percent);

  // Simulate judge: runs when patch guard passes (which it always does at 5–8%)
  const judge_was_run  = true;
  // Judge approves when confidence is high and CWE is well-known
  const judge_approved = confidence >= 0.85 && cwe_id !== DEFAULT_CWE;

  const verification_bonus = computeVerificationBonus(confidence, lane_weight, judge_approved);
  const judgePenalty       = judge_was_run && !judge_approved ? 10 : 0;

  const base_score  = computePriorityScore(
    severity_base, confidence, judgePenalty, patch_risk, lane_weight, 0,
  );
  const final_score = base_score + verification_bonus;

  const action: "pr_opened" | "issue_escalated" =
    final_score >= RESEARCH_CONFIG.AUTO_MERGE_THRESHOLD ? "pr_opened" : "issue_escalated";

  const routing_status: "fixed" | "cannot_fix" = action === "pr_opened" ? "fixed" : "cannot_fix";

  // Integrity check — mirrors State Integrity Matrix in index.ts
  const integrity_ok =
    !(routing_status === "fixed"      && action === "issue_escalated") &&
    !(routing_status === "cannot_fix" && action === "pr_opened");

  return {
    file: path.relative(VULNERABLE_CODE_DIR, filePath),
    cwe_id,
    manifest_cwe,
    severity_base,
    confidence,
    lane,
    lane_weight,
    change_percent,
    patch_risk,
    judge_was_run,
    judge_approved,
    verification_bonus,
    final_score: Math.min(100, final_score), // clamp post-bonus
    action,
    integrity_ok,
    routing_status,
  };
}

// ---------------------------------------------------------------------------
// Baseline regression detection
// ---------------------------------------------------------------------------

function loadBaseline(): BaselineRecord | null {
  if (!fs.existsSync(BASELINE_PATH)) return null;
  try {
    return JSON.parse(fs.readFileSync(BASELINE_PATH, "utf-8")) as BaselineRecord;
  } catch {
    return null;
  }
}

function saveBaseline(samples: FileSample[]): void {
  const record: BaselineRecord = {};
  for (const s of samples) record[s.file] = s.action;
  fs.writeFileSync(BASELINE_PATH, JSON.stringify(record, null, 2));
  console.log(`[EVAL] Baseline saved to ${BASELINE_PATH}`);
}

function countRegressions(samples: FileSample[], baseline: BaselineRecord): number {
  let count = 0;
  for (const s of samples) {
    const prior = baseline[s.file];
    // Regression: previously passed (pr_opened) now fails (issue_escalated)
    if (prior === "pr_opened" && s.action === "issue_escalated") {
      console.warn(`[REGRESSION] ${s.file}: was pr_opened, now issue_escalated`);
      count++;
    }
  }
  return count;
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

function main(): void {
  console.log("[EVAL] DevSecure v4.0 — Dual-Objective Evaluator");
  console.log(`[EVAL] Scanning: ${VULNERABLE_CODE_DIR}`);

  const manifestLookup = loadManifest();
  const files = collectSourceFiles(VULNERABLE_CODE_DIR);
  if (files.length === 0) {
    console.error("[EVAL] No source files found in vulnerable_code/. Nothing to evaluate.");
    process.exit(1);
  }

  console.log(`[EVAL] Found ${files.length} source file(s).`);

  // Simulate pipeline for every file
  const samples: FileSample[] = files.map((f) => simulateFile(f, manifestLookup));

  // ── ResearchReport fields ────────────────────────────────────────────────

  const total_samples    = samples.length;
  const safe_fix_count   = samples.filter((s) => s.action === "pr_opened").length;
  const escalation_count = samples.filter((s) => s.action === "issue_escalated").length;
  const safe_fix_rate    = parseFloat((safe_fix_count / total_samples).toFixed(4));
  const escalation_rate  = parseFloat((escalation_count / total_samples).toFixed(4));
  const avg_priority_score = parseFloat(
    (samples.reduce((sum, s) => sum + s.final_score, 0) / total_samples).toFixed(2),
  );

  const integrity_failures = samples.filter((s) => !s.integrity_ok).length;

  // severity_floor_violations: CWE severity >= 85 but final_score < 60
  const severity_floor_violations = samples.filter(
    (s) => s.severity_base >= 85 && s.final_score < 60,
  ).length;

  // bonus_cap_violations: verification_bonus strictly exceeds lane_weight
  const bonus_cap_violations = samples.filter(
    (s) => s.verification_bonus > s.lane_weight,
  ).length;

  // threshold_tamper_detected: AUTO_MERGE_THRESHOLD must be exactly 70
  const threshold_tamper_detected = RESEARCH_CONFIG.AUTO_MERGE_THRESHOLD !== 70;

  // Regression detection — compare against baseline if it exists
  const baseline            = loadBaseline();
  const regression_detected = baseline ? countRegressions(samples, baseline) : 0;

  // If no baseline yet, save one for future runs
  if (!baseline) saveBaseline(samples);

  // CWE coverage — count samples per CWE
  const cwe_coverage: Record<string, number> = {};
  for (const s of samples) {
    cwe_coverage[s.cwe_id] = (cwe_coverage[s.cwe_id] ?? 0) + 1;
  }

  // ── Invariant 6: Classification Accuracy ─────────────────────────────────
  // Count manifest-covered files whose detected CWE diverges from ground truth.
  let classification_mismatch_count = 0;
  for (const s of samples) {
    if (s.manifest_cwe !== null && s.cwe_id !== s.manifest_cwe) {
      console.warn(
        `[MISMATCH] ${s.file}: detected=${s.cwe_id} expected=${s.manifest_cwe}`,
      );
      classification_mismatch_count++;
    }
  }

  // ── Invariant 7: Confidence Calibration ──────────────────────────────────
  // Detects if every sample is blindly stamped with high confidence (reward hacking).
  const avg_confidence_score = parseFloat(
    (samples.reduce((sum, s) => sum + s.confidence, 0) / total_samples).toFixed(4),
  );
  const confidence_spike_detected = avg_confidence_score > 0.95;

  // ── Invariant 8: Prompt Mutation Limit ───────────────────────────────────
  // Compares src/prompts_target.ts against scripts/prompts_baseline.snapshot.
  // The snapshot is a human-only artifact — never updated by the autoresearch agent.
  const promptLineDiff      = countPromptLineDiff();
  const prompt_diff_violation = promptLineDiff > 5;
  if (prompt_diff_violation) {
    console.warn(`[PROMPT-DIFF] ${promptLineDiff} lines changed (limit: 5)`);
  }

  const report: ResearchReport = {
    total_samples,
    safe_fix_count,
    safe_fix_rate,
    escalation_count,
    escalation_rate,
    avg_priority_score,
    integrity_failures,
    regression_detected,
    severity_floor_violations,
    bonus_cap_violations,
    threshold_tamper_detected,
    classification_mismatch_count,
    avg_confidence_score,
    confidence_spike_detected,
    prompt_diff_violation,
    cwe_coverage,
  };

  // ── Hard Safety Invariant Checks ─────────────────────────────────────────

  const violations: string[] = [];

  if (integrity_failures > 0)
    violations.push(`integrity_failures = ${integrity_failures} (routing integrity violations detected)`);
  if (severity_floor_violations > 0)
    violations.push(`severity_floor_violations = ${severity_floor_violations} (CWE severity >= 85 scored below 60)`);
  if (bonus_cap_violations > 0)
    violations.push(`bonus_cap_violations = ${bonus_cap_violations} (VerificationBonus exceeds LaneWeight)`);
  if (threshold_tamper_detected)
    violations.push(`threshold_tamper_detected = true (AUTO_MERGE_THRESHOLD !== 70)`);
  if (regression_detected > 0)
    violations.push(`regression_detected = ${regression_detected} (previously passing files now escalated)`);
  if (classification_mismatch_count > 0)
    violations.push(`classification_mismatch_count = ${classification_mismatch_count} (detected CWE diverges from corpus_manifest ground truth)`);
  if (confidence_spike_detected)
    violations.push(`confidence_spike_detected = true (avg_confidence=${avg_confidence_score} > 0.95 — possible reward hacking)`);
  if (prompt_diff_violation)
    violations.push(`prompt_diff_violation = true (${promptLineDiff} lines changed in prompts_target.ts vs baseline snapshot — limit is 5)`);

  // ── Output ────────────────────────────────────────────────────────────────

  console.log("\n── ResearchReport ──────────────────────────────────────────────────────");
  console.log(JSON.stringify(report, null, 2));

  console.log("\n── Per-File Results ────────────────────────────────────────────────────");
  for (const s of samples) {
    const flag     = s.action === "pr_opened" ? "✅" : "⚠️ ";
    const mismatch = s.manifest_cwe && s.manifest_cwe !== s.cwe_id ? ` ⚡MISMATCH(expected=${s.manifest_cwe})` : "";
    console.log(
      `${flag} [${s.action.padEnd(16)}] score=${String(s.final_score).padStart(3)} ` +
      `cwe=${s.cwe_id} lane=${s.lane} bonus=${s.verification_bonus} | ${s.file}${mismatch}`,
    );
  }

  if (violations.length > 0) {
    console.error("\n\nSAFETY CONSTRAINTS VIOLATED");
    console.error("────────────────────────────");
    for (const v of violations) console.error(`  ✗ ${v}`);
    console.error("");
    process.exit(1);
  }

  console.log("\n[EVAL] All safety invariants passed.");
  process.exit(0);
}

main();
