// Author: Jeremy Quadri
// devsecure-orchestrator: Cloudflare Worker
// Fail-closed vulnerability classification and automated remediation pipeline.
// Pipeline: POST /remediate → Qwen2.5 classify → Vectorize RAG → Qwen3 fix → GitHub PR | Issue

import { getEmbedding } from "./embed";
import { seedCWEData } from "./seed-data";
import type { Env } from "./env";

// HF Inference Router — primary 2026 endpoint; model dispatched via body "model" field
const HF_CHAT_URL = "https://router.huggingface.co/v1/chat/completions";
// Fallback model IDs — overridden at runtime by env.CLASSIFIER_MODEL / env.REMEDIATION_MODEL
const DEFAULT_CLASSIFIER_MODEL = "Qwen/Qwen2.5-Coder-7B-Instruct";
const DEFAULT_REMEDIATION_MODEL = "Qwen/Qwen2.5-Coder-32B-Instruct";
const GITHUB_API = "https://api.github.com";

// Env is defined in env.ts and imported above.

// ---------------------------------------------------------------------------
// Request / Response shapes
// ---------------------------------------------------------------------------

interface DsDetection {
  type: string;               // detection rule type
  rule_id: string;            // unique rule identifier
  cwe_hint?: string;          // used for mismatch detection — never the final CWE
  scanner_severity?: string;  // L1 scanner severity — V2.0 primary priority signal
                              // ("critical" | "high" | "medium" | "low")

  // Detection Normalisation Layer: accepted for schema compatibility but DISCARDED —
  // the L2 LLM Classification Plane (Qwen2.5) is the sole source of CWE and confidence.
  scanner_confidence?: unknown;
  scanner_cwe?: unknown;
}

interface CodeContext {
  snippet: string;    // source code to analyse
  language: string;   // language identifier
}

interface RemediationRequest {
  repo: string;         // "owner/repo-name"
  file_path: string;    // relative path in repo, e.g. "src/auth.py"
  code: string;         // raw vulnerable source code (legacy field)
  language: string;     // "python" | "javascript" | etc. (legacy field)
  base_branch?: string; // branch to target, defaults to "main"
  ds_detection?: DsDetection;  // normalized detection input layer
  code_context?: CodeContext;  // normalized code input layer
}

interface ClassificationResult {
  cwe_id: string;       // e.g. "CWE-89"
  cwe_name: string;     // e.g. "SQL Injection"
  confidence: number;   // 0.0 – 1.0
  lane: number;         // 1 = trivial → 4 = architectural / cannot assess
  summary: string;      // one-sentence description
}

// HiddenSignalLayer — internal only; never serialised to API responses or full logs
interface HiddenSignalLayer {
  source_type: string;       // detection origin (e.g. "sast", "dast", "manual")
  cwe_hint?: string;         // vendor-supplied CWE; used only for mismatch detection
  scanner_severity?: string; // L1 severity; forwarded to priority scoring
}

interface RemediationResult {
  status: "fixed" | "cannot_fix";
  search_replace_block?: string; // raw <<<< SEARCH / ==== / >>>> REPLACE text
  reason?: string;
}

// Failure classification — determines advisory tone and structured log field.
// infra    = transient/infrastructure error (atob, network, parsing, judge unavailable)
// model    = LLM produced invalid/non-parseable output
// policy   = gate decision (lane, confidence, patch size, score, judge reject)
// validation = schema constraint violated
type FailureType = "infra" | "model" | "policy" | "validation";

// ---------------------------------------------------------------------------
// HuggingFace helpers
// ---------------------------------------------------------------------------

async function hfChat(
  model: string,
  messages: Array<{ role: string; content: string }>,
  apiKey: string,
  maxTokens = 1024,
): Promise<string> {
  const res = await fetch(HF_CHAT_URL, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${apiKey}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({ model, messages, max_tokens: maxTokens, stream: false }),
  });

  if (!res.ok) {
    const errorText = await res.text();
    console.error(
      `HF chat error — model: ${model} | HTTP: ${res.status} | URL: ${HF_CHAT_URL} | body: ${errorText}`,
    );
    throw new Error(`HF chat error [${model}]: HTTP ${res.status} – ${errorText}`);
  }

  const data = (await res.json()) as {
    choices: Array<{ message: { content: string } }>;
  };
  return data.choices[0].message.content.trim();
}

// getEmbedding is imported from ./embed (uses Cloudflare Workers AI)

// ---------------------------------------------------------------------------
// Step 1 — Classification (Qwen2.5-Coder)
// ---------------------------------------------------------------------------

async function classify(
  code: string,
  language: string,
  apiKey: string,
  env: Env,
): Promise<ClassificationResult> {
  const system = `You are a senior application security engineer specialising in static analysis.
Analyse the provided source code and return ONLY raw JSON. No markdown formatting, no backticks, no explanations.

Required schema:
{
  "cwe_id":     "CWE-<number>",
  "cwe_name":   "<short CWE name>",
  "confidence": <0.0-1.0>,
  "lane":       <1|2|3|4>,
  "summary":    "<one sentence describing the vulnerability and its location>"
}

Lane assignment guide:
  1 — Trivial: rename, constant swap, single-line sanitiser call
  2 — Localised: logic change within one function, parameterised query, encoding fix
  3 — Moderate: multi-function refactor, interface change, new dependency required
  4 — Architectural or cannot assess: systemic design flaw, insufficient context

Output the JSON object and nothing else. Do not wrap it in a code block.`;

  const user = `Language: ${language}\n\nVulnerable code:\n\`\`\`${language}\n${code}\n\`\`\``;

  const classifierModel = env.CLASSIFIER_MODEL || DEFAULT_CLASSIFIER_MODEL;
  const raw = await hfChat(
    classifierModel,
    [{ role: "system", content: system }, { role: "user", content: user }],
    apiKey,
    512,
  );

  // Sanitise: slice from first '{' to last '}' to strip any surrounding markdown or prose
  const first = raw.indexOf("{");
  const last  = raw.lastIndexOf("}");
  if (first === -1 || last === -1 || last <= first) {
    console.error(JSON.stringify({ event: "classify_no_json", raw_output: raw.slice(0, 500) }));
    throw new Error(`L2 Classifier returned no JSON object. Raw: ${raw.slice(0, 300)}`);
  }
  const jsonSlice = raw.slice(first, last + 1);

  try {
    return JSON.parse(jsonSlice) as ClassificationResult;
  } catch (parseErr) {
    console.error(JSON.stringify({
      event:       "classify_json_parse_failed",
      error:       parseErr instanceof Error ? parseErr.message : String(parseErr),
      raw_output:  raw.slice(0, 500),
      json_slice:  jsonSlice.slice(0, 500),
    }));
    // Graceful fallback — pipeline will escalate via low confidence + lane 4
    return { error: "invalid_json", confidence: 0, status: "failed" } as unknown as ClassificationResult;
  }
}

// ---------------------------------------------------------------------------
// Step 2 — RAG context retrieval (Cloudflare Vectorize)
// ---------------------------------------------------------------------------

async function retrieveRagContext(
  cweId: string,
  summary: string,
  vectorIndex: Vectorize,
  env: Env,
): Promise<string> {
  const queryText = `${cweId} remediation secure coding pattern: ${summary}`;
  const vector = await getEmbedding(queryText, env);

  const results = await vectorIndex.query(vector, { topK: 3, returnMetadata: "all" });

  if (!results.matches || results.matches.length === 0) {
    return `No RAG context found in cwe-knowledge-base for ${cweId}.`;
  }

  return results.matches
    .map((m, i) => {
      const meta = m.metadata as Record<string, string> | undefined;
      const text = meta?.text ?? meta?.content ?? JSON.stringify(meta ?? {});
      return `[RAG Context ${i + 1} | score: ${m.score.toFixed(3)}]\n${text}`;
    })
    .join("\n\n---\n\n");
}

// ---------------------------------------------------------------------------
// Step 3 — Remediation (Qwen3)
// ---------------------------------------------------------------------------

async function remediate(
  code: string,
  language: string,
  classification: ClassificationResult,
  ragContext: string,
  apiKey: string,
  env: Env,
): Promise<RemediationResult> {
  const system = `You are an expert secure-code engineer. You will receive vulnerable source code, a structured vulnerability classification, and RAG context containing CWE-indexed secure coding patterns and verified historical patch exemplars.

Your task: produce the minimal security fix — only change what is required to eliminate the vulnerability.

CRITICAL OUTPUT RULES:
- Return ONLY valid JSON — no prose, no markdown fences, no explanation outside the JSON
- NEVER output the full file or any unmodified code
- Express the fix as a SINGLE search/replace block in the "search_replace_block" field
- The block MUST use this EXACT format (delimiters on their own lines):

<<<< SEARCH
[exact original lines — must match the file character-for-character, including indentation and blank lines]
====
[new secured lines — only the minimal change to eliminate the vulnerability]
>>>> REPLACE

If you can fix the vulnerability with confidence ≥ 0.75:
{"status":"fixed","search_replace_block":"<<<< SEARCH\\n[exact original]\\n====\\n[fixed lines]\\n>>>> REPLACE"}

Otherwise (low confidence, architectural issue, or insufficient context):
{"status":"cannot_fix","reason":"<concise explanation for the L4 human reviewer>"}

Hard constraints:
- Do NOT output more than one search/replace block
- The SEARCH text MUST exactly match the existing source — character for character, including whitespace
- Your <<<< SEARCH block MUST include at least 2 lines of surrounding context (lines before and after the vulnerability) to ensure exact matching during the replacement phase
- Ensure all newlines within the search_replace_block string are properly escaped as \\n so the JSON remains valid
- Do NOT alter program behaviour beyond the security fix
- Do NOT add features, refactor unrelated code, or change formatting
- Preserve all original comments, variable names, and indentation

CRITICAL — Anti-Duplication Rule:
- When modifying a variable that is immediately used in an execution statement (e.g., parameterizing a SQL query assigned to a variable and then passed to cursor.execute), your <<<< SEARCH block MUST include BOTH the original variable assignment AND the execution statement that uses it.
- If you include only the variable assignment in your SEARCH block but add a new execution statement in your REPLACE block, the original execution statement will remain untouched in the file, producing a duplicate execution bug that runs the query twice with inconsistent arguments.
- Always capture the full logical block being modified. If changing a query string, your SEARCH block must span from the string assignment through to the line where it is executed.

SECURITY AUDIT TRAIL:
- Your REPLACE block MUST begin with the following formal audit header using the correct comment syntax for the target language, before any code lines:
  [SECURITY REMEDIATION]
  TYPE: {CWE_ID}
  TIMESTAMP: {ISO_DATE}
  BY: DevSecure Autonomous Surgeon (L3-32B)
- Use // for JavaScript/TypeScript/Java/C#/Dart, # for Python/Ruby/PHP, -- for SQL.
- Place this header immediately above the first changed line in your REPLACE block.`;

  const user = `## Vulnerability Classification (from Qwen2.5)
\`\`\`json
${JSON.stringify(classification, null, 2)}
\`\`\`

## RAG Context — CWE Knowledge Base (${classification.cwe_id})
${ragContext}

## Original ${language} code to fix
\`\`\`${language}
${code}
\`\`\``;

  const remediationModel = env.REMEDIATION_MODEL || DEFAULT_REMEDIATION_MODEL;
  const raw = await hfChat(
    remediationModel,
    [{ role: "system", content: system }, { role: "user", content: user }],
    apiKey,
    2048,
  );

  const match = raw.match(/\{[\s\S]*\}/);
  if (!match) {
    console.error("RAW LLM OUTPUT:", raw);
    throw new Error(`Remediation model did not return JSON. Raw output: ${raw}`);
  }

  // ── Primary path: strict JSON.parse ──────────────────────────────────────
  let result: RemediationResult;
  try {
    result = JSON.parse(match[0]) as RemediationResult;
    return result;
  } catch (e) {
    const parseErr = e instanceof Error ? e.message : String(e);
    console.error(`Remediation JSON parse failed (${parseErr}) — attempting raw-text fallback`);
  }

  // ── Fallback: raw-text regex extraction ──────────────────────────────────
  // The 32B model sometimes emits unescaped newlines inside the JSON string
  // literal for search_replace_block, producing "Bad control character" errors.
  // Rather than failing, we extract the status and the block directly from the
  // raw LLM output, making the patch text the source of truth instead of the
  // JSON envelope.

  const statusMatch = raw.match(/"status"\s*:\s*"(fixed|cannot_fix)"/);
  if (!statusMatch) {
    console.error("RAW LLM OUTPUT:", raw);
    throw new Error("Remediation JSON parse failed and raw-text fallback could not extract status");
  }
  const status = statusMatch[1] as "fixed" | "cannot_fix";

  if (status === "cannot_fix") {
    // Extract reason if present; safe to return without a block
    const reasonMatch = raw.match(/"reason"\s*:\s*"([^"]+)"/);
    console.log("Raw-text fallback: cannot_fix extracted");
    return { status: "cannot_fix", reason: reasonMatch?.[1] ?? "Model returned cannot_fix (raw-text fallback)" };
  }

  // status === "fixed" — extract the search/replace block directly from raw text.
  // No JSON.parse: the 32B model mixes unescaped and escaped quotes, making any
  // JSON token reconstruction unreliable. The raw block is the source of truth.
  const blockMatch = raw.match(/(<<<< SEARCH[\s\S]*?>>>> REPLACE)/);
  if (!blockMatch) {
    console.error("RAW LLM OUTPUT:", raw);
    throw new Error("Remediation JSON parse failed and raw-text fallback could not extract search/replace block");
  }

  // Undo JSON escape sequences the model emitted inside the string value.
  // No JSON.parse — the mixed-quote environment makes token reconstruction unsafe.
  // Order is critical: double-backslashes must be resolved first so that \\n is
  // not mistakenly converted to a real newline before \\\\ is collapsed.
  const decodedBlock = blockMatch[1]
    .replace(/\\\\/g, "\\")   // \\\\ → \   (collapse double-backslashes first)
    .replace(/\\"/g, '"')      // \\"  → "   (unescape escaped quotes)
    .replace(/\\n/g, "\n")     // \n   → LF  (literal backslash-n → real newline)
    .replace(/\\r/g, "\r")     // \r   → CR
    .replace(/\\t/g, "\t");    // \t   → TAB

  console.log(JSON.stringify({ event: "remediation_fallback_used", block_length: decodedBlock.length }));
  return { status: "fixed", search_replace_block: decodedBlock };
}

// ---------------------------------------------------------------------------
// Schema validation
// ---------------------------------------------------------------------------

function validateRemediation(result: RemediationResult): void {
  if (!result || !result.status) {
    throw new Error("Invalid remediation: missing status");
  }
  if (result.status !== "fixed" && result.status !== "cannot_fix") {
    throw new Error(`Invalid remediation: unknown status "${result.status}"`);
  }
  if (result.status === "fixed") {
    if (!result.search_replace_block || result.search_replace_block.trim() === "") {
      throw new Error("Invalid remediation: search_replace_block is missing or empty");
    }
  }
  if (result.status === "cannot_fix") {
    if (!result.reason || result.reason.trim() === "") {
      throw new Error("Invalid remediation: reason is missing or empty");
    }
  }
}

// ---------------------------------------------------------------------------
// Auto-retry wrapper (max 2 attempts)
// ---------------------------------------------------------------------------

async function remediateWithRetry(
  code: string,
  language: string,
  classification: ClassificationResult,
  ragContext: string,
  apiKey: string,
  env: Env,
): Promise<RemediationResult> {
  const MAX_ATTEMPTS = 2;
  for (let attempt = 1; attempt <= MAX_ATTEMPTS; attempt++) {
    try {
      console.log("Remediation attempt:", attempt);
      const result = await remediate(code, language, classification, ragContext, apiKey, env);
      validateRemediation(result);
      return result;
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      console.error(`Schema validation failed on attempt ${attempt}:`, msg);
      if (attempt === MAX_ATTEMPTS) {
        console.error("Remediation retry exhausted after", MAX_ATTEMPTS, "attempts. Last error:", msg);
        throw err;
      }
      console.log(`Retrying remediation (attempt ${attempt + 1} of ${MAX_ATTEMPTS})...`);
    }
  }
  throw new Error("remediateWithRetry: exhausted attempts");
}

// ---------------------------------------------------------------------------
// safeAtob — Base64 decoder tolerant of whitespace and plaintext payloads
// ---------------------------------------------------------------------------

function safeAtob(input: string): string {
  const cleaned = input.replace(/\s/g, "");
  try {
    return atob(cleaned);
  } catch (err) {
    console.error(
      `[safeAtob] Invalid Base64 — falling back to raw string. Error: ${err instanceof Error ? err.message : String(err)}`,
    );
    return input;
  }
}

// ---------------------------------------------------------------------------
// Search/Replace patch applicator
// ---------------------------------------------------------------------------

// Applies one or more <<<< SEARCH / ==== / >>>> REPLACE blocks produced by
// the remediation model to the original source string.
//
// Matching strategy — single pass, always line-by-line fuzzy:
//   Both the original file and the SEARCH block are split into line arrays.
//   Each pair of lines is compared using .trim() on BOTH sides so indentation
//   and trailing whitespace differences from the LLM are completely ignored
//   during the matching phase.  The original file lines are NEVER mutated.
//
//   Once the matching window is located the REPLACE lines are re-anchored to
//   the base indentation of the first matched original line so the resulting
//   file preserves syntactic structure (no Python IndentationError).
//
// Invariants (all throw on violation — caller must catch and classify as "model"):
//   - At least one well-formed block must be present.
//   - Empty SEARCH blocks are rejected (would silently match everywhere).
//   - If the line sequence cannot be found, the "SEARCH text not found" error
//     is thrown to maintain the Fail-Closed moat.
//
// Multiple blocks are applied in order; each block operates on the already-
// patched line array so relative positions remain stable.
// ---------------------------------------------------------------------------
// Security audit trail header — prepended deterministically after patch applied
// ---------------------------------------------------------------------------

function buildAuditHeader(language: string, cweId: string): string {
  const today = new Date().toISOString().slice(0, 10); // YYYY-MM-DD
  const lines = [
    `[SECURITY REMEDIATION]`,
    `TYPE: ${cweId}`,
    `TIMESTAMP: ${today}`,
    `BY: DevSecure Autonomous Surgeon (L3-32B)`,
  ];
  const commentChar = /^(python|ruby|php|bash|perl|r)$/i.test(language) ? "#"
    : /^(sql|lua|haskell)$/i.test(language) ? "--"
    : "//";
  return lines.map(l => `${commentChar} ${l}`).join("\n") + "\n";
}

function prependAuditHeader(patchedCode: string, language: string, cweId: string): string {
  const header = buildAuditHeader(language, cweId);
  // Idempotent: don't double-add if the model already injected it
  if (patchedCode.includes("[SECURITY REMEDIATION]")) return patchedCode;
  return header + patchedCode;
}

function applySearchReplace(original: string, llmOutput: string): string {
  // Regex: tolerates optional \r before each \n (CRLF-safe)
  // \s* absorbs trailing spaces on the tag lines.
  // =+ accepts any run of equals signs (e.g. git-conflict-style "=======" or "====").
  const BLOCK_RE = /<<<< SEARCH\s*\r?\n([\s\S]*?)\r?\n=+\s*\r?\n([\s\S]*?)\r?\n>>>> REPLACE/g;

  const blocks: Array<{ search: string; replace: string }> = [];
  let m: RegExpExecArray | null;
  while ((m = BLOCK_RE.exec(llmOutput)) !== null) {
    blocks.push({ search: m[1], replace: m[2] });
  }

  if (blocks.length === 0) {
    throw new Error("Malformed search/replace block: no valid <<<< SEARCH / ==== / >>>> REPLACE structure found");
  }

  // Work entirely on a mutable line array; never use whole-string indexOf/replace.
  let resultLines = original.split("\n");

  for (const { search, replace } of blocks) {
    if (!search || search.trim() === "") {
      throw new Error("Malformed search/replace block: SEARCH section is empty");
    }

    // ── Line-by-line fuzzy match ──────────────────────────────────────────
    // Trim both sides during comparison only — originals are read-only here.
    const searchLines   = search.split("\n");
    const trimmedSearch = searchLines.map(l => l.trim());

    let matchStart = -1;
    outer: for (let i = 0; i <= resultLines.length - searchLines.length; i++) {
      for (let j = 0; j < searchLines.length; j++) {
        if (resultLines[i + j].trim() !== trimmedSearch[j]) continue outer;
      }
      matchStart = i;
      break;
    }

    if (matchStart === -1) {
      throw new Error("Malformed search/replace block or context mismatch: SEARCH text not found in original code");
    }

    // ── Indentation re-anchoring ──────────────────────────────────────────
    // Derive base indent from the first matched original line (read-only).
    // Apply the same base to all REPLACE lines, preserving relative depth.
    const origBaseIndent    = resultLines[matchStart].match(/^(\s*)/)?.[1] ?? "";
    const replaceLines      = replace.split("\n");
    const firstNonEmpty     = replaceLines.find(l => l.trim() !== "") ?? "";
    const replaceBaseIndent = firstNonEmpty.match(/^(\s*)/)?.[1] ?? "";

    const reindented = replaceLines.map(line => {
      if (line.trim() === "") return line;                          // preserve blank lines as-is
      const lineIndent = line.match(/^(\s*)/)?.[1] ?? "";
      const extra      = lineIndent.length - replaceBaseIndent.length; // relative depth delta
      return origBaseIndent + " ".repeat(Math.max(0, extra)) + line.trimStart();
    });

    // ── Splice matched range with re-indented replacement ─────────────────
    resultLines = [
      ...resultLines.slice(0, matchStart),
      ...reindented,
      ...resultLines.slice(matchStart + searchLines.length),
    ];
  }

  return resultLines.join("\n");
}

// ---------------------------------------------------------------------------
// Advisory Agent — root cause + abstract remediation strategy (no code)
// ---------------------------------------------------------------------------

const ADVISORY_TIMEOUT_MS = 5000;

// Patterns that indicate the advisory model generated executable content.
// On match, the output is discarded and the deterministic fallback is used.
const ADVISORY_FORBIDDEN: RegExp[] = [
  /\b(def |function |class )\s*\w+\s*\(/m,
  /\b(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE)\b[\s\S]{0,200}\b(FROM|INTO|TABLE|WHERE|SET)\b/i,
  /```[\s\S]*\n[\s\S]*\n[\s\S]*\n/,
];

async function generateAdvisory(
  classification: ClassificationResult,
  failureType: FailureType,
  env: Env,
): Promise<string> {
  const fallback = `Root cause: ${classification.cwe_name} vulnerability present in the affected file. `
    + `Remediation strategy: Apply ${classification.cwe_id}-compliant secure coding patterns per OWASP guidelines. `
    + `No verified fix could be safely generated.`;

  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), ADVISORY_TIMEOUT_MS);

  try {
    const model = env.CLASSIFIER_MODEL || DEFAULT_CLASSIFIER_MODEL;
    const res = await fetch(HF_CHAT_URL, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${env.HF_API_KEY}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        model,
        messages: [
          {
            role: "system",
            content: `You are a security advisory writer. Your ONLY task is to explain vulnerability root cause and abstract remediation strategy in plain prose.
STRICT CONSTRAINTS — violation discards your output:
- No executable code of any kind
- No SQL queries
- No function or class definitions
- No code fences with more than one line of content
- Maximum 3 short paragraphs. Plain prose only.`,
          },
          {
            role: "user",
            content: `Vulnerability: ${classification.cwe_id} — ${classification.cwe_name}
Summary: ${classification.summary}
Failure classification: ${failureType}
Provide: (1) Root cause in one sentence. (2) Abstract remediation strategy in one sentence. (3) One safe pattern description — no code.`,
          },
        ],
        max_tokens: 256,
        stream: false,
      }),
      signal: controller.signal,
    });

    if (!res.ok) throw new Error(`Advisory model HTTP ${res.status}`);

    const data = (await res.json()) as { choices: Array<{ message: { content: string } }> };
    const advisory = data.choices[0].message.content.trim();

    for (const pattern of ADVISORY_FORBIDDEN) {
      if (pattern.test(advisory)) {
        console.error(JSON.stringify({ event: "advisory_validation_rejected", cwe_id: classification.cwe_id, failure_type: failureType }));
        return fallback;
      }
    }

    return advisory;
  } catch (err) {
    const reason = err instanceof Error ? err.message : String(err);
    console.error(JSON.stringify({ event: "advisory_generation_failed", reason, cwe_id: classification.cwe_id }));
    return "Advisory unavailable due to generation failure.";
  } finally {
    clearTimeout(timeoutId);
  }
}

// ---------------------------------------------------------------------------
// Issue idempotency — find existing open L4 issue for same repo+file+CWE
// ---------------------------------------------------------------------------

async function findExistingIssue(
  repo: string,
  filePath: string,
  cweId: string,
  pat: string,
): Promise<{ number: number; html_url: string } | null> {
  try {
    const res = await ghFetch(
      `/repos/${repo}/issues?state=open&labels=L4-escalation&per_page=50`,
      "GET",
      pat,
    );
    if (!res.ok) return null;
    const issues = (await res.json()) as Array<{ number: number; html_url: string; title: string }>;
    const match = issues.find(
      (i) => i.title.includes(`[L4 Escalation] ${cweId}`) && i.title.includes(filePath),
    );
    return match ? { number: match.number, html_url: match.html_url } : null;
  } catch {
    return null;
  }
}

// ---------------------------------------------------------------------------
// Patch Guard — diff size check
// ---------------------------------------------------------------------------

interface PatchGuardResult {
  allowed: boolean;
  originalLines: number;
  fixedLines: number;
  changedLines: number;
  changePercent: number;
  reason?: string;
}

function checkPatchGuard(original: string, fixed: string): PatchGuardResult {
  const originalLines = original.split("\n");
  const fixedLines = fixed.split("\n");
  const originalCount = originalLines.length;
  const fixedCount = fixedLines.length;
  const originalBytes = original.length;
  const fixedBytes = fixed.length;

  // Line-based diff: count lines not present in the other set (symmetric diff)
  const originalSet = new Map<string, number>();
  for (const line of originalLines) {
    originalSet.set(line, (originalSet.get(line) ?? 0) + 1);
  }
  const fixedSet = new Map<string, number>();
  for (const line of fixedLines) {
    fixedSet.set(line, (fixedSet.get(line) ?? 0) + 1);
  }
  let changedLines = 0;
  for (const [line, count] of originalSet) {
    const fixedCount2 = fixedSet.get(line) ?? 0;
    if (count > fixedCount2) changedLines += count - fixedCount2;
  }
  for (const [line, count] of fixedSet) {
    const origCount2 = originalSet.get(line) ?? 0;
    if (count > origCount2) changedLines += count - origCount2;
  }

  const changePercent = originalCount > 0 ? (changedLines / originalCount) * 100 : 100;
  const sizeRatio = originalBytes > 0 ? fixedBytes / originalBytes : Infinity;

  // Absolute Floor: small targeted fixes (≤ 10 changed lines) are always allowed
  // regardless of changePercent. The 20% limit is only meaningful on larger files;
  // on a 20-line file a 5-line security fix legitimately exceeds 20% without risk.
  const absoluteFloor = changedLines <= 10;

  const violations: string[] = [];
  if (!absoluteFloor && changePercent > 20) {
    violations.push(`${changePercent.toFixed(1)}% of lines changed (limit: 20%)`);
  }
  if (changedLines > 50) {
    violations.push(`${changedLines} absolute lines changed (limit: 50)`);
  }
  if (sizeRatio > 2) {
    violations.push(`file size increased ${sizeRatio.toFixed(2)}x (limit: 2x)`);
  }
  if (sizeRatio < 0.5) {
    violations.push(`file size decreased to ${(sizeRatio * 100).toFixed(1)}% of original (limit: 50%)`);
  }

  const allowed = violations.length === 0;
  console.log(JSON.stringify({
    event: "patch_guard",
    originalLines: originalCount,
    fixedLines: fixedCount,
    changedLines,
    changePercent: parseFloat(changePercent.toFixed(1)),
    sizeRatio: parseFloat(sizeRatio.toFixed(2)),
    absoluteFloor,
    allowed,
  }));

  return {
    allowed,
    originalLines: originalCount,
    fixedLines: fixedCount,
    changedLines,
    changePercent,
    reason: allowed ? undefined : `Blocked by Patch Guard: ${violations.join("; ")}`,
  };
}

// ---------------------------------------------------------------------------
// RPS Score fetch
// ---------------------------------------------------------------------------

// Source-to-sink CWEs that require multi-line context to patch safely.
// The Diversity Judge is ALWAYS triggered for these, regardless of confidence
// or changePercent, to guard against incomplete or duplicated fix blocks.
const COMPLEX_CWES = ["CWE-89", "CWE-78", "CWE-22", "CWE-79", "CWE-94"];

// ---------------------------------------------------------------------------
// V2.0 Priority Scoring — L1 Severity × L2 Confidence
// ---------------------------------------------------------------------------

// Maps L1 scanner severity string to a 0-100 base score.
// Default 50 when the scanner did not supply a severity value.
const SEVERITY_WEIGHTS: Record<string, number> = {
  critical: 100,
  high:     80,
  medium:   50,
  low:      20,
};

// Compute the final priority score from L1 severity and L2 LLM confidence,
// then subtract pipeline penalties applied upstream (judge, patch risk, etc.).
function computePriorityScore(
  scannerSeverity: string | undefined,
  confidence: number,
  judgePenalty: number,
  patchRisk: number,
  laneWeight: number,
  mismatchPenalty: number,
): number {
  const baseScore = Math.round(
    (SEVERITY_WEIGHTS[(scannerSeverity ?? "").toLowerCase()] ?? 50) * confidence,
  );
  return Math.min(100, Math.max(0, baseScore - judgePenalty - patchRisk - laneWeight - mismatchPenalty));
}

// ---------------------------------------------------------------------------
// Diversity Judge
// ---------------------------------------------------------------------------

const OPENAI_CHAT_URL = "https://api.openai.com/v1/chat/completions";
const DEFAULT_JUDGE_MODEL = "gpt-4o-mini";
const JUDGE_TIMEOUT_MS = 5000;

interface JudgeVerdict {
  verdict: "approve" | "reject";
  confidence: number;
  issues: string[];
  reason: string;
}

async function judgeReview(
  originalCode: string,
  fixedCode: string,
  classification: ClassificationResult,
  env: Env,
): Promise<JudgeVerdict> {
  const model = env.JUDGE_MODEL || DEFAULT_JUDGE_MODEL;

  const system = `You are an independent security code reviewer. You will receive an original vulnerable code snippet, a proposed fix, and a vulnerability classification.

Your ONLY task is to critique the proposed fix. You MUST NOT generate new code.

Return ONLY a valid JSON object. No prose. No markdown. No explanation outside the JSON.

Required schema:
{
  "verdict": "approve" | "reject",
  "confidence": <0.0-1.0>,
  "issues": ["<issue description>", ...],
  "reason": "<concise one-sentence critique>"
}

verdict rules:
- "approve" if the fix correctly eliminates the vulnerability without breaking behaviour
- "reject" if the fix is incomplete, incorrect, introduces new risk, or alters unrelated behaviour

issues: empty array [] if no issues found.`;

  const user = `## Vulnerability Classification
\`\`\`json
${JSON.stringify(classification, null, 2)}
\`\`\`

## Original Code
\`\`\`
${originalCode.slice(0, 2000)}
\`\`\`

## Proposed Fix
\`\`\`
${fixedCode.slice(0, 2000)}
\`\`\``;

  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), JUDGE_TIMEOUT_MS);

  let raw: string;
  try {
    const res = await fetch(OPENAI_CHAT_URL, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${env.JUDGE_API_KEY}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        model,
        messages: [
          { role: "system", content: system },
          { role: "user", content: user },
        ],
        max_tokens: 512,
        stream: false,
      }),
      signal: controller.signal,
    });

    if (!res.ok) {
      const errText = await res.text();
      throw new Error(`Judge API error: HTTP ${res.status} — ${errText}`);
    }

    const data = (await res.json()) as { choices: Array<{ message: { content: string } }> };
    raw = data.choices[0].message.content.trim();
  } finally {
    clearTimeout(timeoutId);
  }

  const match = raw.match(/\{[\s\S]*\}/);
  if (!match) {
    throw new Error(`Judge did not return JSON. Raw output length: ${raw.length}`);
  }

  let verdict: JudgeVerdict;
  try {
    verdict = JSON.parse(match[0]) as JudgeVerdict;
  } catch (e) {
    throw new Error(`Judge JSON parse failed: ${e instanceof Error ? e.message : String(e)}`);
  }

  if (!verdict.verdict || (verdict.verdict !== "approve" && verdict.verdict !== "reject")) {
    throw new Error(`Judge returned invalid verdict: "${verdict.verdict}"`);
  }
  if (typeof verdict.confidence !== "number") {
    throw new Error("Judge response missing numeric confidence");
  }
  if (!verdict.reason || verdict.reason.trim() === "") {
    throw new Error("Judge response missing non-empty reason");
  }
  if (!Array.isArray(verdict.issues)) {
    throw new Error("Judge response missing issues array");
  }

  return verdict;
}

// ---------------------------------------------------------------------------
// GitHub API helpers
// ---------------------------------------------------------------------------

async function ghFetch(
  path: string,
  method: string,
  pat: string,
  body?: unknown,
): Promise<Response> {
  return fetch(`${GITHUB_API}${path}`, {
    method,
    headers: {
      Authorization: `Bearer ${pat}`,
      Accept: "application/vnd.github+json",
      "X-GitHub-Api-Version": "2022-11-28",
      "Content-Type": "application/json",
      "User-Agent": "devsecure-orchestrator/1.0",
    },
    body: body !== undefined ? JSON.stringify(body) : undefined,
  });
}

// Step 4a — Fail path: open a GitHub Issue (L4 Manual Escalation Queue)
// Idempotent: if an open issue for the same repo+file+CWE already exists,
// appends a comment instead of creating a duplicate.
// Advisory content is generated inline with a hard 5-second timeout.
// Invariant: advisory output is NEVER allowed into the PR path.
async function openIssue(
  repo: string,
  filePath: string,
  classification: ClassificationResult,
  remediation: RemediationResult,
  pat: string,
  env: Env,
  failureType: FailureType = "infra",
): Promise<string> {
  const structuredLog = {
    event: "failure_classified",
    failure_type: failureType,
    reason: remediation.reason ?? "none",
    cwe_id: classification.cwe_id,
    lane: classification.lane,
    fix_attempted: true,
    fix_generated: false,
  };

  // ── Idempotency check ───────────────────────────────────────────────────
  const existing = await findExistingIssue(repo, filePath, classification.cwe_id, pat);
  if (existing) {
    const commentBody = [
      `## L4 Escalation Update`,
      ``,
      `| Field | Value |`,
      `|---|---|`,
      `| **Failure Classification** | \`${failureType}\` |`,
      `| **Reason** | ${remediation.reason ?? "No reason provided."} |`,
      ``,
      `> ⚠️ **Not verified by DevSecure gates** | **No verified fix could be safely generated.**`,
      ``,
      `*Duplicate suppressed — existing issue updated. fix_attempted=true | fix_generated=false*`,
    ].join("\n");

    await ghFetch(`/repos/${repo}/issues/${existing.number}/comments`, "POST", pat, { body: commentBody });
    console.log(JSON.stringify({ ...structuredLog, idempotent: true, issue_number: existing.number }));
    return existing.html_url;
  }

  // ── Advisory generation (5 s hard timeout, fail-safe) ──────────────────
  const advisory = await generateAdvisory(classification, failureType, env);

  // ── Create new issue ────────────────────────────────────────────────────
  const title = `[L4 Escalation] ${classification.cwe_id} – ${classification.cwe_name} in \`${filePath}\``;

  const body = [
    `## Automated L4 Escalation — Manual Review Required`,
    ``,
    `> ⚠️ **Not verified by DevSecure gates** | **No verified fix could be safely generated.**`,
    ``,
    `| Field | Value |`,
    `|---|---|`,
    `| **File** | \`${filePath}\` |`,
    `| **CWE** | ${classification.cwe_id} — ${classification.cwe_name} |`,
    `| **Confidence** | ${(classification.confidence * 100).toFixed(1)}% |`,
    `| **Routing Lane** | L${classification.lane} |`,
    `| **Failure Classification** | \`${failureType}\` |`,
    ``,
    `### Failure Context`,
    `${remediation.reason ?? "No reason provided."}`,
    ``,
    `### Root Cause & Remediation Strategy`,
    `${advisory}`,
    ``,
    `---`,
    `*Generated by **devsecure-orchestrator**. Assign to a senior engineer for manual remediation.*`,
    `*fix_attempted=true | fix_generated=false*`,
  ].join("\n");

  const res = await ghFetch(`/repos/${repo}/issues`, "POST", pat, {
    title,
    body,
    labels: ["security", "L4-escalation", "needs-human-review"],
  });

  if (!res.ok) {
    throw new Error(`GitHub Issue creation failed: HTTP ${res.status} – ${await res.text()}`);
  }

  const issueUrl = ((await res.json()) as { html_url: string }).html_url;
  console.log(JSON.stringify({ ...structuredLog, idempotent: false }));
  return issueUrl;
}

// ---------------------------------------------------------------------------
// Tiered Complexity Analysis Engine (PoC simulation)
// ---------------------------------------------------------------------------

type Tier = "enterprise" | "free";

interface ComplexityProfile {
  tier:        Tier;
  tier_label:  string;
  ccn:         number;   // Cyclomatic Complexity Number
  fan_in:      number;   // incoming call/dependency count
  taint_risk:  "High" | "None";
  action:      "BLOCK_AUTOMERGE" | "SAFE_AUTOMERGE";
  pr_label:    string;   // GitHub label text
  fusion_note: string;   // investor-facing summary line
}

// Evaluate file path to assign a simulated complexity profile.
// Files with 'db' or 'controller' in the name → Tier 2 (Enterprise).
// All other files → Tier 1 (Free).
function analyseComplexity(filePath: string): ComplexityProfile {
  const name = filePath.split("/").pop()?.toLowerCase() ?? "";
  const isEnterprise = /db|controller/.test(name);

  if (isEnterprise) {
    return {
      tier:        "enterprise",
      tier_label:  "Tier 2 — Enterprise",
      ccn:         45,
      fan_in:      85,
      taint_risk:  "High",
      action:      "BLOCK_AUTOMERGE",
      pr_label:    "🔴 Enterprise Review Required",
      fusion_note: "High CCN + taint propagation detected. Human review mandatory before merge.",
    };
  }

  return {
    tier:        "free",
    tier_label:  "Tier 1 — Free",
    ccn:         4,
    fan_in:      2,
    taint_risk:  "None",
    action:      "SAFE_AUTOMERGE",
    pr_label:    "✅ Safe: Auto-Merge",
    fusion_note: "Low complexity. No taint propagation detected. Safe for automated merge.",
  };
}

// Step 4b — Fix path: create branch, commit file, update ledger, open GitHub PR
async function openPr(
  repo: string,
  filePath: string,
  fixedCode: string,
  classification: ClassificationResult,
  baseBranch: string,
  pat: string,
  scannerSeverity: string = "unknown",
  priorityScore: number = 0,
  complexity: ComplexityProfile = analyseComplexity(filePath),
): Promise<string> {
  // 1. Resolve base branch HEAD SHA
  const refRes = await ghFetch(
    `/repos/${repo}/git/refs/heads/${baseBranch}`,
    "GET",
    pat,
  );
  if (!refRes.ok) {
    throw new Error(`Cannot resolve base branch "${baseBranch}": ${await refRes.text()}`);
  }
  const baseSha = ((await refRes.json()) as { object: { sha: string } }).object.sha;

  // 2. Create unique fix branch
  const fixBranch = `devsecure/fix-${classification.cwe_id.toLowerCase().replace("/", "-")}-${Date.now()}`;
  const branchRes = await ghFetch(`/repos/${repo}/git/refs`, "POST", pat, {
    ref: `refs/heads/${fixBranch}`,
    sha: baseSha,
  });
  if (!branchRes.ok) {
    throw new Error(`Branch creation failed: HTTP ${branchRes.status} – ${await branchRes.text()}`);
  }

  // 3. Fetch current file blob SHA from the BASE branch (not the new fix branch,
  //    which is a fresh copy and may not yet have the file if it was just added).
  //    GitHub Contents API requires the existing blob SHA to update a file;
  //    omitting it is correct for net-new files.
  let existingFileSha: string | undefined;
  const fileRes = await ghFetch(
    `/repos/${repo}/contents/${filePath}?ref=${baseBranch}`,
    "GET",
    pat,
  );
  if (fileRes.ok) {
    existingFileSha = ((await fileRes.json()) as { sha: string }).sha;
  } else {
    console.log(`File ${filePath} not found on base branch — will be created as a new file.`);
  }

  // 4. Commit the fixed file (base64-encoded, UTF-8 safe)
  const encodedContent = btoa(unescape(encodeURIComponent(fixedCode)));
  const commitRes = await ghFetch(`/repos/${repo}/contents/${filePath}`, "PUT", pat, {
    message: `fix(security): remediate ${classification.cwe_id} in ${filePath}\n\nAutomated minimal fix by devsecure-orchestrator.\nClassification confidence: ${(classification.confidence * 100).toFixed(1)}%\nRouting lane: L${classification.lane}`,
    content: encodedContent,
    branch: fixBranch,
    ...(existingFileSha ? { sha: existingFileSha } : {}),
  });
  if (!commitRes.ok) {
    throw new Error(`File commit failed: HTTP ${commitRes.status} – ${await commitRes.text()}`);
  }

  // 5. Commit updated vulnerabilities.json ledger to the fix branch
  const LEDGER_PATH = "vulnerabilities.json";
  try {
    // Read existing ledger from base branch (may not exist yet)
    const existingLedgerRes = await ghFetch(`/repos/${repo}/contents/${LEDGER_PATH}?ref=${baseBranch}`, "GET", pat);
    let ledgerEntries: LedgerEntry[] = [];
    let existingLedgerSha: string | undefined;
    if (existingLedgerRes.ok) {
      const existingLedgerFile = (await existingLedgerRes.json()) as { sha: string; content: string };
      existingLedgerSha = existingLedgerFile.sha;
      try {
        ledgerEntries = JSON.parse(safeAtob(existingLedgerFile.content)) as LedgerEntry[];
      } catch { ledgerEntries = []; }
    }
    // Append new entry
    const newEntry: LedgerEntry = {
      timestamp:      new Date().toISOString(),
      repo,
      file_path:      filePath,
      cwe_id:         classification.cwe_id,
      severity:       scannerSeverity,
      confidence:     classification.confidence,
      priority_score: priorityScore,
      action:         "pr_opened",
      github_url:     "",  // filled after PR creation
    };
    ledgerEntries.push(newEntry);
    const ledgerContent = btoa(unescape(encodeURIComponent(JSON.stringify(ledgerEntries, null, 2))));
    await ghFetch(`/repos/${repo}/contents/${LEDGER_PATH}`, "PUT", pat, {
      message: `chore(security): update vulnerability ledger for ${classification.cwe_id} in ${filePath}`,
      content: ledgerContent,
      branch: fixBranch,
      ...(existingLedgerSha ? { sha: existingLedgerSha } : {}),
    });
  } catch (err) {
    // Ledger update failure is non-fatal — log and continue to PR creation
    console.error(JSON.stringify({ event: "ledger_update_failed", reason: err instanceof Error ? err.message : String(err) }));
  }

  // 6. Open the Pull Request — with Fusion Score dashboard
  const fusionScore = Math.round(
    (100 - Math.min(complexity.ccn, 100)) * 0.4 +
    (classification.confidence * 100) * 0.4 +
    (complexity.taint_risk === "None" ? 20 : 0),
  );

  const tierBadge = complexity.tier === "enterprise"
    ? "🔴 **ENTERPRISE** — Manual review required before merge"
    : "✅ **FREE** — Automated merge approved";

  let prRes: Response;
  try {
    prRes = await ghFetch(`/repos/${repo}/pulls`, "POST", pat, {
      title: `[DevSecure] [${complexity.tier_label}] Fix ${classification.cwe_id} in \`${filePath}\``,
      body: `## DevSecure Automated Remediation — ${tierBadge}

---

### Fusion Score Dashboard

| Metric | Value | Signal |
|---|---|---|
| **Cyclomatic Complexity (CCN)** | ${complexity.ccn} | ${complexity.ccn > 20 ? "🔴 High" : "🟢 Low"} |
| **Fan-In (Dependencies)** | ${complexity.fan_in} | ${complexity.fan_in > 10 ? "🔴 High coupling" : "🟢 Low coupling"} |
| **Taint Propagation Risk** | ${complexity.taint_risk} | ${complexity.taint_risk === "High" ? "🔴 Taint paths detected" : "🟢 Clean"} |
| **L2 LLM Confidence** | ${(classification.confidence * 100).toFixed(1)}% | ${classification.confidence >= 0.85 ? "🟢 High" : classification.confidence >= 0.70 ? "🟡 Medium" : "🔴 Low"} |
| **L1 Severity** | ${scannerSeverity.toUpperCase()} | — |
| **Priority Score** | ${priorityScore} / 100 | — |
| **Fusion Score** | **${fusionScore} / 100** | ${fusionScore >= 70 ? "🟢 Auto-merge eligible" : "🔴 Blocked"} |

> **Routing Decision:** \`${complexity.action}\` — ${complexity.fusion_note}

---

### Vulnerability Classification

| Field | Value |
|---|---|
| **CWE** | ${classification.cwe_id} — ${classification.cwe_name} |
| **File** | \`${filePath}\` |
| **Routing Lane** | L${classification.lane} |
| **Complexity Profile** | ${complexity.tier_label} |

${classification.summary}

---

### ${complexity.tier === "enterprise" ? "Enterprise" : "Tier B"} Review Checklist
- [ ] Full test suite passes
- [ ] AST semantic preservation verified (behaviour unchanged)
- [ ] SAST regression scan clean (no new findings)
- [ ] Minimal diff constraint satisfied (only security-relevant lines changed)
${complexity.tier === "enterprise" ? "- [ ] Senior engineer sign-off (CCN > 20 mandate)\n- [ ] Taint propagation paths manually verified" : ""}

> ⚠️ **AI models have zero approval authority.** A human reviewer must approve and merge this PR.

*Generated by **devsecure-orchestrator** · Complexity Engine v1 · Ledger: \`${LEDGER_PATH}\`*`,
      head: fixBranch,
      base: baseBranch,
      labels: [complexity.pr_label],
    });
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    console.error(`openPr: GitHub fetch threw unexpectedly — ${msg}`);
    throw new Error(`PR creation fetch failed: ${msg}`);
  }
  if (!prRes.ok) {
    const errBody = await prRes.text();
    console.error(`openPr: PR creation failed — HTTP ${prRes.status} | repo: ${repo} | branch: ${fixBranch} | body: ${errBody}`);
    throw new Error(`PR creation failed: HTTP ${prRes.status} – ${errBody}`);
  }

  return ((await prRes.json()) as { html_url: string }).html_url;
}

// ---------------------------------------------------------------------------
// In-memory metrics (persists across requests within the same Worker instance)
// ---------------------------------------------------------------------------

const worker_start_time = Date.now();

let metrics_total_requests        = 0;
let metrics_pr_opened_count       = 0;
let metrics_issue_escalated_count = 0;
let metrics_total_final_score     = 0;
let metrics_mismatch_count        = 0;

interface RecentDecision {
  timestamp: string;
  repo: string;
  cve_id: string | null;
  final_score: number;
  decision: "pr_opened" | "issue_escalated";
}
const recent_decisions: RecentDecision[] = [];

// ---------------------------------------------------------------------------
// In-memory Vulnerability Ledger — severity-driven (V2.0)
// ---------------------------------------------------------------------------

interface LedgerEntry {
  timestamp:       string;
  repo:            string;
  file_path:       string;
  cwe_id:          string;
  severity:        string;   // from L1 scanner (critical/high/medium/low)
  confidence:      number;   // from L2 classifier (0.0-1.0)
  priority_score:  number;   // final computed score
  action:          string;
  github_url:      string;
}

const vulnerability_ledger: LedgerEntry[] = [];

// ---------------------------------------------------------------------------
// Main handler
// ---------------------------------------------------------------------------

export default {
  async fetch(request: Request, env: Env, _ctx: ExecutionContext): Promise<Response> {
    const url = new URL(request.url);

    // Health check
    if (request.method === "GET" && url.pathname === "/") {
      return new Response(
        JSON.stringify({ status: "ok", service: "devsecure-orchestrator" }),
        { status: 200, headers: { "Content-Type": "application/json" } },
      );
    }

    // GET /ledger — return in-memory vulnerability ledger
    if (request.method === "GET" && url.pathname === "/ledger") {
      return new Response(
        JSON.stringify({ total: vulnerability_ledger.length, entries: vulnerability_ledger }),
        { status: 200, headers: { "Content-Type": "application/json" } },
      );
    }


    // Seed the Vectorize index with PoC Top 5 CWE guidance (one-shot, idempotent).
    // Protected: requires the SEED_SECRET bearer token so the public cannot overwrite the DB.
    if (request.method === "GET" && url.pathname === "/seed") {
      const authHeader = request.headers.get("Authorization");
      if (!authHeader || authHeader !== `Bearer ${env.SEED_SECRET}`) {
        return new Response(
          JSON.stringify({ error: "Unauthorized." }),
          { status: 401, headers: { "Content-Type": "application/json" } },
        );
      }

      try {
        const result = await seedCWEData(env);
        return new Response(
          JSON.stringify({ status: "ok", ...result }),
          { status: 200, headers: { "Content-Type": "application/json" } },
        );
      } catch (err) {
        const detail = err instanceof Error ? err.message : String(err);
        return new Response(
          JSON.stringify({ error: "Seed failed.", detail }),
          { status: 500, headers: { "Content-Type": "application/json" } },
        );
      }
    }

    // POST /ingest-fix — Learning Guard ingestion endpoint.
    // Accepts a validated fix, embeds it, and upserts into VECTOR_INDEX.
    // Protected by the same SEED_SECRET bearer token.
    if (request.method === "POST" && url.pathname === "/ingest-fix") {
      const ingestAuth = request.headers.get("Authorization");
      if (!ingestAuth || ingestAuth !== `Bearer ${env.SEED_SECRET}`) {
        return new Response(
          JSON.stringify({ error: "Unauthorized." }),
          { status: 401, headers: { "Content-Type": "application/json" } },
        );
      }

      interface IngestFixRequest {
        cwe_id: string;
        summary: string;
        fixed_code: string;
        metadata: Record<string, unknown>;
      }

      let ingestBody: IngestFixRequest;
      try {
        ingestBody = (await request.json()) as IngestFixRequest;
      } catch {
        return new Response(
          JSON.stringify({ error: "Request body must be valid JSON." }),
          { status: 400, headers: { "Content-Type": "application/json" } },
        );
      }

      const { cwe_id, summary, fixed_code, metadata } = ingestBody;
      if (!cwe_id || !summary || !fixed_code) {
        return new Response(
          JSON.stringify({ error: "Missing required fields: cwe_id, summary, fixed_code." }),
          { status: 400, headers: { "Content-Type": "application/json" } },
        );
      }

      try {
        // Build embedding text: CWE context + truncated fixed code (max 1500 chars)
        const embeddingText = `${cwe_id} fix: ${summary}\n${fixed_code.slice(0, 1500)}`;
        const vector = await getEmbedding(embeddingText, env);

        // Duplicate detection: query top-1, skip if score > 0.95
        const dupeCheck = await env.VECTOR_INDEX.query(vector, { topK: 1, returnMetadata: "none" });
        if (dupeCheck.matches && dupeCheck.matches.length > 0 && dupeCheck.matches[0].score > 0.95) {
          console.log(`[ingest-fix] Duplicate detected for ${cwe_id} (score: ${dupeCheck.matches[0].score.toFixed(4)}) — skipping.`);
          return new Response(
            JSON.stringify({ status: "skipped", reason: "duplicate", score: dupeCheck.matches[0].score }),
            { status: 200, headers: { "Content-Type": "application/json" } },
          );
        }

        const commitSha = typeof metadata.commit_sha === "string" ? metadata.commit_sha : String(Date.now());
        const vectorId = `learn-${cwe_id.toLowerCase().replace(/[^a-z0-9-]/g, "-")}-${commitSha.slice(0, 12)}`;

        await env.VECTOR_INDEX.upsert([{
          id: vectorId,
          values: vector,
          metadata: {
            cwe_id,
            summary,
            fixed_code: fixed_code.slice(0, 2000),
            source: "learning-guard",
            ingested_at: new Date().toISOString(),
            ...metadata,
          },
        }]);

        console.log(`[ingest-fix] Ingested ${vectorId} for ${cwe_id}.`);
        return new Response(
          JSON.stringify({ status: "ingested", id: vectorId }),
          { status: 200, headers: { "Content-Type": "application/json" } },
        );
      } catch (err) {
        const detail = err instanceof Error ? err.message : String(err);
        console.error("[ingest-fix] Ingestion failed:", detail);
        return new Response(
          JSON.stringify({ error: "Ingestion failed.", detail }),
          { status: 500, headers: { "Content-Type": "application/json" } },
        );
      }
    }

    if (request.method === "GET" && url.pathname === "/metrics") {
      return new Response(
        JSON.stringify({
          total_requests: metrics_total_requests,
          pr_opened: metrics_pr_opened_count,
          issue_escalated: metrics_issue_escalated_count,
          success_rate:
            metrics_total_requests === 0
              ? 0
              : Math.round((metrics_pr_opened_count / metrics_total_requests) * 10000) / 100,
          avg_final_score:
            metrics_total_requests === 0
              ? 0
              : Math.round((metrics_total_final_score / metrics_total_requests) * 100) / 100,
          uptime_seconds: Math.floor((Date.now() - worker_start_time) / 1000),
          health_status:
            metrics_total_requests === 0
              ? "healthy"
              : metrics_pr_opened_count / metrics_total_requests >= 0.7
              ? "healthy"
              : metrics_pr_opened_count / metrics_total_requests >= 0.5
              ? "degraded"
              : "unhealthy",
          recent_decisions,
          mismatch_rate:
            metrics_total_requests === 0
              ? 0
              : Math.round((metrics_mismatch_count / metrics_total_requests) * 10000) / 100,
        }),
        {
          status: 200,
          headers: {
            "Content-Type": "application/json",
            "Access-Control-Allow-Origin": "*",
          },
        },
      );
    }

    if (request.method !== "POST" || url.pathname !== "/remediate") {
      return new Response(
        JSON.stringify({ error: "Only POST /remediate is accepted." }),
        { status: 405, headers: { "Content-Type": "application/json" } },
      );
    }

    // Parse body
    let body: RemediationRequest;
    try {
      body = (await request.json()) as RemediationRequest;
    } catch {
      return new Response(
        JSON.stringify({ error: "Request body must be valid JSON." }),
        { status: 400, headers: { "Content-Type": "application/json" } },
      );
    }

    const { repo, file_path, base_branch = "main", ds_detection, code_context } = body;

    // Resolve effective inputs: code_context takes precedence over legacy fields
    const code     = code_context?.snippet  ?? body.code;
    const language = code_context?.language ?? body.language;

    // Detection Normalisation Layer
    // scanner_severity → consumed as V2.0 L1 priority signal
    // scanner_confidence / scanner_cwe → discarded; L2 LLM is sole authoritative source
    void ds_detection?.scanner_confidence;
    void ds_detection?.scanner_cwe;
    const scanner_severity = (ds_detection?.scanner_severity ?? "").toLowerCase() || "unknown";

    // ── Hidden Signal Layer — internal context; never exposed in API responses ─
    const hsl: HiddenSignalLayer = {
      source_type:      ds_detection?.type ?? "unknown",
      cwe_hint:         ds_detection?.cwe_hint,
      scanner_severity: scanner_severity,
    };

    if (!code || !language) {
      return new Response(
        JSON.stringify({
          error: "Missing required fields.",
          required: ["code_context.snippet + code_context.language", "or legacy: code + language"],
        }),
        { status: 400, headers: { "Content-Type": "application/json" } },
      );
    }

    if (code.length > 100_000) {
      return new Response(
        JSON.stringify({ error: "Payload too large" }),
        { status: 413, headers: { "Content-Type": "application/json" } }
      );
    }

    if (!repo || !file_path) {
      return new Response(
        JSON.stringify({
          error: "Missing required fields.",
          required: ["repo", "file_path"],
        }),
        { status: 400, headers: { "Content-Type": "application/json" } },
      );
    }

    // Validate ds_detection required fields when provided
    if (ds_detection !== undefined) {
      if (!ds_detection.type || !ds_detection.rule_id) {
        return new Response(
          JSON.stringify({ error: "ds_detection requires type and rule_id." }),
          { status: 400, headers: { "Content-Type": "application/json" } },
        );
      }
    }

    // 🔍 DEBUG TRACE + REQUEST LOGGING
    const traceId = request.headers.get("X-Trace-Id") || "no-trace";
    const authHeader = request.headers.get("Authorization");

    console.log("TRACE:", traceId, "| method:", request.method, "| path:", url.pathname);
    console.log("Auth present:", !!authHeader, "| length:", authHeader?.length || 0);

    // Auth guard — caller must supply the same secret as the GitHub Action
    if (!authHeader || authHeader !== `Bearer ${env.SEED_SECRET}`) {
      return new Response(
        JSON.stringify({ error: "Unauthorized." }),
        { status: 401, headers: { "Content-Type": "application/json" } },
      );
    }

    let pipelineStep = "init";
    const start = Date.now();
    try {
      // ── Step 1: Classification (Qwen2.5) ──────────────────────────────────
      pipelineStep = "classification";
      const classification = await classify(code, language, env.HF_API_KEY, env);
      console.log("Classification result:", JSON.stringify(classification));

      // ── ds_detection mismatch: hint exists and differs from LLM-derived CWE ─
      const cwe_mismatch = !!(
        ds_detection?.cwe_hint &&
        ds_detection.cwe_hint !== classification.cwe_id
      );

      // Lane adjustment: mismatch forces lane to at least 3 (never overrides LLM classification)
      if (cwe_mismatch) {
        classification.lane = Math.max(classification.lane, 3);
        console.log(JSON.stringify({
          event: "cwe_mismatch_detected",
          llm_cwe: classification.cwe_id,
          lane: classification.lane,
          decision: "judge_forced",
        }));
      }

      // ── Explainability factors — accumulated throughout pipeline ───────────
      const explainabilityFactors: string[] = [];
      if (cwe_mismatch)                     explainabilityFactors.push("cwe_mismatch");
      if (classification.confidence < 0.80) explainabilityFactors.push("low_confidence");

      // ── Step 2: RAG context retrieval (Vectorize + CF AI embeddings) ───────
      pipelineStep = "rag";
      let ragContext = "";
      try {
        ragContext = await retrieveRagContext(
          classification.cwe_id,
          classification.summary,
          env.VECTOR_INDEX,
          env,
        );
      } catch (e) {
        console.log("RAG failed, using fallback");
        ragContext = "No RAG context available.";
      }
      console.log("RAG context length:", ragContext.length);

      // ── Step 3: Confidence gate (fail-closed) ─────────────────────────────
      pipelineStep = "confidence_gate";
      const BENIGN_PATTERNS = ["no vulnerability", "benign", "not vulnerable"];
      const summaryLower = classification.summary.toLowerCase();
      const cweBlocked =
        !classification.cwe_id ||
        classification.cwe_id.trim() === "" ||
        classification.cwe_id === "CWE-0";
      const confidenceBlocked = classification.confidence < 0.75;
      const laneBlocked = classification.lane >= 3;
      const summaryBlocked = BENIGN_PATTERNS.some((p) => summaryLower.includes(p));
      if (confidenceBlocked || laneBlocked || cweBlocked || summaryBlocked) {
        console.log("Blocked by confidence gate:", JSON.stringify(classification));
        const gateReason = [
          confidenceBlocked && `confidence=${classification.confidence} < 0.75`,
          laneBlocked && `lane=${classification.lane} >= 3`,
          cweBlocked && `cwe_id invalid ("${classification.cwe_id}")`,
          summaryBlocked && `summary matched benign pattern`,
        ].filter(Boolean).join("; ");
        pipelineStep = "github";
        console.log(JSON.stringify({ event: "failure_classified", failure_type: "policy", reason: `Confidence gate triggered: ${gateReason}`, cwe_id: classification.cwe_id, lane: classification.lane, fix_attempted: false, fix_generated: false }));
        const gateUrl = await openIssue(
          repo,
          file_path,
          classification,
          { status: "cannot_fix", reason: `Confidence gate triggered: ${gateReason}` },
          env.GITHUB_PAT,
          env,
          "policy",
        );
        console.log("Pipeline duration:", Date.now() - start, "ms");
        return new Response(
          JSON.stringify({
            action: "issue_escalated",
            github_url: gateUrl,
            classification,
            remediation_status: "cannot_fix",
          }),
          { status: 200, headers: { "Content-Type": "application/json" } },
        );
      }

      // ── Step 4: Remediation ───────────────────────────────────────────────
      pipelineStep = "remediation";
      console.log("Calling remediation model: " + (env.REMEDIATION_MODEL || DEFAULT_REMEDIATION_MODEL));
      let remediation: RemediationResult;
      let remediationRequiredRetry = false;
      try {
        // Wrap remediateWithRetry to detect if attempt 1 failed and attempt 2 was needed.
        // We monkey-patch by catching attempt-1 failure at this level without re-running.
        let attempt1Succeeded = false;
        try {
          const result1 = await remediate(code, language, classification, ragContext, env.HF_API_KEY, env);
          validateRemediation(result1);
          remediation = result1;
          attempt1Succeeded = true;
        } catch {
          remediationRequiredRetry = true;
        }
        if (!attempt1Succeeded) {
          remediation = await remediateWithRetry(code, language, classification, ragContext, env.HF_API_KEY, env);
        }
      } catch (err) {
        const msg = err instanceof Error ? err.message : String(err);
        console.error("Remediation exhausted retries, escalating to L4:", msg);
        pipelineStep = "github";
        const fallbackUrl = await openIssue(
          repo,
          file_path,
          classification,
          { status: "cannot_fix", reason: `Automated remediation failed after retries: ${msg}` },
          env.GITHUB_PAT,
          env,
          "model",
        );
        console.log("Pipeline duration:", Date.now() - start, "ms");
        return new Response(
          JSON.stringify({
            action: "issue_escalated",
            github_url: fallbackUrl,
            classification,
            remediation_status: "cannot_fix",
          }),
          { status: 200, headers: { "Content-Type": "application/json" } },
        );
      }
      if (remediation.status === "fixed" && remediation.search_replace_block) {
        console.log(JSON.stringify({ event: "remediation_received", status: "fixed", block_length: remediation.search_replace_block.length }));
      } else {
        console.log("Remediation status: " + remediation.status + " — reason: " + (remediation.reason ?? "none"));
      }

      // ── Step 5: Fail-closed gate + Patch Guard ────────────────────────────
      pipelineStep = "github";
      let githubUrl: string;
      let action: "pr_opened" | "issue_escalated";
      let judgeWasRun = false;
      let scorePayload: {
        severity: string;
        confidence: number;
        judge_penalty: number;
        patch_risk: number;
        lane_weight: number;
        mismatch_penalty: number;
        final_priority_score: number;
      } | Record<string, never> = {};

      if (remediation.status === "cannot_fix") {
        // L4 escalation path → open GitHub Issue
        githubUrl = await openIssue(
          repo,
          file_path,
          classification,
          remediation,
          env.GITHUB_PAT,
          env,
          "model",
        );
        action = "issue_escalated";
      } else {
        // ── Apply search/replace patch (failure_type: model) ─────────────────
        let decoded: string;
        try {
          decoded = applySearchReplace(code, remediation.search_replace_block!);
          decoded = prependAuditHeader(decoded, language, classification.cwe_id);
        } catch (err) {
          const msg = err instanceof Error ? err.message : String(err);
          const reason = "Malformed search/replace block or context mismatch";
          console.error(JSON.stringify({ event: "failure_classified", failure_type: "model", reason, detail: msg, cwe_id: classification.cwe_id, lane: classification.lane, fix_attempted: true, fix_generated: false }));
          githubUrl = await openIssue(
            repo,
            file_path,
            classification,
            { status: "cannot_fix", reason },
            env.GITHUB_PAT,
            env,
            "model",
          );
          action = "issue_escalated";
          console.log("Pipeline duration:", Date.now() - start, "ms");
          return new Response(
            JSON.stringify({ action, github_url: githubUrl, classification, remediation_status: "cannot_fix" }),
            { status: 200, headers: { "Content-Type": "application/json" } },
          );
        }

        // ── Patch Guard: check diff size before committing ───────────────────
        let guard: PatchGuardResult;
        try {
          guard = checkPatchGuard(code, decoded);
        } catch (err) {
          const msg = err instanceof Error ? err.message : String(err);
          console.error(JSON.stringify({ event: "failure_classified", failure_type: "infra", reason: "Patch Guard calculation error", detail: msg, cwe_id: classification.cwe_id, lane: classification.lane, fix_attempted: true, fix_generated: false }));
          githubUrl = await openIssue(
            repo,
            file_path,
            classification,
            { status: "cannot_fix", reason: `Patch Guard calculation error: ${msg}` },
            env.GITHUB_PAT,
            env,
            "infra",
          );
          action = "issue_escalated";
          console.log("Pipeline duration:", Date.now() - start, "ms");
          return new Response(
            JSON.stringify({ action, github_url: githubUrl, classification, remediation_status: "cannot_fix" }),
            { status: 200, headers: { "Content-Type": "application/json" } },
          );
        }

        if (!guard.allowed) {
          console.log(
            `Patch Guard blocked PR: ${guard.reason} | originalLines=${guard.originalLines} fixedLines=${guard.fixedLines} changedLines=${guard.changedLines} changePercent=${guard.changePercent.toFixed(1)}%`,
          );
          githubUrl = await openIssue(
            repo,
            file_path,
            classification,
            {
              status: "cannot_fix",
              reason: `${guard.reason}. Original: ${guard.originalLines} lines → Fixed: ${guard.fixedLines} lines (${guard.changePercent.toFixed(1)}% changed, ${guard.changedLines} lines modified).`,
            },
            env.GITHUB_PAT,
            env,
            "policy",
          );
          action = "issue_escalated";
        } else {
          // ── Step 5b: Diversity Judge (risk-triggered, fail-closed) ───────────
          pipelineStep = "judge";
          const judgeTriggerReasons: string[] = [];
          if (COMPLEX_CWES.includes(classification.cwe_id))            judgeTriggerReasons.push("complex_cwe_mandate");
          if (classification.lane >= 3)                                judgeTriggerReasons.push("lane=" + classification.lane);
          if (classification.confidence < 0.80)                        judgeTriggerReasons.push("confidence=" + classification.confidence);
          if (guard.changePercent > 15 && guard.changePercent < 20)    judgeTriggerReasons.push("borderline_patch=" + guard.changePercent.toFixed(1) + "%");
          if (remediationRequiredRetry)                                 judgeTriggerReasons.push("remediation_retried");
          if (cwe_mismatch)                                             judgeTriggerReasons.push("cwe_mismatch");
          const judgeTriggered = judgeTriggerReasons.length > 0;

          // Judge penalty and result — defaults for skip path
          let judgePenalty = 0;
          let judgeRejectReason: string | null = null;
          let judgeFailure = false;

          if (judgeTriggered) {
            console.log(JSON.stringify({
              event: "[JUDGE] triggered",
              lane: classification.lane,
              confidence: classification.confidence,
              changePercent: guard.changePercent,
              remediationRequiredRetry,
              triggerReasons: judgeTriggerReasons,
            }));
            try {
              judgeWasRun = true;
              const judgeResult = await judgeReview(code, decoded, classification, env);

              // Strict mode when cwe_mismatch: require explicit approve + confidence >= 0.85 + no issues
              const effectiveReject = cwe_mismatch
                ? (judgeResult.verdict !== "approve" || judgeResult.confidence < 0.85 || judgeResult.issues.length > 0)
                : (judgeResult.verdict === "reject" || judgeResult.confidence < 0.80 || judgeResult.issues.length > 0);

              // Judge penalty: verdict-based + confidence gap + issue count (capped at 15)
              if (judgeResult.verdict === "reject") {
                judgePenalty += 20;
              } else if (judgeResult.confidence < 0.85) {
                judgePenalty += 10;
              }
              if (judgeResult.issues.length > 0) {
                judgePenalty += Math.min(judgeResult.issues.length * 5, 15);
              }

              // Explainability factors from judge output
              if (judgeResult.verdict === "reject")  explainabilityFactors.push("judge_reject");
              if (judgeResult.issues.length > 0)     explainabilityFactors.push("judge_issues");

              console.log(JSON.stringify({
                event: effectiveReject ? "[JUDGE] verdict: reject" : "[JUDGE] verdict: approve",
                verdict: judgeResult.verdict,
                confidence: judgeResult.confidence,
                issueCount: judgeResult.issues.length,
                issues: judgeResult.issues,
                reason: judgeResult.reason,
                judgePenalty,
                effectiveReject,
              }));

              if (effectiveReject) {
                judgeRejectReason = `Diversity Judge rejected fix (verdict=${judgeResult.verdict}, confidence=${judgeResult.confidence}): ${judgeResult.reason}${judgeResult.issues.length > 0 ? " Issues: " + judgeResult.issues.join("; ") : ""}`;
              }
            } catch (err) {
              const msg = err instanceof Error ? err.message : String(err);
              console.error(JSON.stringify({ event: "[JUDGE] failure", error: msg, outcome: "issue_escalated" }));
              judgeFailure = true;
              judgeRejectReason = `Diversity Judge unavailable or invalid response: ${msg}`;
            }
          } else {
            console.log(JSON.stringify({
              event: "[JUDGE] skipped",
              lane: classification.lane,
              confidence: classification.confidence,
              changePercent: guard.changePercent,
            }));
          }

          // ── Step 5c: RPS / Pseudo-RPS ────────────────────────────────────
          // cve_id is consumed here and never forwarded to GitHub artifacts
          // (taxonomy moat — see openIssue / openPr: neither embeds cve_id).
          // ── Step 5d: Final Priority Scoring (V2.0 — Severity × Confidence) ─
          pipelineStep = "scoring";
          const laneWeightMap: Record<number, number> = { 1: 0, 2: 5, 3: 10, 4: 20 };
          const laneWeight = laneWeightMap[classification.lane] ?? 20;

          let patchRisk: number;
          if (guard.changePercent <= 10) {
            patchRisk = 0;
          } else if (guard.changePercent <= 15) {
            patchRisk = 5;
          } else {
            patchRisk = 10;
          }

          // Dynamic mismatch penalty — scaled by |llm_confidence – detection_baseline|
          const DETECTION_CONFIDENCE_BASELINE = 0.7;
          let mismatchPenalty = 0;
          if (cwe_mismatch) {
            const delta = Math.abs(classification.confidence - DETECTION_CONFIDENCE_BASELINE);
            if (delta < 0.2)       mismatchPenalty = 5;
            else if (delta <= 0.5) mismatchPenalty = 10;
            else                   mismatchPenalty = 15;
          }

          const finalScore = computePriorityScore(
            scanner_severity,
            classification.confidence,
            judgePenalty,
            patchRisk,
            laneWeight,
            mismatchPenalty,
          );

          console.log(JSON.stringify({
            event:            "final_scoring",
            severity:         scanner_severity,
            confidence:       classification.confidence,
            judge_penalty:    judgePenalty,
            lane_weight:      laneWeight,
            patch_risk:       patchRisk,
            mismatch_penalty: mismatchPenalty,
            final_score:      finalScore,
          }));

          // ── Step 5e: Decision engine ──────────────────────────────────────
          pipelineStep = "github";

          // Fail-closed: judge failure or reject always escalates, score is irrelevant
          if (judgeFailure || judgeRejectReason !== null) {
            githubUrl = await openIssue(
              repo, file_path, classification,
              { status: "cannot_fix", reason: judgeRejectReason ?? "Judge failure — fail-closed escalation" },
              env.GITHUB_PAT,
              env,
              judgeFailure ? "infra" : "policy",
            );
            action = "issue_escalated";
          } else if (finalScore >= 85) {
            const complexity = analyseComplexity(file_path);
            console.log(JSON.stringify({ event: "complexity_analysis", tier: complexity.tier, ccn: complexity.ccn, fan_in: complexity.fan_in, taint_risk: complexity.taint_risk, action: complexity.action, file_path }));
            githubUrl = await openPr(repo, file_path, decoded, classification, base_branch, env.GITHUB_PAT, scanner_severity, finalScore, complexity);
            action = "pr_opened";
            console.log(JSON.stringify({ event: "pr_created", cwe_id: classification.cwe_id, lane: classification.lane, final_score: finalScore, severity: scanner_severity, tier: complexity.tier, pr_label: complexity.pr_label, fix_attempted: true, fix_generated: true }));
          } else if (finalScore >= 70) {
            console.log(JSON.stringify({ event: "final_scoring", warning: "score_in_caution_band", final_score: finalScore }));
            const complexity = analyseComplexity(file_path);
            console.log(JSON.stringify({ event: "complexity_analysis", tier: complexity.tier, ccn: complexity.ccn, fan_in: complexity.fan_in, taint_risk: complexity.taint_risk, action: complexity.action, file_path }));
            githubUrl = await openPr(repo, file_path, decoded, classification, base_branch, env.GITHUB_PAT, scanner_severity, finalScore, complexity);
            action = "pr_opened";
            console.log(JSON.stringify({ event: "pr_created", cwe_id: classification.cwe_id, lane: classification.lane, final_score: finalScore, severity: scanner_severity, tier: complexity.tier, pr_label: complexity.pr_label, fix_attempted: true, fix_generated: true }));
          } else {
            githubUrl = await openIssue(
              repo, file_path, classification,
              { status: "cannot_fix", reason: `Final priority score too low to auto-merge: score=${finalScore} (severity=${scanner_severity}, confidence=${classification.confidence.toFixed(2)}, judgePenalty=${judgePenalty}, patchRisk=${patchRisk}, laneWeight=${laneWeight}, mismatchPenalty=${mismatchPenalty})` },
              env.GITHUB_PAT,
              env,
              "policy",
            );
            action = "issue_escalated";
          }

          scorePayload = { severity: scanner_severity, confidence: classification.confidence, judge_penalty: judgePenalty, patch_risk: patchRisk, lane_weight: laneWeight, mismatch_penalty: mismatchPenalty, final_priority_score: finalScore };

          // Update in-memory metrics (scoring path — has rpsScore + finalScore)
          metrics_total_requests++;
          if (cwe_mismatch) metrics_mismatch_count++;
          if (action === "pr_opened") metrics_pr_opened_count++;
          else metrics_issue_escalated_count++;
          metrics_total_final_score += finalScore;
          recent_decisions.push({ timestamp: new Date().toISOString(), repo, cve_id: null, final_score: finalScore, decision: action });
          if (recent_decisions.length > 10) recent_decisions.shift();

          // Push to in-memory vulnerability ledger
          vulnerability_ledger.push({
            timestamp:      new Date().toISOString(),
            repo,
            file_path,
            cwe_id:         classification.cwe_id,
            severity:       scanner_severity,
            confidence:     classification.confidence,
            priority_score: finalScore,
            action,
            github_url:     githubUrl ?? "",
          });
          if (vulnerability_ledger.length > 50) vulnerability_ledger.shift();
        }
      }

      // Update metrics for cannot_fix / patch-guard-blocked paths (no score computed)
      if (Object.keys(scorePayload).length === 0 && action !== undefined) {
        metrics_total_requests++;
        if (cwe_mismatch) metrics_mismatch_count++;
        if (action === "pr_opened") metrics_pr_opened_count++;
        else metrics_issue_escalated_count++;
        recent_decisions.push({ timestamp: new Date().toISOString(), repo, cve_id: cve_id ?? null, final_score: 0, decision: action });
        if (recent_decisions.length > 10) recent_decisions.shift();
      }

      console.log("Pipeline duration:", Date.now() - start, "ms");

      const decisionPath = [
        "classify",
        "rag",
        "remediate",
        "patch_guard",
        ...(judgeWasRun ? ["judge"] : []),
        "rps",
        "score",
        action,
      ].join(" → ");

      return new Response(
        JSON.stringify({
          action,
          github_url: githubUrl,
          classification: {
            cwe_id: classification.cwe_id,
            confidence: classification.confidence,
          },
          correlation: {
            cve_id: cve_id ?? null,
            cwe_mismatch,
          },
          metrics: {
            mismatch_penalty:      scorePayload.mismatch_penalty    ?? 0,
            judge_penalty:         scorePayload.judge_penalty        ?? 0,
            final_priority_score:  scorePayload.final_priority_score ?? 0,
          },
          explainability: {
            factors:       explainabilityFactors,
            decision_path: decisionPath,
          },
          remediation_status: remediation.status,
          priority: {
            severity:             scorePayload.severity             ?? "unknown",
            confidence:           scorePayload.confidence           ?? 0,
            final_priority_score: scorePayload.final_priority_score ?? 0,
          },
          ...scorePayload,
        }),
        { status: 200, headers: { "Content-Type": "application/json" } },
      );
    } catch (err) {
      const detail = err instanceof Error ? err.message : String(err);
      console.error(`Pipeline failure at step [${pipelineStep}]:`, detail);
      return new Response(
        JSON.stringify({ error: "Pipeline failure.", step: pipelineStep, detail }),
        { status: 500, headers: { "Content-Type": "application/json" } },
      );
    }
  },
} satisfies ExportedHandler<Env>;
