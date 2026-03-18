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
  type: string;       // detection rule type
  rule_id: string;    // unique rule identifier
  cwe_hint?: string;  // optional CWE hint — never used as final CWE value
  cve_id?: string;    // optional CVE ID — attached to output if present, never inferred
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
  cve_id?: string;      // top-level CVE ID for RPS scoring (legacy field)
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
  source_type: string;     // detection origin (e.g. "sast", "dast", "manual")
  cwe_hint?: string;       // vendor-supplied CWE; used only for mismatch detection
  cve_id?: string;         // CVE from detection; used only for RPS lookup
}

interface RemediationResult {
  status: "fixed" | "cannot_fix";
  fixed_code_base64?: string;
  reason?: string;
}

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
Analyse the provided source code and return ONLY a valid JSON object — no prose, no markdown fences, no explanation.

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
  4 — Architectural or cannot assess: systemic design flaw, insufficient context`;

  const user = `Language: ${language}\n\nVulnerable code:\n\`\`\`${language}\n${code}\n\`\`\``;

  const classifierModel = env.CLASSIFIER_MODEL || DEFAULT_CLASSIFIER_MODEL;
  const raw = await hfChat(
    classifierModel,
    [{ role: "system", content: system }, { role: "user", content: user }],
    apiKey,
    512,
  );

  const match = raw.match(/\{[\s\S]*\}/);
  if (!match) {
    throw new Error(`Qwen2.5 classification did not return JSON. Raw output: ${raw}`);
  }
  return JSON.parse(match[0]) as ClassificationResult;
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
- Return ONLY valid JSON
- Encode the entire fixed code using base64
- Do NOT return raw code in any field
- Do NOT include backticks or markdown
- Ensure JSON is strictly parseable

If you can fix the vulnerability with confidence ≥ 0.75 and a minimal diff:
{"status":"fixed","fixed_code_base64":"<base64 encoded complete corrected code block>"}

Otherwise (low confidence, architectural issue, or insufficient context):
{"status":"cannot_fix","reason":"<concise explanation for the L4 human reviewer>"}

Hard constraints:
- Do NOT alter program behaviour beyond the security fix
- Do NOT add features, refactor unrelated code, or change formatting
- Preserve all original comments, variable names, and indentation`;

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
  let result: RemediationResult;
  try {
    result = JSON.parse(match[0]) as RemediationResult;
  } catch (e) {
    console.error("RAW LLM OUTPUT:", raw);
    throw new Error(`Remediation JSON parse failed: ${e instanceof Error ? e.message : String(e)}`);
  }
  return result;
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
    if (!result.fixed_code_base64 || result.fixed_code_base64.trim() === "") {
      throw new Error("Invalid remediation: fixed_code_base64 is missing or empty");
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

  const violations: string[] = [];
  if (changePercent > 20) {
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
  console.log(
    `Patch Guard: originalLines=${originalCount} fixedLines=${fixedCount} changedLines=${changedLines} changePercent=${changePercent.toFixed(1)}% sizeRatio=${sizeRatio.toFixed(2)} allowed=${allowed}`,
  );

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

const RPS_DEFAULT_SCORE = 50;

async function fetchRpsScore(cveId: string, env: Env): Promise<number> {
  if (!env.RPS_API_URL) {
    console.log(JSON.stringify({ event: "rps_fetch", status: "fallback", reason: "RPS_API_URL not configured" }));
    return RPS_DEFAULT_SCORE;
  }
  try {
    const url = `${env.RPS_API_URL}?cve_id=${encodeURIComponent(cveId)}`;
    const res = await fetch(url, {
      method: "GET",
      headers: { Authorization: `Bearer ${env.RPS_TOKEN}` },
    });
    if (!res.ok) {
      console.log(JSON.stringify({ event: "rps_fetch", cve_id: cveId, status: "fallback", httpStatus: res.status }));
      return RPS_DEFAULT_SCORE;
    }
    const data = (await res.json()) as Record<string, unknown>;
    const score = data.rps_score;
    if (typeof score !== "number") {
      console.log(JSON.stringify({ event: "rps_fetch", cve_id: cveId, status: "fallback", reason: "missing_rps_score" }));
      return RPS_DEFAULT_SCORE;
    }
    console.log(JSON.stringify({ event: "rps_fetch", cve_id: cveId, status: "success", rps_score: score }));
    return score;
  } catch (err) {
    const reason = err instanceof Error ? err.message : String(err);
    console.log(JSON.stringify({ event: "rps_fetch", cve_id: cveId, status: "fallback", reason }));
    return RPS_DEFAULT_SCORE;
  }
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
async function openIssue(
  repo: string,
  filePath: string,
  classification: ClassificationResult,
  remediation: RemediationResult,
  pat: string,
): Promise<string> {
  const title = `[L4 Escalation] ${classification.cwe_id} – ${classification.cwe_name} in \`${filePath}\``;

  const body = `## Automated L4 Escalation — Manual Review Required

| Field | Value |
|---|---|
| **File** | \`${filePath}\` |
| **CWE** | ${classification.cwe_id} — ${classification.cwe_name} |
| **Confidence** | ${(classification.confidence * 100).toFixed(1)}% |
| **Routing Lane** | L${classification.lane} |

### Vulnerability Summary
${classification.summary}

### Why Automatic Remediation Failed
${remediation.reason ?? "Qwen3 returned \`cannot_fix\` without a specific reason."}

---
*Generated by **devsecure-orchestrator**. Assign to a senior engineer for manual remediation.*`;

  const res = await ghFetch(`/repos/${repo}/issues`, "POST", pat, {
    title,
    body,
    labels: ["security", "L4-escalation", "needs-human-review"],
  });

  if (!res.ok) {
    throw new Error(`GitHub Issue creation failed: HTTP ${res.status} – ${await res.text()}`);
  }

  return ((await res.json()) as { html_url: string }).html_url;
}

// Step 4b — Fix path: create branch, commit file, open GitHub PR
async function openPr(
  repo: string,
  filePath: string,
  fixedCode: string,
  classification: ClassificationResult,
  baseBranch: string,
  pat: string,
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

  // 5. Open the Pull Request
  let prRes: Response;
  try {
    prRes = await ghFetch(`/repos/${repo}/pulls`, "POST", pat, {
      title: `[DevSecure] Fix ${classification.cwe_id} – ${classification.cwe_name} in \`${filePath}\``,
      body: `## Automated Security Remediation

| Field | Value |
|---|---|
| **CWE** | ${classification.cwe_id} — ${classification.cwe_name} |
| **File** | \`${filePath}\` |
| **Confidence** | ${(classification.confidence * 100).toFixed(1)}% |
| **Routing Lane** | L${classification.lane} |

### Vulnerability Summary
${classification.summary}

---

### Tier B Review Checklist
- [ ] Full test suite passes
- [ ] AST semantic preservation verified (behaviour unchanged)
- [ ] SAST regression scan clean (no new findings)
- [ ] Minimal diff constraint satisfied (only security-relevant lines changed)

> ⚠️ **AI models have zero approval authority.** A human reviewer must approve and merge this PR.

*Generated by **devsecure-orchestrator**.*`,
      head: fixBranch,
      base: baseBranch,
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
let metrics_total_rps_score       = 0;
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
          avg_rps_score:
            metrics_total_requests === 0
              ? 0
              : Math.round((metrics_total_rps_score / metrics_total_requests) * 100) / 100,
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
    // CVE: ds_detection.cve_id takes precedence over top-level cve_id; never inferred
    const cve_id   = ds_detection?.cve_id   ?? body.cve_id;

    // ── Hidden Signal Layer — internal context; never exposed in API responses ─
    const hsl: HiddenSignalLayer = {
      source_type: ds_detection?.type ?? "unknown",
      cwe_hint:    ds_detection?.cwe_hint,
      cve_id:      cve_id,
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
        const gateUrl = await openIssue(
          repo,
          file_path,
          classification,
          { status: "cannot_fix", reason: `Confidence gate triggered: ${gateReason}` },
          env.GITHUB_PAT,
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
      if (remediation.status === "fixed" && remediation.fixed_code_base64) {
        console.log("Remediation received. Base64 length: " + remediation.fixed_code_base64.length);
      } else {
        console.log("Remediation status: " + remediation.status + " — reason: " + (remediation.reason ?? "none"));
      }

      // ── Step 5: Fail-closed gate + Patch Guard ────────────────────────────
      pipelineStep = "github";
      let githubUrl: string;
      let action: "pr_opened" | "issue_escalated";
      let judgeWasRun = false;
      let scorePayload: {
        rps_score: number;
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
        );
        action = "issue_escalated";
      } else {
        // Patch Guard: decode and check diff size before committing
        let decoded: string;
        let guard: PatchGuardResult;
        try {
          decoded = atob(remediation.fixed_code_base64!);
          guard = checkPatchGuard(code, decoded);
        } catch (err) {
          const msg = err instanceof Error ? err.message : String(err);
          console.error("Patch Guard calculation failed, escalating to L4:", msg);
          githubUrl = await openIssue(
            repo,
            file_path,
            classification,
            { status: "cannot_fix", reason: `Patch Guard calculation error: ${msg}` },
            env.GITHUB_PAT,
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
          );
          action = "issue_escalated";
        } else {
          // ── Step 5b: Diversity Judge (risk-triggered, fail-closed) ───────────
          pipelineStep = "judge";
          const judgeTriggerReasons: string[] = [];
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

          // ── Step 5c: RPS fetch ────────────────────────────────────────────
          pipelineStep = "rps";
          let rpsScore: number;
          if (cve_id) {
            rpsScore = await fetchRpsScore(cve_id, env);
          } else {
            console.log(JSON.stringify({ event: "rps_fetch", status: "fallback", reason: "rps_skipped_no_cve" }));
            rpsScore = RPS_DEFAULT_SCORE;
          }

          // ── Step 5d: Final Priority Scoring ──────────────────────────────
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
            if (delta < 0.2)      mismatchPenalty = 5;
            else if (delta <= 0.5) mismatchPenalty = 10;
            else                   mismatchPenalty = 15;
          }

          const rawScore = rpsScore - judgePenalty - patchRisk - laneWeight - mismatchPenalty;
          const finalScore = Math.min(100, Math.max(0, rawScore));

          console.log(JSON.stringify({
            event: "final_scoring",
            rps: rpsScore,
            judge_penalty: judgePenalty,
            lane_weight: laneWeight,
            patch_risk: patchRisk,
            mismatch_penalty: mismatchPenalty,
            final_score: finalScore,
          }));

          // ── Step 5e: Decision engine ──────────────────────────────────────
          pipelineStep = "github";

          // Fail-closed: judge failure or reject always escalates, score is irrelevant
          if (judgeFailure || judgeRejectReason !== null) {
            githubUrl = await openIssue(
              repo, file_path, classification,
              { status: "cannot_fix", reason: judgeRejectReason ?? "Judge failure — fail-closed escalation" },
              env.GITHUB_PAT,
            );
            action = "issue_escalated";
          } else if (finalScore >= 85) {
            githubUrl = await openPr(repo, file_path, decoded, classification, base_branch, env.GITHUB_PAT);
            action = "pr_opened";
          } else if (finalScore >= 70) {
            console.log(JSON.stringify({ event: "final_scoring", warning: "score_in_caution_band", final_score: finalScore }));
            githubUrl = await openPr(repo, file_path, decoded, classification, base_branch, env.GITHUB_PAT);
            action = "pr_opened";
          } else {
            githubUrl = await openIssue(
              repo, file_path, classification,
              { status: "cannot_fix", reason: `Final priority score too low to auto-merge: score=${finalScore} (rps=${rpsScore}, judgePenalty=${judgePenalty}, patchRisk=${patchRisk}, laneWeight=${laneWeight}, mismatchPenalty=${mismatchPenalty})` },
              env.GITHUB_PAT,
            );
            action = "issue_escalated";
          }

          scorePayload = { rps_score: rpsScore, judge_penalty: judgePenalty, patch_risk: patchRisk, lane_weight: laneWeight, mismatch_penalty: mismatchPenalty, final_priority_score: finalScore };

          // Update in-memory metrics (scoring path — has rpsScore + finalScore)
          metrics_total_requests++;
          if (cwe_mismatch) metrics_mismatch_count++;
          if (action === "pr_opened") metrics_pr_opened_count++;
          else metrics_issue_escalated_count++;
          metrics_total_final_score += finalScore;
          metrics_total_rps_score   += rpsScore;
          recent_decisions.push({ timestamp: new Date().toISOString(), repo, cve_id: cve_id ?? null, final_score: finalScore, decision: action });
          if (recent_decisions.length > 10) recent_decisions.shift();
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
