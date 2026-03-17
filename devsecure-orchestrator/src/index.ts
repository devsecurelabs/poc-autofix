// Author: Jeremy Quadri
// devsecure-orchestrator: Cloudflare Worker
// Fail-closed vulnerability classification and automated remediation pipeline.
// Pipeline: POST /remediate → Qwen2.5 classify → Vectorize RAG → Qwen3 fix → GitHub PR | Issue

import { getEmbedding } from "./embed";
import { seedCWEData } from "./seed-data";
import type { Env } from "./env";

// HF Inference Router — explicit provider path; model encoded in URL, not the request body
const HF_CHAT_BASE = "https://router.huggingface.co/hf-inference/models";
// Fallback model IDs — overridden at runtime by env.CLASSIFIER_MODEL / env.REMEDIATION_MODEL
const DEFAULT_CLASSIFIER_MODEL = "Qwen/Qwen2.5-Coder-7B-Instruct";
const DEFAULT_REMEDIATION_MODEL = "Qwen/Qwen2.5-Coder-32B-Instruct";
const GITHUB_API = "https://api.github.com";

// Env is defined in env.ts and imported above.

// ---------------------------------------------------------------------------
// Request / Response shapes
// ---------------------------------------------------------------------------

interface RemediationRequest {
  repo: string;         // "owner/repo-name"
  file_path: string;    // relative path in repo, e.g. "src/auth.py"
  code: string;         // raw vulnerable source code
  language: string;     // "python" | "javascript" | etc.
  base_branch?: string; // branch to target, defaults to "main"
}

interface ClassificationResult {
  cwe_id: string;       // e.g. "CWE-89"
  cwe_name: string;     // e.g. "SQL Injection"
  confidence: number;   // 0.0 – 1.0
  lane: number;         // 1 = trivial → 4 = architectural / cannot assess
  summary: string;      // one-sentence description
}

interface RemediationResult {
  status: "fixed" | "cannot_fix";
  fixed_code?: string;
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
  // Explicit provider path — model is encoded in the URL; body carries only messages.
  const url = `${HF_CHAT_BASE}/${model}/v1/chat/completions`;
  const res = await fetch(url, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${apiKey}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({ messages, max_tokens: maxTokens, stream: false }),
  });

  if (!res.ok) {
    const errorText = await res.text();
    console.error(`HF chat error [${model}] HTTP ${res.status} at ${url} — response: ${errorText}`);
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

Return ONLY a valid JSON object. No prose. No markdown. No explanation outside the JSON.

If you can fix the vulnerability with confidence ≥ 0.75 and a minimal diff:
{"status":"fixed","fixed_code":"<complete corrected code block, preserving all logic and formatting>"}

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
    throw new Error(`Qwen3 remediation did not return JSON. Raw output: ${raw}`);
  }
  return JSON.parse(match[0]) as RemediationResult;
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
  const prRes = await ghFetch(`/repos/${repo}/pulls`, "POST", pat, {
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
  if (!prRes.ok) {
    throw new Error(`PR creation failed: HTTP ${prRes.status} – ${await prRes.text()}`);
  }

  return ((await prRes.json()) as { html_url: string }).html_url;
}

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

    const { repo, file_path, code, language, base_branch = "main" } = body;

    if (!repo || !file_path || !code || !language) {
      return new Response(
        JSON.stringify({
          error: "Missing required fields.",
          required: ["repo", "file_path", "code", "language"],
        }),
        { status: 400, headers: { "Content-Type": "application/json" } },
      );
    }

    // Auth guard — caller must supply the same secret as the GitHub Action
    const authHeader = request.headers.get("Authorization");
    if (!authHeader || authHeader !== `Bearer ${env.SEED_SECRET}`) {
      return new Response(
        JSON.stringify({ error: "Unauthorized." }),
        { status: 401, headers: { "Content-Type": "application/json" } },
      );
    }

    let pipelineStep = "init";
    try {
      // ── Step 1: Classification (Qwen2.5) ──────────────────────────────────
      pipelineStep = "classification";
      const classification = await classify(code, language, env.HF_API_KEY, env);
      console.log("Classification result:", JSON.stringify(classification));

      // ── Step 2: RAG context retrieval (Vectorize + CF AI embeddings) ───────
      pipelineStep = "rag";
      const ragContext = await retrieveRagContext(
        classification.cwe_id,
        classification.summary,
        env.VECTOR_INDEX,
        env,
      );
      console.log("RAG context length:", ragContext.length);

      // ── Step 3: Remediation (Qwen3) ───────────────────────────────────────
      pipelineStep = "remediation";
      const remediation = await remediate(
        code,
        language,
        classification,
        ragContext,
        env.HF_API_KEY,
        env,
      );

      // ── Step 4: Fail-closed gate ──────────────────────────────────────────
      pipelineStep = "github";
      let githubUrl: string;
      let action: "pr_opened" | "issue_escalated";

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
        // Fix path → commit + open GitHub PR
        githubUrl = await openPr(
          repo,
          file_path,
          remediation.fixed_code!,
          classification,
          base_branch,
          env.GITHUB_PAT,
        );
        action = "pr_opened";
      }

      return new Response(
        JSON.stringify({
          action,
          github_url: githubUrl,
          classification,
          remediation_status: remediation.status,
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
