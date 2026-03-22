const fs = require('fs');
const path = require('path');

// ==========================================
// 🧠 SOURCE OF TRUTH (System Configuration)
// In Phase 2, this will be imported directly from src/config.ts
// ==========================================
const SYSTEM_CONFIG = {
  thresholds: {
    auto_merge: 85,
    manual_review: 70,
    fail_closed: 69
  },
  patch_guard: {
    max_lines_changed_percent: 20,
    absolute_max_lines: 50
  },
  agent_contract: [
    "Do not refactor unrelated code",
    "Do not delete business logic",
    "Do not hardcode values",
    "Preserve functionality",
    "Use secure standard patterns"
  ],
  required_judge_checks: [
    "removed_original_vulnerability",
    "preserved_original_business_logic",
    "did_not_hardcode_values",
    "did_not_delete_functionality"
  ]
};

// ==========================================
// 📄 DOCUMENT TEMPLATE
// ==========================================
const template = `# DevSecure v4.0: Cloud Infrastructure Architecture

This document defines the cloud infrastructure and architectural mandates required to support the DevSecure v4.0 automated remediation pipeline. 
> ⚠️ **AUTO-GENERATED ARTIFACT:** This document is generated from system source code. Do not edit manually.

## Strategic Positioning

DevSecure operates across two distinct security timelines:
* **Pre-CVE (Code Risk):** Fusion Score — prevents vulnerabilities before disclosure in proprietary code.
* **Post-CVE (Exploit Risk):** RPS — prioritizes real-world exploitation risk for known dependencies.

---

## 1. Core Architectural Principles

### 1.1 Fail-Closed Guarantee
* **No AI-generated code is ever trusted by default.**
* All fixes must pass deterministic verification (Tier A + Tier B).
* Any failure results in a routed Issue (L4 Escalation); there are **never** silent successes or silent failures.

### 1.2 Separation of Domains
| Domain | Responsibility |
| :--- | :--- |
| **AI Domain** | Propose + critique |
| **Deterministic Domain** | Verify + enforce |
| **Control Plane** | Decide outcome (Governance) |

---

## 2. Enterprise Production Infrastructure

### 2.1 Agent Contract Layer (MANDATORY)
All AI agents operate under a shared constitutional contract enforced both in prompts and code.
**Core Contract:**
${SYSTEM_CONFIG.agent_contract.map(c => `* ${c}`).join('\n')}

**Rule:** LLM output is strictly advisory. Code enforcement is authoritative.

### 2.2 LLM Safety Boundary
All LLM outputs are treated as highly untrusted, volatile inputs.
**Controls:**
* **Safe JSON Parsing:** All agent responses are wrapped in \`try/catch\` blocks.
* **Fail-Closed Fallbacks:** Malformed AI output injects a fail-closed schema (e.g., \`remediation_status = cannot_fix\`).
* **Checklist Enforcement:** Missing checklist fields automatically trigger a rejection.

### 2.3 Execution State Model
Final routing is governed by an explicit State Integrity Matrix.
* **Core States:** \`remediation_status\` (fixed | cannot_fix) and \`action\` (pr_opened | issue_escalated | auto_merged)
* **Invariants:**
  * \`fixed\` + \`escalated\` → ROUTING_INTEGRITY_VIOLATION
  * \`cannot_fix\` + \`pr_opened\` → ROUTING_INTEGRITY_VIOLATION
  * Score < ${SYSTEM_CONFIG.thresholds.auto_merge} + \`auto_merged\` → ROUTING_INTEGRITY_VIOLATION

### 2.4 Dual Risk Engine Model
1. **External Risk Engine (RPS):** Input: CVE. Applies ONLY to known dependencies.
2. **Internal Risk Engine (Fusion Score):** Input: CWE + code context. Applies to proprietary code.
**MANDATORY RULE:** CVE present → use RPS. No CVE → use Fusion Score.

### 2.5 Risk & Decision Engine Thresholds
**Algorithm:** \`final_priority_score = clamp(risk_score - judge_penalty - patch_risk - lane_weight - mismatch_penalty, 0, 100)\`
* **>= ${SYSTEM_CONFIG.thresholds.auto_merge}:** Auto-merge PR (safe path)
* **${SYSTEM_CONFIG.thresholds.manual_review}–${SYSTEM_CONFIG.thresholds.auto_merge - 1}:** PR with manual review required
* **<= ${SYSTEM_CONFIG.thresholds.fail_closed}:** L4 escalation (fail-closed)

---

## 3. PoC Architecture (Serverless Implementation)

### 3.1 Components
* **GitHub Actions:** Pipeline triggers and execution environment.
* **Cloudflare Workers:** Orchestration, Control Plane logic, Risk scoring.

### 3.2 PoC Scope Constraints
The current Proof of Concept (PoC) supports:
* **SAST (CWE-based detection)**
* **Fusion Score routing**

**Out of Scope for PoC Demo:**
* RPS runtime integration (Defined architecturally, but inactive in PoC execution path)
* SCA dependency scanning
* Multi-file remediation

---

## 4. Observability & Failure Handling

### 4.1 Failure Handling Examples
* **Example 1: Malformed LLM Output** → JSON parse fails → injected fail object → \`remediation_status = cannot_fix\` → L4 Issue created.
* **Example 2: Patch Guard Failure** → diff exceeds ${SYSTEM_CONFIG.patch_guard.max_lines_changed_percent}% → policy failure override → escalation.
* **Example 3: Judge Checklist Failure** → AI omits '${SYSTEM_CONFIG.required_judge_checks[1]}' → override AI verdict → reject patch.

`;

// ==========================================
// 🚀 COMPILE AND WRITE
// ==========================================
const outputPath = path.join(__dirname, '..', 'CLAUDE.md');
fs.writeFileSync(outputPath, template.trim());
console.log('✅ CLAUDE.md successfully auto-generated from system config!');