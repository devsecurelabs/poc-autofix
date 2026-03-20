# DevSecure v4.0: Cloud Infrastructure Architecture

This document defines the cloud infrastructure and architectural mandates required to support the DevSecure v4.0 automated remediation pipeline. It outlines the target enterprise production state and the lightweight Proof of Concept (PoC) implementation.

## Strategic Positioning

DevSecure operates across two distinct security timelines:
* **Pre-CVE (Code Risk):** Fusion Score — prevents vulnerabilities before disclosure in proprietary code.
* **Post-CVE (Exploit Risk):** RPS — prioritizes real-world exploitation risk for known dependencies.

### Why This Architecture Matters
Traditional tools rely on CVE-based scoring, which cannot evaluate new or proprietary vulnerabilities. DevSecure introduces a dual-engine model: the Fusion Score secures code before disclosure (zero-day prevention), while the RPS prioritizes real-world exploitation risk post-disclosure. This enables DevSecure to secure both unreleased code and production systems simultaneously.

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

### 1.3 Failure Classification Model (MANDATORY)
This model permanently replaces all legacy `cannot_fix` logic. All failures MUST be explicitly classified:
* **`infra`**: Parsing, encoding (e.g., `atob()`), transport, or runtime errors.
* **`model`**: Invalid JSON outputs, hallucinated structures, or retry exhaustion.
* **`policy`**: Lane routing rejections, judge rejections, or risk control blocks.
* **`validation`**: Test suite failures, patch guard blocks, or semantic preservation failures.

### 1.4 Strict Single-File Constraint (Bounded Autonomy)
* **V1 Blast Radius Limit:** The AI Execution Plane is strictly constrained to single-file remediations.
* **Multi-File Fallback:** If a vulnerability requires cross-file refactoring, the system mathematically locks out the Auto-Merge path and defaults to an "AI-Assisted PR" requiring human review. Safety over reckless autonomy.

---

## 2. Enterprise Production Infrastructure

### 2.1 LLM Inference Planes (Multi-Agent System)
The pipeline splits inference into distinct planes, requiring different compute profiles and strict model diversity.

* **Classification Plane (Advisory SLM)**
  * **Model:** `Qwen2.5-Coder-1.5B`
  * **Output:** `{cwe_id, confidence, lane, summary}`
* **Execution Plane (Patch Author Agent)**
  * **Model:** `Qwen2.5-Coder-32B-Instruct`
  * **Responsibility:** Generates candidate fixes (base64 encoded).
* **Primary Reviewer (Critique Agent)**
  * **Model:** Same-family model (Qwen)
  * **Validates:** Logical correctness, security completeness, and minimality of fix.
* **Diversity Reviewer (MANDATORY for Risk-Triggered Cases)**
  * **Model:** Different model provider (e.g., OpenAI / Claude)
  * **Purpose:** Break correlated hallucinations and provide an independent critique signal.
  * **Trigger Conditions:**
    * lane >= L3
    * classification confidence < threshold
    * retry occurred
    * reviewer disagreement

### 2.2 Synchronous API Gateway & Orchestration (Cloudflare Worker)
Acts as the pipeline orchestrator, policy enforcement engine, and failure router for the synchronous fast-track.

#### 2.2.1 Detection Normalisation Layer (Internal Signal Handling)
The underlying detection engine (`ds_detection`, e.g., OpenGrep) acts strictly as a **silent enrichment oracle**.
* **CVE Handling:** CVE extraction is OPTIONAL enrichment only. Absence of a CVE is expected for internal code.
* **Primary Truth Source:** CWE classification is ALWAYS derived from the LLM Classification Plane, discarding detection-derived severity/confidence to prevent taxonomy contamination.
* **Data Privacy:** CVE is not surfaced for proprietary code findings, but MAY be surfaced for dependency-based vulnerabilities.

#### 2.2.2 Dual Risk Engine Model (MANDATORY)
DevSecure operates two distinct risk engines:
1. **External Risk Engine (RPS):**
   * **Input:** CVE
   * **Sources:** CVSS, EPSS, CISA KEV
   * **Applies:** ONLY to known vulnerabilities (dependencies, OSS).
2. **Internal Risk Engine (Fusion Score):**
   * **Input:** CWE + code context
   * **Applies:** To proprietary code and zero-day vulnerabilities.

**MANDATORY RULE:** CVE present → use RPS. No CVE → use Fusion Score. NEVER synthesize fake CVEs or pseudo-RPS.

#### 2.2.3 Asynchronous Analysis Engine (Enterprise Scale)
Heavy architectural analysis (e.g., Cyclomatic Complexity, cross-file Taint Analysis) is offloaded from the Cloudflare Worker to Go/Python microservices via message queues to avoid CPU timeouts.

### 2.3 Risk & Decision Engine (Control Plane)
**Crucial Rule:** The final decision to merge is NOT based on LLM output.
* **Inputs:** Risk Score, judge output, patch risk, lane weight, and hidden signals.
* **Algorithm:** `final_priority_score = clamp(risk_score - judge_penalty - patch_risk - lane_weight - mismatch_penalty, 0, 100)`
* *(Where `risk_score` = RPS (if CVE exists) OR Fusion Score (if no CVE))*

* **Decision Policy:**
  * **>= 85:** Auto-merge PR (safe path)
  * **70–84:** PR with manual review required
  * **< 70:** L4 escalation (fail-closed)

* **Final Authority:** All routing decisions are validated by the State Integrity Matrix. Invalid states are impossible by design.

#### 2.3.1 Audit-Grade State Integrity Matrix
Final routing is governed by an explicit state matrix. The system physically cannot escalate a successful fix or auto-merge a failed/high-risk fix. Any invalid state throws a hard `ROUTING_INTEGRITY_VIOLATION` error, instantly failing-closed and preserving the audit trail for SIEM ingestion.

#### 2.3.2 Fusion Score (Internal Risk Engine)
Fusion Score is a deterministic risk metric for zero-day vulnerabilities.

* **Normalization Rule:**
  Fusion Score MUST be normalized to a 0–100 scale to align with decision engine thresholds.
  `Fusion_Score = clamp(CWE_Severity_Base * Confidence_Weight * Blast_Radius_Factor, 0, 100)`

* **CWE Severity Mapping (Deterministic):**
  * Critical (e.g., RCE, SQLi): 80–90
  * High (e.g., Command Injection, Auth bypass): 70–80
  * Medium: 40–70
  * Low: < 40

* **Confidence Constraints:**
  * confidence < 0.40 → classification = uncertain → route L4
  * confidence < 0.75 → remediation must output cannot_fix

* **Lane Influence:**
  * L1–L2: low blast radius → lower risk multiplier
  * L3–L4: high blast radius → increases Fusion Score weighting

* **Fail-Closed Rule:** Unknown CWE → default severity = 80 (HIGH).

### 2.4 Hidden Signal Layer (Critical Moat)
Non-visible signals strictly influence risk scoring: CWE mismatch, retry occurrence, patch size anomaly, and judge disagreement.

### 2.5 Deterministic Verification System
The sole approval authority of DevSecure.
* **Tier A (Fast Gates):** Syntax validation, minimal diff enforcement, AST safety checks.
* **Tier B (Heavy Gates):** Full test suite execution, security regression scanning.
* **Tier C (Post-Merge Production Guardrails):** Integrates with Datadog/New Relic to trigger automated `git revert` if 5xx errors or latency spike within 15 minutes of merge.

---

## 3. PoC Architecture (Serverless Implementation)

### 3.1 Components
* **GitHub Actions:** Pipeline triggers and execution environment for Tier A/B gates.
* **Cloudflare Workers:** Orchestration, Control Plane logic, Risk scoring, and Advisory layer.
* **Hugging Face APIs:** Qwen2.5-Coder (Classification) and Qwen3-Coder (Remediation).

### 3.2 End-to-End Flow
1. **Detection:** Triggered via GitHub Action. Worker receives payload.
2. **Classification:** Routed to Qwen2.5-Coder.
3. **Context Retrieval:** Secure patterns pulled from Vectorize.
4. **Remediation:** Qwen3-Coder attempts patch generation.
5. **Review:** Primary Reviewer critiques.
6. **Decision:**
   * **Risk Score Calculated:**
     * CVE present → RPS
     * No CVE → Fusion Score
   * **Routing:**
     * If safe → verification gates (Tier A/B)
     * If failed → L4 escalation (fail-closed)

---

## 4. Observability & Metrics

**Structured Logs (MANDATORY)**
Every end-state decision must emit a machine-readable JSON log.