# DevSecure v4.0: Cloud Infrastructure Architecture

This document defines the cloud infrastructure and architectural mandates required to support the DevSecure v4.0 automated remediation pipeline. It outlines the target enterprise production state and the lightweight Proof of Concept (PoC) implementation.

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

---

## 2. Enterprise Production Infrastructure

### 2.1 LLM Inference Planes (Multi-Agent System)
The pipeline splits inference into distinct planes, requiring different compute profiles and strict model diversity.

* **Classification Plane (Advisory SLM)**
  * **Model:** `Qwen2.5-Coder-1.5B`
  * **Output:** `{cwe_id, confidence, lane, summary}`
* **Execution Plane (Patch Author Agent)**
  * **Model:** `Qwen2.5-Coder-1.5B`
  * **Responsibility:** Generates candidate fixes (base64 encoded).
* **Primary Reviewer (Critique Agent)**
  * **Model:** Same-family model (Qwen)
  * **Validates:** Logical correctness, security completeness, and minimality of fix.
* **Diversity Reviewer (MANDATORY for Risk-Triggered Cases)**
  * **Model:** Different model provider (e.g., OpenAI / Claude)
  * **Purpose:** Break correlated hallucinations and provide an independent critique signal.
  * **Trigger Conditions:** `lane >= 3`, `confidence < threshold`, retry occurred, or patch risk mismatch signals.

### 2.2 Orchestration & Control Layer (Cloudflare Worker)
Acts as the pipeline orchestrator, policy enforcement engine, and failure router.
* **Responsibilities:** Classification → Remediation → Review → Scoring → Decision.
* Handles failure classification, routes to the Safe Advisory Layer, and manages GitHub integrations (PRs / Issues).

### 2.2.1 Detection Normalisation Layer (Internal Signal Handling)
The underlying detection engine (`ds_detection`, e.g., OpenGrep) acts strictly as a **silent enrichment oracle**.
* **CVE Extraction:** The engine is used solely to extract reference CVE IDs.
* **Taxonomy Scrubbing (MANDATORY):** Detection-derived fields (CWE, severity, confidence) are explicitly discarded to prevent taxonomy contamination. The LLM Classification Plane is the sole source of truth for CWE and confidence.
* **Data Privacy:** The extracted CVE ID is stored internally and passed to the RPS API, but is NEVER surfaced externally in UIs, PRs, or L4 Issues.

### 2.2.2 Heuristic Pseudo-Risk Engine (Zero-Day Handling)
If `ds_detection` yields no CVE (e.g., internal code or zero-days), the pipeline must not default to a static neutral score, which would paralyze the auto-merge path.
* **Fallback Logic:** The engine synthesizes a `Pseudo_RPS` by mapping the LLM-derived `CWE_ID` to a static severity baseline, multiplied by the SLM's `Relative Confidence` score.
* **Outcome:** This ensures internal critical vulnerabilities (like a custom SQL injection) receive a high enough synthetic RPS to trigger the autonomous PR path, provided they pass all Deterministic Verification Gates.

### 2.3 Risk & Decision Engine (Control Plane)
**Crucial Rule:** The final decision to merge is NOT based on LLM output.
* **Inputs:** RPS score (external API), judge output, patch risk, lane weight, and hidden signals.
* **Algorithm:** `final_priority_score = clamp(rps - judge_penalty - patch_risk - lane_weight - mismatch_penalty, 0–100)`
* **Decision Policy:**
  * `>= 85`: Open PR
  * `70–84`: Open PR (with warning labels)
  * `< 70`: Discard to Issue (L4 Escalation)

### 2.4 Hidden Signal Layer (Critical Moat)
Non-visible signals strictly influence risk scoring:
* **CWE mismatch** (Detector vs. LLM classification).
* **Retry occurrence** (Increases risk weight dynamically).
* **Patch size anomaly** (Violates minimal diff).
* **Judge disagreement** (Agentic debate conflict).

### 2.5 Deterministic Verification System
The sole approval authority of DevSecure.

* **Tier A (Fast Gates):** Syntax validation, minimal diff enforcement, original vulnerability re-check, AST safety checks.
* **Tier B (Heavy Gates):** Full test suite execution, semantic preservation, and security regression scanning.
* **Failure Mapping:** If Tier A or B fails, the outcome is strictly mapped to `validation`. Immediate escalation; no human override path.

### 2.6 Safe Advisory Layer (L4 Escalation Only)
Triggered when any failure occurs or no verified fix can be produced. 
* **MUST Include:** Root cause, remediation strategy.
* **MUST NOT Include:** Full patches, copy-paste code, repo-specific fixes.
* **Mandatory Footer:** > *No verified fix could be safely generated.*
  > ⚠️ *Not verified by DevSecure gates*

### 2.7 L4 Escalation Queue (GitHub Issues)
Driven exclusively by the Failure Classification model.
* **Issue Experience Contract:** Every issue must contain the context (CWE, confidence, lane), failure type + reason, the Safe Advisory, and the trust boundary warning.
* **Idempotency:** Same `repo + file + CWE` must update the existing issue to prevent alert fatigue.

### 2.8 RAG Knowledge Store (Verified Learning Only)
* **Data Sources:** CWE secure patterns and Verified fixes ONLY.
* **STRICT RULE: ❌ NO RED PATHS FEED LEARNING**
  * ✅ Verified PR (passed all gates): **YES**
  * ❌ Failed fix / advisory: **NO**
  * ❌ LLM raw outputs: **NO**
* **Purpose:** Improve fix quality, inject secure coding patterns, and avoid hallucination drift.

---

## 3. PoC Architecture (Serverless Implementation)

### 3.1 Components
* **GitHub:** Source of truth (PR = success path, Issues = fail-closed path).
* **GitHub Actions:** Pipeline triggers and execution environment for Tier A/B gates.
* **Cloudflare Workers:** Orchestration, Control Plane logic, Risk scoring, and Advisory layer.
* **Cloudflare Vectorize:** RAG retrieval (verified knowledge only).
* **Hugging Face APIs:** Qwen2.5 (Classification) and Qwen3 (Remediation).
* **External LLM Provider (MANDATORY):** Used exclusively for the Diversity Reviewer.

### 3.2 End-to-End Flow
1. **Detection:** Triggered via GitHub Action. Worker receives payload.
2. **Classification:** Routed to Qwen2.5.
3. **Context Retrieval:** Secure patterns pulled from Vectorize.
4. **Remediation:** Qwen3 attempts patch generation.
5. **Review:** Primary Reviewer critiques. Diversity Reviewer critiques (if triggered by risk).
6. **Decision:** * **PR (if safe):** Verification gates run (Tier A/B).
   * **Issue + Advisory (if failed):** Fail-closed with explicit classification.

---

## 4. Observability & Metrics

**Structured Logs (MANDATORY)**
Every end-state decision must emit a machine-readable JSON log:
```json
{
  "event": "failure_classified",
  "failure_type": "infra|model|policy|validation",
  "reason": "...",
  "cwe_id": "...",
  "lane": 3
}