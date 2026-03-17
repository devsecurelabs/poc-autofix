# DevSecure v4.0: Cloud Infrastructure Architecture

[cite_start]This document defines the cloud infrastructure required to support the DevSecure v4.0 automated remediation pipeline[cite: 1, 2]. The architecture is divided into the target production state and a lightweight Proof of Concept (PoC) for rapid testing.


---

## 1. Enterprise Production Infrastructure

[cite_start]To run the fail-closed, dual-model architecture at scale[cite: 2], the following cloud components are required. 

### 1.1 LLM Inference Nodes
[cite_start]The pipeline splits inference into two distinct planes, requiring different compute profiles[cite: 3].
* [cite_start]**Classification Plane (Advisory SLM):** Hosts `Qwen2.5-Coder-1.5B`[cite: 7]. 
  * **Compute Profile:** Lightweight GPU instances (e.g., NVIDIA L4 or T4) or high-end CPUs.
  * **Scaling:** Highly elastic, autoscaling based on incoming code commit volume.
* [cite_start]**Execution Plane (Patch Author Agent):** Hosts `Qwen3-Coder-30B-A3B`[cite: 7, 35].
  * **Compute Profile:** Heavy GPU infrastructure (e.g., NVIDIA A100 or H100 clusters) required for a 30B parameter model.
  * **Scaling:** Queue-based provisioning to manage cost, processing fixes asynchronously.

### 1.2 Orchestration & Routing Layer
This layer acts as the middleware brain, handling context assembly and model routing.
* **Compute Containerization:** Kubernetes (EKS/GKE) or serverless container environments (AWS Fargate/Cloud Run).
* [cite_start]**The Go Router:** An initial microservice that performs the fast Cyclomatic Complexity Number (CCN) check before hitting the LLMs[cite: 159].
* [cite_start]**Remediation Control Router:** Evaluates the 26-dimensional complexity vector outputted by Qwen2.5 and strictly assigns the L1-L4 lane[cite: 26, 159].

### 1.3 RAG Knowledge Store
[cite_start]Required to inject semantic context into the Qwen3 Execution Plane[cite: 74, 75].
* **Vector Database:** A managed vector store (e.g., Pinecone, Milvus, or pgvector on RDS).
* [cite_start]**Data Sources:** Stores embedding vectors for CWE-indexed secure coding patterns and historical `verified_freshfix` patch exemplars[cite: 75, 76].

### 1.4 Deterministic Verification Environments
[cite_start]Crucial for the pipeline's zero-approval-authority constraint[cite: 36, 43].
* [cite_start]**Tier A Gates (Fast, Per-Iteration):** Ephemeral sandbox containers built for rapid execution[cite: 142]. [cite_start]Must execute syntax checks, original detector re-runs, minimal diff checks against lane budgets, and AST safety attestations[cite: 143, 144, 145, 146].
* [cite_start]**Tier B Gates (Final PR, Heavy):** Dedicated CI/CD runners (e.g., GitHub Actions larger runners or GitLab CI)[cite: 147]. [cite_start]Executes the full test suite, semantic preservation gate via AST, and full SAST security regression scans[cite: 148, 149, 150].

### 1.5 L4 Manual Escalation Queue
[cite_start]The fail-closed backstop for the system[cite: 154].
* **Integration:** Direct API hooks into enterprise ticketing systems (Jira, ServiceNow, or GitHub Issues).
* [cite_start]**Triggers:** Receives payloads when Qwen3 outputs `cannot_fix`, or when the iteration budget is exhausted without consensus[cite: 83, 157].

---

## 2. Lightweight Proof of Concept (PoC) Implementation

Before provisioning the heavy production infrastructure, this PoC implements the DevSecure v4.0 architecture using a serverless, hybrid stack.



### 2.1 PoC Architecture Overview
This PoC implements a fail-closed event-driven architecture. It leverages GitHub Actions for event triggering and deterministic verification, Cloudflare Workers and Vectorize for serverless orchestration and RAG, and Hugging Face Inference APIs for AI-driven analysis. 

### 2.2 PoC Core Components
* **GitHub Repository (Source of Truth & Escalation):**
    * Receives proposed fixes exclusively via Pull Requests (PRs).
    * Utilizes **GitHub Issues** as the **L4 Manual Escalation Queue**. 
* **GitHub Actions (Triggers & Verification Gates):**
    * **Trigger:** Activates when a security scanner flags a vulnerability.
    * [cite_start]**Tier A Gates:** A fast action runs syntax checks and minimal diff constraint validations[cite: 143, 145].
    * [cite_start]**Tier B Gates:** Runs on the open PR, executing the full test suite and a SAST scan[cite: 148, 150].
* **Cloudflare Workers & Vectorize (Orchestration & RAG):**
    * **Worker:** Handles API chaining, JSON extraction, and fail-closed logic.
    * [cite_start]**Vectorize:** Queries the vector database to retrieve CWE-indexed secure coding guidance and verified historical patches[cite: 75, 76].
* **Hugging Face API (LLM Inference):**
    * [cite_start]**Model 1 (Qwen2.5):** Outputs structured JSON vulnerability report (CWE ID, confidence, lane)[cite: 26].
    * [cite_start]**Model 2 (Qwen3):** Ingests Qwen2.5's JSON and the Vectorize RAG context to output the fixed code block or a `cannot_fix` status[cite: 58, 83].

### 2.3 PoC End-to-End Flow
1. **Detection:** GitHub Action detects a vulnerability and POSTs context to the Cloudflare Worker.
2. **Classification:** Worker calls Hugging Face (Qwen2.5). [cite_start]Returns classification JSON[cite: 159].
3. **Context Retrieval:** Worker queries Cloudflare Vectorize for CWE guidance.
4. [cite_start]**Remediation:** Worker calls Hugging Face (Qwen3) with the original code, JSON, and RAG context[cite: 58, 74].
5. **Gate Evaluation:**
   * [cite_start]If `cannot_fix`, Worker opens a GitHub Issue (L4 Queue)[cite: 83].
   * If `fixed`, Worker opens a PR. [cite_start]Tier A and B gates run on the PR[cite: 142, 147].