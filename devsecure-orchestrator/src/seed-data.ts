// Author: Jeremy Quadri
// seed-data.ts — Seeds the cwe-knowledge-base Vectorize index with PoC Top 5 CWE guidance.
// Uses Cloudflare Workers AI for embeddings via getEmbedding from ./embed.

import { getEmbedding } from "./embed";
import type { Env } from "./env";

// ---------------------------------------------------------------------------
// PoC Top 5 — CWE remediation guidance
// ---------------------------------------------------------------------------

interface CweRecord {
  id: string;
  cwe_id: string;
  name: string;
  text: string;
}

const CWE_RECORDS: CweRecord[] = [
  {
    id: "CWE-89",
    cwe_id: "CWE-89",
    name: "SQL Injection",
    text: "Guidance: Use parameterized queries. For Python/sqlite3, use '?' placeholders. Example: cursor.execute('SELECT * FROM users WHERE id = ?', (user_id,)). Never use string concatenation or f-strings for SQL.",
  },
  {
    id: "CWE-79",
    cwe_id: "CWE-79",
    name: "Cross-Site Scripting (XSS)",
    text: "Guidance: Use context-aware output encoding. For Node.js, use escape-html. In Python/Flask, use markupsafe.escape(). Prefer .textContent over .innerHTML in JavaScript.",
  },
  {
    id: "CWE-78",
    cwe_id: "CWE-78",
    name: "OS Command Injection",
    text: "Guidance: Avoid shell=True. Use argument lists with subprocess.run(['ls', path]). Prefer built-in library functions like os.path instead of calling OS binaries.",
  },
  {
    id: "CWE-22",
    cwe_id: "CWE-22",
    name: "Path Traversal",
    text: "Guidance: Validate that the resolved path is within the intended directory. Use os.path.abspath() and check the prefix. Sanitize input to remove ../ sequences.",
  },
  {
    id: "CWE-94",
    cwe_id: "CWE-94",
    name: "Code Injection",
    text: "Guidance: Never use eval(), exec(), or new Function() with untrusted input. Use a whitelist of allowed commands or a safe parser like json.parse() if data exchange is needed.",
  },
];

// ---------------------------------------------------------------------------
// Seed function
// ---------------------------------------------------------------------------

export interface SeedResult {
  inserted: string[];
  count: number;
}

export async function seedCWEData(env: Env): Promise<SeedResult> {
  const inserted: string[] = [];

  for (const record of CWE_RECORDS) {
    const vector = await getEmbedding(record.text, env);

    await env.VECTOR_INDEX.upsert([
      {
        id: record.id,
        values: vector,
        metadata: {
          cwe_id: record.cwe_id,
          name: record.name,
          text: record.text,
        },
      },
    ]);

    inserted.push(record.id);
  }

  return { inserted, count: inserted.length };
}
