// Author: Jeremy Quadri
// embed.ts — Embedding helper using Cloudflare Workers AI (@cf/baai/bge-base-en-v1.5, 768 dims).
// Replaces the Hugging Face embedding call to eliminate external 404 routing issues.

import type { Env } from "./env";

export async function getEmbedding(text: string, env: Env): Promise<number[]> {
  const result = await env.AI.run("@cf/baai/bge-base-en-v1.5", { text: [text] });
  const vector: number[] = (result as unknown as { data: number[][] }).data[0];

  // @cf/baai/bge-base-en-v1.5 must return 768 dimensions to match the Vectorize index.
  if (vector.length !== 768) {
    throw new Error(`Embedding dimension mismatch: expected 768, got ${vector.length}`);
  }

  return vector;
}
