// ─── Prompt Injection Patterns ────────────────────────────────────────────────

const INJECTION_PATTERNS: RegExp[] = [
  /^SYSTEM:\s*/gim,
  /^INSTRUCTION:\s*/gim,
  /^IGNORE\s+PREVIOUS\s*/gim,
  /^YOU\s+ARE\s+NOW\s*/gim,
];

const SCRIPT_TAG_PATTERN = /<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi;
const HTML_TAG_PATTERN = /<[^>]+>/g;
const CODE_FENCE_PATTERN = /^```[^\n]*$/gm;

// ─── Sanitise Function ────────────────────────────────────────────────────────

/**
 * Sanitise a string before injecting it into an LLM prompt.
 * Removes HTML tags, script blocks, prompt injection patterns, and code fence markers.
 * Truncates to maxLength characters.
 */
export function sanitiseForLLM(input: string, maxLength: number): string {
  let sanitised = input;

  // Remove script tag content
  sanitised = sanitised.replace(SCRIPT_TAG_PATTERN, '[SCRIPT_REMOVED]');

  // Remove HTML tags
  sanitised = sanitised.replace(HTML_TAG_PATTERN, '');

  // Remove prompt injection patterns (line by line for multi-line)
  for (const pattern of INJECTION_PATTERNS) {
    sanitised = sanitised.replace(pattern, '[REDACTED] ');
  }

  // Remove markdown code fence markers (``` lines)
  sanitised = sanitised.replace(CODE_FENCE_PATTERN, '');

  // Truncate
  if (sanitised.length > maxLength) {
    sanitised = sanitised.slice(0, maxLength) + '\n[TRUNCATED]';
  }

  return sanitised;
}
