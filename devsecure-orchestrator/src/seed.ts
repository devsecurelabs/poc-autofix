// Author: Jeremy Quadri
// seed.ts — Populates the cwe-knowledge-base Vectorize index with CWE remediation guidance.
// Trigger via GET /seed on the deployed Worker (one-shot, idempotent).

import { hfEmbed } from "./embed";
import type { Env } from "./env";

// ---------------------------------------------------------------------------
// CWE knowledge base
// ---------------------------------------------------------------------------

interface CweEntry {
  id: string;       // Primary Vectorize ID — also used as the CWE identifier
  cwe_id: string;   // Human-readable label stored in metadata
  name: string;     // Short CWE name
  text: string;     // Prescriptive remediation guidance (embedded into the vector)
}

export const CWE_DATA: CweEntry[] = [
  {
    id: "CWE-89",
    cwe_id: "CWE-89",
    name: "SQL Injection",
    text: `CWE-89 SQL Injection — Remediation Guidance

NEVER concatenate user-controlled input into a SQL string. Always use parameterised queries or prepared statements through your database driver.

Python (psycopg2 / sqlite3):
  BAD:  cursor.execute("SELECT * FROM users WHERE name = '" + name + "'")
  GOOD: cursor.execute("SELECT * FROM users WHERE name = %s", (name,))

Node.js (pg / mysql2):
  BAD:  db.query("SELECT * FROM users WHERE name = '" + name + "'")
  GOOD: db.query("SELECT * FROM users WHERE name = $1", [name])

ORM layer: use the ORM's query-builder methods; never drop into raw SQL with interpolated values unless the ORM explicitly marks the call as safe and you are binding parameters.

Input validation is a defence-in-depth measure, NOT a substitute for parameterisation. An allowlist regex on the input field should accompany — never replace — parameterised queries.

Error messages must never expose SQL structure to the client. Catch database exceptions and return generic 500 responses; log the full error server-side only.`,
  },
  {
    id: "CWE-79",
    cwe_id: "CWE-79",
    name: "Cross-Site Scripting (XSS)",
    text: `CWE-79 Cross-Site Scripting (XSS) — Remediation Guidance

NEVER insert unsanitised user input into HTML, JavaScript, CSS, or URL contexts. The fix depends on the output context.

HTML body context — escape these five characters before rendering:
  & → &amp;   < → &lt;   > → &gt;   " → &quot;   ' → &#x27;
  Use your framework's built-in escaping (e.g. Jinja2 {{ value }}, React JSX expressions) rather than manual string replacement.

HTML attribute context — the same escaping applies; additionally quote every attribute value.

JavaScript context — use JSON.stringify() to embed server data; never use innerHTML or document.write() with user data. Prefer textContent over innerHTML.

URL context — encode with encodeURIComponent() for query parameters; validate that scheme is http or https before using a URL in a redirect.

Content Security Policy (CSP): set a strict CSP header (default-src 'self'; script-src 'self') as a defence-in-depth layer. CSP alone is NOT a fix.

Stored XSS: sanitise on input AND escape on output. Use a library such as DOMPurify for rich-text HTML; do not write your own allowlist parser.`,
  },
  {
    id: "CWE-78",
    cwe_id: "CWE-78",
    name: "OS Command Injection",
    text: `CWE-78 OS Command Injection — Remediation Guidance

NEVER pass user-controlled data to a shell interpreter. The safest fix is to avoid invoking a shell entirely.

Python:
  BAD:  subprocess.run("ls " + user_path, shell=True)
  GOOD: subprocess.run(["ls", user_path], shell=False)
  Rule: use subprocess.run() or subprocess.Popen() with an ARGUMENT LIST (shell=False). Never set shell=True when any argument derives from user input.
  If you must validate the input first, use a strict allowlist (e.g. re.fullmatch(r'[a-zA-Z0-9._/-]+', user_path)) and still prefer the argument-list form.

Node.js:
  BAD:  exec("ls " + userPath)
  GOOD: execFile("ls", [userPath])   // or spawn("ls", [userPath])
  Use execFile() or spawn() with a separate args array; never exec() with concatenated input.

Shell scripts:
  Quote every variable expansion: "$variable" not $variable.
  Use -- to signal end of options before user-supplied arguments: command -- "$arg".

Do NOT rely on blocklist filtering (stripping ;, |, &, etc.) — encoding tricks and Unicode lookalikes routinely bypass these checks. Use the argument-list pattern exclusively.`,
  },
  {
    id: "CWE-22",
    cwe_id: "CWE-22",
    name: "Path Traversal",
    text: `CWE-22 Path Traversal — Remediation Guidance

NEVER construct a filesystem path from user input without canonicalisation and containment checks.

Step 1 — Canonicalise: resolve the absolute real path BEFORE checking it.
  Python:  safe = os.path.realpath(os.path.join(BASE_DIR, user_input))
  Node.js: safe = path.resolve(BASE_DIR, userInput)
  realpath / resolve expands ../ sequences and symlinks so the check in step 2 is reliable.

Step 2 — Containment assertion: verify the resolved path starts with the allowed base directory.
  Python:
    if not safe.startswith(os.path.realpath(BASE_DIR) + os.sep):
        raise PermissionError("Path traversal detected")
  Node.js:
    if (!safe.startsWith(path.resolve(BASE_DIR) + path.sep)) throw new Error("Forbidden path");

Step 3 — Allowlist filenames where possible: if the set of valid files is known, validate the filename against an explicit list or a strict pattern (e.g. /^[a-z0-9_-]+\\.html$/) before constructing the path at all.

Never expose directory listings to the user. Catch ENOENT / FileNotFoundError and return a generic 404; do not echo back the attempted path.

Symlink attacks: if the base directory may contain symlinks, use lstat() to confirm the resolved target is still inside the base before opening.`,
  },
  {
    id: "CWE-94",
    cwe_id: "CWE-94",
    name: "Code Injection",
    text: `CWE-94 Code Injection — Remediation Guidance

NEVER pass user-controlled input to code-evaluation functions. These functions must be treated as unconditionally forbidden when any part of their argument is user-supplied.

Forbidden functions — do not call with user data under any circumstances:
  Python:  eval(), exec(), compile(), __import__()
  Node.js: eval(), new Function(), setTimeout(string), setInterval(string), vm.runInNewContext() with user code
  PHP:     eval(), assert() with a string argument, preg_replace() with /e modifier
  Ruby:    eval(), instance_eval(), class_eval() with user strings

Safe alternatives:
  - Replace dynamic expression evaluation with a safe parser or a restricted expression engine
    (e.g. asteval for Python maths expressions, filtrex for JS rule evaluation).
  - Replace dynamic dispatch (eval("func_" + name + "()")) with an explicit allowlist map:
      ALLOWED = {"add": add_fn, "subtract": sub_fn}
      fn = ALLOWED.get(user_input)
      if fn: fn()
  - For templating: use a sandboxed template engine (Jinja2 with sandbox, Nunjucks) rather
    than string interpolation followed by eval.

If legacy code cannot be refactored immediately:
  - Strict allowlist validation on the input (exact match against known-good values only).
  - Run the evaluation in an isolated subprocess with minimal OS privileges (no network, no filesystem write).
  - Log every invocation with the full input for audit purposes.

Note: allowlist validation is a defence-in-depth measure. The primary fix is always removal of the eval call.`,
  },
];

// ---------------------------------------------------------------------------
// Seed function
// ---------------------------------------------------------------------------

export async function seed(env: Env): Promise<{ seeded: number; ids: string[] }> {
  const inserted: string[] = [];

  for (const entry of CWE_DATA) {
    // Embed the prescriptive remediation text (768-dim via bge-base-en-v1.5)
    const vector = await hfEmbed(entry.text, env.HF_API_KEY);

    await env.VECTOR_INDEX.upsert([
      {
        id: entry.id,
        values: vector,
        metadata: {
          cwe_id: entry.cwe_id,
          name: entry.name,
          text: entry.text,
        },
      },
    ]);

    inserted.push(entry.id);
  }

  return { seeded: inserted.length, ids: inserted };
}
