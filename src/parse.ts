/**
 * Minimal parsers for the config formats agents use, so the scanner has zero
 * dependencies. They handle what real configs contain and fail soft: an
 * unparseable file yields `undefined`, never an exception.
 */

// ---------------------------------------------------------------- frontmatter

export interface Frontmatter {
  data: Record<string, unknown>;
  body: string;
  /** Line number where the body starts (1-based). */
  bodyLine: number;
}

function scalar(raw: string): unknown {
  const v = raw.trim();
  if (v === '') return '';
  if ((v.startsWith('"') && v.endsWith('"')) || (v.startsWith("'") && v.endsWith("'"))) {
    const inner = v.slice(1, -1);
    return v.startsWith('"') ? inner.replace(/\\"/g, '"').replace(/\\n/g, '\n') : inner.replace(/''/g, "'");
  }
  if (v.startsWith('[') && v.endsWith(']')) {
    return v
      .slice(1, -1)
      .split(',')
      .map((x) => scalar(x))
      .filter((x) => x !== '');
  }
  if (v === 'true' || v === 'false') return v === 'true';
  if (v === 'null' || v === '~') return null;
  if (/^-?\d+(\.\d+)?$/.test(v)) return Number(v);
  return v.replace(/\s+#.*$/, '');
}

/** YAML frontmatter between `---` lines: scalars, quoted strings, `|`/`>` blocks, simple lists and one level of nesting. */
export function parseFrontmatter(text: string): Frontmatter {
  const m = /^---[ \t]*\r?\n([\s\S]*?)\r?\n---[ \t]*(\r?\n|$)/.exec(text);
  if (!m) return { data: {}, body: text, bodyLine: 1 };
  const yaml = m[1] ?? '';
  const data: Record<string, unknown> = {};
  const lines = yaml.split(/\r?\n/);
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i] ?? '';
    const kv = /^([A-Za-z0-9_-]+):(.*)$/.exec(line);
    if (!kv) continue;
    const key = kv[1] as string;
    const rest = (kv[2] ?? '').trim();
    if (rest === '|' || rest === '>' || rest === '|-' || rest === '>-') {
      const block: string[] = [];
      while (i + 1 < lines.length && (/^\s+/.test(lines[i + 1] ?? '') || (lines[i + 1] ?? '') === '')) block.push((lines[++i] ?? '').replace(/^\s{1,4}/, ''));
      data[key] = rest.startsWith('>') ? block.join(' ').replace(/\s+/g, ' ').trim() : block.join('\n').trimEnd();
    } else if (rest === '') {
      // nested map or list
      const list: unknown[] = [];
      const map: Record<string, unknown> = {};
      while (i + 1 < lines.length && /^\s+\S/.test(lines[i + 1] ?? '')) {
        const sub = (lines[++i] ?? '').trim();
        const li = /^-\s*(.*)$/.exec(sub);
        if (li) list.push(scalar(li[1] ?? ''));
        else {
          const skv = /^([A-Za-z0-9_-]+):(.*)$/.exec(sub);
          if (skv) map[skv[1] as string] = scalar(skv[2] ?? '');
        }
      }
      data[key] = list.length ? list : map;
    } else data[key] = scalar(rest);
  }
  const body = text.slice(m[0].length);
  const bodyLine = (text.slice(0, m[0].length).match(/\n/g) ?? []).length + 1;
  return { data, body, bodyLine };
}

// ---------------------------------------------------------------- JSONC

/** JSON with comments and trailing commas (OpenCode, VS Code, Cursor). */
export function parseJsonc(text: string): unknown {
  let out = '';
  let i = 0;
  let inStr = false;
  while (i < text.length) {
    const ch = text[i] as string;
    const next = text[i + 1];
    if (inStr) {
      out += ch;
      if (ch === '\\') {
        out += next ?? '';
        i += 2;
        continue;
      }
      if (ch === '"') inStr = false;
      i++;
      continue;
    }
    if (ch === '"') {
      inStr = true;
      out += ch;
      i++;
    } else if (ch === '/' && next === '/') {
      while (i < text.length && text[i] !== '\n') i++;
    } else if (ch === '/' && next === '*') {
      i += 2;
      while (i < text.length && !(text[i] === '*' && text[i + 1] === '/')) i++;
      i += 2;
    } else {
      out += ch;
      i++;
    }
  }
  try {
    return JSON.parse(out.replace(/,(\s*[}\]])/g, '$1'));
  } catch {
    return undefined;
  }
}

// ---------------------------------------------------------------- TOML

/**
 * Enough TOML for agent configs (Codex `config.toml`): tables, dotted and
 * quoted keys, strings (basic, literal, multi-line), numbers, booleans,
 * arrays and inline tables. Arrays of tables (`[[x]]`) are collected as lists.
 */
export function parseToml(text: string): Record<string, unknown> | undefined {
  const root: Record<string, unknown> = {};
  let table = root;
  let i = 0;
  const err = () => {
    throw new Error('toml');
  };
  const ws = () => {
    while (i < text.length && (text[i] === ' ' || text[i] === '\t')) i++;
  };
  const skipLine = () => {
    while (i < text.length && text[i] !== '\n') i++;
    i++;
  };
  const key = (): string[] => {
    const parts: string[] = [];
    for (;;) {
      ws();
      if (text[i] === '"' || text[i] === "'") parts.push(String(value()));
      else {
        const m = /^[A-Za-z0-9_-]+/.exec(text.slice(i));
        if (!m) err();
        parts.push(m![0]);
        i += m![0].length;
      }
      ws();
      if (text[i] === '.') {
        i++;
        continue;
      }
      return parts;
    }
  };
  const descend = (base: Record<string, unknown>, path: string[], arrayLast = false) => {
    let cur = base;
    path.forEach((p, idx) => {
      const last = idx === path.length - 1;
      if (last && arrayLast) {
        const list = (Array.isArray(cur[p]) ? cur[p] : (cur[p] = [])) as Record<string, unknown>[];
        const t: Record<string, unknown> = {};
        list.push(t);
        cur = t;
        return;
      }
      const existing = cur[p];
      if (Array.isArray(existing)) cur = (existing[existing.length - 1] as Record<string, unknown>) ?? {};
      else if (existing && typeof existing === 'object') cur = existing as Record<string, unknown>;
      else cur = cur[p] = {} as Record<string, unknown>;
    });
    return cur;
  };
  const value = (): unknown => {
    ws();
    const s = text.slice(i);
    if (s.startsWith('"""') || s.startsWith("'''")) {
      const q = s.slice(0, 3);
      const end = text.indexOf(q, i + 3);
      if (end === -1) err();
      let v = text.slice(i + 3, end).replace(/^\r?\n/, '');
      i = end + 3;
      if (q === '"""') v = unescape(v.replace(/\\\r?\n\s*/g, ''));
      return v;
    }
    if (s[0] === '"') {
      let j = i + 1;
      let v = '';
      while (j < text.length && text[j] !== '"' && text[j] !== '\n') {
        if (text[j] === '\\') {
          v += text.slice(j, j + 2);
          j += 2;
        } else v += text[j++];
      }
      if (text[j] !== '"') err(); // unterminated string
      i = j + 1;
      return unescape(v);
    }
    if (s[0] === "'") {
      const end = text.indexOf("'", i + 1);
      if (end === -1 || text.slice(i + 1, end).includes('\n')) err();
      const v = text.slice(i + 1, end);
      i = end + 1;
      return v;
    }
    if (s[0] === '[') {
      i++;
      const list: unknown[] = [];
      for (;;) {
        while (i < text.length && /[\s,]/.test(text[i] as string)) i++;
        if (text[i] === '#') {
          skipLine();
          continue;
        }
        if (text[i] === ']') {
          i++;
          return list;
        }
        list.push(value());
      }
    }
    if (s[0] === '{') {
      i++;
      const t: Record<string, unknown> = {};
      for (;;) {
        while (i < text.length && /[\s,]/.test(text[i] as string)) i++;
        if (text[i] === '}') {
          i++;
          return t;
        }
        const k = key();
        ws();
        if (text[i] !== '=') err();
        i++;
        const parent = descend(t, k.slice(0, -1));
        parent[k[k.length - 1] as string] = value();
      }
    }
    const m = /^[^\s,\]}#]+/.exec(s);
    if (!m) err();
    i += m![0].length;
    const raw = m![0];
    if (raw === 'true' || raw === 'false') return raw === 'true';
    const n = Number(raw.replace(/_/g, ''));
    return Number.isNaN(n) ? raw : n;
  };
  try {
    while (i < text.length) {
      ws();
      const ch = text[i];
      if (ch === '\n' || ch === '\r') {
        i++;
        continue;
      }
      if (ch === '#') {
        skipLine();
        continue;
      }
      if (ch === '[') {
        const isArray = text[i + 1] === '[';
        i += isArray ? 2 : 1;
        const path = key();
        if (text.slice(i, i + (isArray ? 2 : 1)) !== (isArray ? ']]' : ']')) err(); // unclosed header
        i += isArray ? 2 : 1;
        table = descend(root, path, isArray);
        skipLine();
        continue;
      }
      const k = key();
      ws();
      if (text[i] !== '=') err();
      i++;
      const parent = descend(table, k.slice(0, -1));
      parent[k[k.length - 1] as string] = value();
      ws();
      if (text[i] === '#') skipLine();
    }
  } catch {
    return undefined;
  }
  return root;
}

function unescape(s: string): string {
  return s.replace(/\\(u[0-9a-fA-F]{4}|U[0-9a-fA-F]{8}|.)/g, (_, e: string) => {
    if (e[0] === 'u' || e[0] === 'U') return String.fromCodePoint(parseInt(e.slice(1), 16));
    return ({ n: '\n', t: '\t', r: '\r', '"': '"', '\\': '\\', b: '\b', f: '\f' } as Record<string, string>)[e] ?? e;
  });
}
