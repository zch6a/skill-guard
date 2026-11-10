import { readdirSync, readFileSync, statSync } from 'node:fs';
import { homedir } from 'node:os';
import { join, sep } from 'node:path';

export function home(): string {
  return process.env.SKILL_GUARD_HOME || homedir();
}

export function exists(path: string): boolean {
  try {
    statSync(path);
    return true;
  } catch {
    return false;
  }
}

export function isDir(path: string): boolean {
  try {
    return statSync(path).isDirectory();
  } catch {
    return false;
  }
}

export function listDir(path: string): string[] {
  try {
    return readdirSync(path);
  } catch {
    return [];
  }
}

const SKIP_DIRS = new Set(['node_modules', '.git', '__pycache__', '.venv', 'venv', 'dist', 'build', '.next', '.cache']);

/** All files under `root` (depth-limited, skips dependency and VCS folders). */
export function walkFiles(root: string, maxDepth = 6, maxFiles = 5000): string[] {
  const out: string[] = [];
  const visit = (dir: string, depth: number) => {
    let entries;
    try {
      entries = readdirSync(dir, { withFileTypes: true });
    } catch {
      return;
    }
    for (const e of entries) {
      if (out.length >= maxFiles) return;
      const p = join(dir, e.name);
      if (e.isDirectory()) {
        if (depth < maxDepth && !SKIP_DIRS.has(e.name)) visit(p, depth + 1);
      } else if (e.isFile()) out.push(p);
    }
  };
  visit(root, 0);
  return out.sort();
}

/** Text extensions we scan. Binary assets (fonts, images) are not instructions or code. */
const TEXT_EXT = /\.(md|mdx|markdown|txt|json|jsonc|ya?ml|toml|ini|cfg|py|pyw|js|mjs|cjs|ts|mts|cts|jsx|tsx|sh|bash|zsh|fish|ps1|psm1|bat|cmd|rb|pl|php|go|rs|lua|r|swift|kt|java|cs|html?|xml|svg|env|csv)$/i;
const CODE_EXT = /\.(py|pyw|js|mjs|cjs|ts|mts|cts|jsx|tsx|sh|bash|zsh|fish|ps1|psm1|bat|cmd|rb|pl|php|go|rs|lua|r|swift|kt|java|cs)$/i;
const NAMED_TEXT = /^(Makefile|Dockerfile|Justfile|\.?env(\..+)?|LICENSE|README)$/i;

export function isTextFile(path: string): boolean {
  const name = path.slice(path.lastIndexOf(sep) + 1).slice(path.lastIndexOf('/') + 1);
  return TEXT_EXT.test(name) || NAMED_TEXT.test(name);
}

export function isCodeFile(path: string): boolean {
  return CODE_EXT.test(path);
}

export const MAX_FILE_BYTES = 2 * 1024 * 1024;

/** Read a text file; returns null (with a reason) for big or binary files. */
export function readText(path: string): { text: string } | { skip: string } {
  let size: number;
  try {
    size = statSync(path).size;
  } catch (e) {
    return { skip: (e as NodeJS.ErrnoException).code ?? 'unreadable' };
  }
  if (size > MAX_FILE_BYTES) return { skip: `larger than ${MAX_FILE_BYTES / 1024 / 1024} MB` };
  let buf: Buffer;
  try {
    buf = readFileSync(path);
  } catch (e) {
    return { skip: (e as NodeJS.ErrnoException).code ?? 'unreadable' };
  }
  // NUL bytes in the first 8 KB: treat as binary.
  if (buf.subarray(0, 8192).includes(0)) return { skip: 'binary' };
  let text = buf.toString('utf8');
  if (text.charCodeAt(0) === 0xfeff) text = text.slice(1);
  return { text };
}

export function readJson(path: string): unknown {
  const r = readText(path);
  if (!('text' in r)) return undefined;
  try {
    return JSON.parse(r.text);
  } catch {
    return undefined;
  }
}

export function isObject(v: unknown): v is Record<string, unknown> {
  return typeof v === 'object' && v !== null && !Array.isArray(v);
}

export function obj(v: unknown): Record<string, unknown> {
  return isObject(v) ? v : {};
}

export function str(v: unknown): string {
  return typeof v === 'string' ? v : '';
}

export function strings(v: unknown): string[] {
  return Array.isArray(v) ? v.filter((x): x is string => typeof x === 'string') : [];
}

export function stringRecord(v: unknown): Record<string, string> {
  const out: Record<string, string> = {};
  for (const [k, x] of Object.entries(obj(v))) if (typeof x === 'string' || typeof x === 'number' || typeof x === 'boolean') out[k] = String(x);
  return out;
}

/** 1-based line and column of a string index. */
export function lineCol(text: string, index: number): { line: number; column: number } {
  let line = 1;
  let last = -1;
  for (let i = 0; i < index && i < text.length; i++) {
    if (text.charCodeAt(i) === 10) {
      line++;
      last = i;
    }
  }
  return { line, column: index - last };
}

/** The full line containing `index`, trimmed to `max` characters around the match. */
export function lineAt(text: string, index: number, max = 160): string {
  const start = text.lastIndexOf('\n', index - 1) + 1;
  let end = text.indexOf('\n', index);
  if (end === -1) end = text.length;
  let line = text.slice(start, end).replace(/\r$/, '');
  const col = index - start;
  if (line.length > max) {
    const from = Math.max(0, Math.min(col - Math.floor(max / 3), line.length - max));
    line = (from > 0 ? '…' : '') + line.slice(from, from + max) + (from + max < line.length ? '…' : '');
  }
  return line.trim();
}

/** Replace the home directory with `~` for display. */
export function tildify(p: string): string {
  const h = homedir();
  if (!p || !h) return p;
  const a = process.platform === 'win32' ? p.toLowerCase() : p;
  const b = process.platform === 'win32' ? h.toLowerCase() : h;
  if (a === b) return '~';
  if (a.startsWith(b + sep) || a.startsWith(b + '/')) return '~' + p.slice(h.length).replace(/\\/g, '/');
  return p;
}

/** Mask anything that looks like a credential before it is printed. */
export function maskSecrets(text: string): string {
  return text
    .replace(/\b(sk-(?:ant-|proj-)?[A-Za-z0-9_-]{6})[A-Za-z0-9_-]{10,}/g, '$1…')
    .replace(/\b(gh[pousr]_[A-Za-z0-9]{4})[A-Za-z0-9]{20,}/g, '$1…')
    .replace(/\b(github_pat_[A-Za-z0-9]{4})[A-Za-z0-9_]{20,}/g, '$1…')
    .replace(/\b((?:AKIA|ASIA)[A-Z0-9]{4})[A-Z0-9]{12}\b/g, '$1…')
    .replace(/\b(AIza[0-9A-Za-z_-]{4})[0-9A-Za-z_-]{20,}/g, '$1…')
    .replace(/\b(xox[abposr]-[A-Za-z0-9]{4})[A-Za-z0-9-]{8,}/g, '$1…')
    .replace(/\b(eyJ[A-Za-z0-9_-]{6})[A-Za-z0-9_-]*\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+/g, '$1…')
    .replace(/(Bearer\s+[A-Za-z0-9._~+/=-]{4})[A-Za-z0-9._~+/=-]{8,}/g, '$1…');
}
