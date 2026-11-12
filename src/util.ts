import { createHash } from 'node:crypto';
import { readdirSync, readFileSync, realpathSync, statSync, type Dirent, type Stats } from 'node:fs';
import { readFile as readFileAsync, stat as statAsync } from 'node:fs/promises';
import { homedir } from 'node:os';
import { isAbsolute, join, relative, sep } from 'node:path';

export function home(): string {
  return process.env.SKILL_GUARD_HOME || homedir();
}

// ---------------------------------------------------------------- scoped filesystem cache
//
// A scan touches the same files many times (a plugin and each of its skills walk the same
// folders; several hooks run the same script). On Windows every open is slow, so within one
// scan, stat/readdir/read results are cached. The cache lives only for the duration of
// withFsCache(): files can change between scans (and do, in tests).

interface FsCache {
  stat: Map<string, Stats | null>;
  dirs: Map<string, Dirent[] | null>;
  texts: Map<string, { text: string } | { skip: string }>;
  /** Content digests of files already read for scanning, so `lock` need not read them again. */
  digests: Map<string, string>;
}
let fsCache: FsCache | null = null;

/** Run `fn` with filesystem results cached; nested calls share the outer cache. */
export function withFsCache<T>(fn: () => T): T {
  if (fsCache) return fn();
  fsCache = { stat: new Map(), dirs: new Map(), texts: new Map(), digests: new Map() };
  try {
    return fn();
  } finally {
    fsCache = null;
  }
}

function stat(path: string): Stats | null {
  const hit = fsCache?.stat.get(path);
  if (hit !== undefined) return hit;
  let st: Stats | null = null;
  try {
    st = statSync(path);
  } catch {
    // missing or unreadable
  }
  fsCache?.stat.set(path, st);
  return st;
}

function entries(dir: string): Dirent[] | null {
  const hit = fsCache?.dirs.get(dir);
  if (hit !== undefined) return hit;
  let list: Dirent[] | null = null;
  try {
    list = readdirSync(dir, { withFileTypes: true });
  } catch {
    // missing or unreadable
  }
  fsCache?.dirs.set(dir, list);
  return list;
}

export function exists(path: string): boolean {
  return stat(path) !== null;
}

export function isDir(path: string): boolean {
  return stat(path)?.isDirectory() ?? false;
}

/** A regular file: not a folder, and not a device, FIFO or socket (`/dev/stdin` would block a read forever). */
export function isFile(path: string): boolean {
  return stat(path)?.isFile() ?? false;
}

export function listDir(path: string): string[] {
  return (entries(path) ?? []).map((e) => e.name);
}

/** Dependencies and VCS data: never what an agent loads. */
const SKIP_ALWAYS = new Set(['node_modules', '.git', '__pycache__', '.venv', 'venv']);
/** Build output: skipped when searching a repository for items, but scanned inside an item (a skill's dist/ is its code). */
const SKIP_IN_REPO = new Set(['dist', 'build', 'out', '.next', '.cache', 'target', 'coverage']);
/** Under these, a folder name is an item name (a skill called "build"), never build output. */
const ITEM_PARENTS = new Set(['skills', 'commands', 'agents', 'plugins', 'skill', 'command', 'agent', 'plugin']);

export interface WalkOptions {
  maxDepth?: number;
  /** Cap on *kept* files (after `filter`), so a folder of 400 images cannot push SKILL.md out. */
  maxFiles?: number;
  /** `item`: everything inside one skill/plugin except dependencies and VCS data. `repo`: also skips build output. */
  mode?: 'item' | 'repo';
  filter?: (path: string) => boolean;
  /** Called for a symbolic link that points outside `root` (not followed: it could pull in ~/.ssh). */
  onOutsideLink?: (link: string, target: string) => void;
}

/** Walks that hit their file cap during this command (reported, never silent). */
const truncatedWalks = new Set<string>();
export function takeTruncatedWalks(): string[] {
  const out = [...truncatedWalks];
  truncatedWalks.clear();
  return out;
}

/**
 * Files under `root`, depth-limited. In `repo` mode build output is skipped except where the
 * folder name is an item name — otherwise a skill named "build" would be invisible. Symbolic
 * links are followed only while they stay inside `root`.
 */
export function walkFiles(root: string, maxDepthOrOpts: number | WalkOptions = 6, maxFiles = 5000, mode: 'item' | 'repo' = 'item'): string[] {
  const o: WalkOptions = typeof maxDepthOrOpts === 'number' ? { maxDepth: maxDepthOrOpts, maxFiles, mode } : maxDepthOrOpts;
  const maxDepth = o.maxDepth ?? 6;
  const cap = o.maxFiles ?? 5000;
  const out: string[] = [];
  let rootReal = '';
  try {
    rootReal = realpathSync(root);
  } catch {
    return out;
  }
  const inside = (p: string) => {
    const rel = relative(rootReal, p);
    return rel === '' || (!rel.startsWith('..') && !isAbsolute(rel));
  };
  // Each real folder once: a folder linked inside the root and walked through its real path too is not scanned
  // twice, and a link back up the tree cannot loop.
  const seen = new Set<string>();
  const visit = (dir: string, depth: number) => {
    let real = dir;
    try {
      real = realpathSync(dir);
    } catch {
      return;
    }
    if (seen.has(real)) return;
    seen.add(real);
    const list = entries(dir);
    if (!list) return;
    const parent = baseName(dir).toLowerCase();
    for (const e of list) {
      if (out.length >= cap) {
        truncatedWalks.add(root);
        return;
      }
      const p = join(dir, e.name);
      let isDirEntry = e.isDirectory();
      let isFileEntry = e.isFile();
      if (e.isSymbolicLink()) {
        let target = '';
        try {
          target = realpathSync(p);
        } catch {
          continue; // dangling
        }
        if (!inside(target)) {
          o.onOutsideLink?.(p, target);
          continue;
        }
        const st = stat(target);
        // A linked folder inside the root (Codex keeps a `latest` junction next to the version it points at) is
        // walked once, through whichever path comes first; its target may be in a folder the walk skips
        // (`scripts` -> `node_modules/.cache/x`), so it must be followed, not assumed walked already.
        if (st?.isDirectory()) {
          if (depth < maxDepth) visit(p, depth + 1);
          continue;
        }
        // A linked file inside the root may point into a skipped folder (node_modules/): keep its target.
        if (st?.isFile() && (!o.filter || o.filter(target))) out.push(target);
        continue;
      }
      if (isDirEntry) {
        const skip = SKIP_ALWAYS.has(e.name) || (o.mode === 'repo' && SKIP_IN_REPO.has(e.name) && !ITEM_PARENTS.has(parent));
        if (depth < maxDepth && !skip) visit(p, depth + 1);
      } else if (isFileEntry && (!o.filter || o.filter(p))) out.push(p);
    }
  };
  visit(root, 0);
  return [...new Set(out)].sort();
}

/** An extensionless file that starts with `#!` is a script. */
export function hasShebang(path: string): boolean {
  if (/\.[A-Za-z0-9]{1,6}$/.test(baseName(path))) return false;
  const r = readText(path);
  return 'text' in r && r.text.startsWith('#!');
}

/** Text extensions we scan. Binary assets (fonts, images) are not instructions or code. */
// Documentation formats an agent reads as easily as Markdown (reStructuredText, AsciiDoc, Org, Cursor rules), notebooks,
// and Windows script hosts: a skill can tell the agent to read or run any of them.
const TEXT_EXT = /\.(md|mdx|mdc|markdown|rst|adoc|asciidoc|org|tex|txt|json|jsonc|ipynb|ya?ml|toml|ini|cfg|conf|properties|py|pyw|pyi|js|mjs|cjs|ts|mts|cts|jsx|tsx|sh|bash|zsh|fish|ps1|psm1|psd1|bat|cmd|vbs|vbe|wsf|rb|pl|php|go|rs|lua|r|swift|kt|java|cs|html?|xml|svg|env|csv)$/i;
const CODE_EXT = /\.(py|pyw|js|mjs|cjs|ts|mts|cts|jsx|tsx|sh|bash|zsh|fish|ps1|psm1|bat|cmd|vbs|vbe|wsf|rb|pl|php|go|rs|lua|r|swift|kt|java|cs)$/i;
const NAMED_TEXT = /^(Makefile|Dockerfile|Justfile|\.?env(\..+)?|LICENSE|README)$/i;

/** The last path segment, whatever the separator (a Windows path on Linux, a POSIX path on Windows). */
export function baseName(path: string): string {
  return path.slice(Math.max(path.lastIndexOf('/'), path.lastIndexOf('\\')) + 1);
}

export function isTextFile(path: string): boolean {
  const name = baseName(path);
  return TEXT_EXT.test(name) || NAMED_TEXT.test(name);
}

export function isCodeFile(path: string): boolean {
  return CODE_EXT.test(path);
}

export const MAX_FILE_BYTES = 2 * 1024 * 1024;

/** Read a text file; returns null (with a reason) for big or binary files. */
export function readText(path: string): { text: string } | { skip: string } {
  const hit = fsCache?.texts.get(path);
  if (hit) return hit;
  const r = readTextUncached(path);
  fsCache?.texts.set(path, r);
  return r;
}

function readTextUncached(path: string): { text: string } | { skip: string } {
  let size: number;
  try {
    const st = statSync(path);
    // A device or FIFO reports size 0 and never ends (`/dev/zero`) or never answers (`/dev/stdin`).
    if (!st.isFile()) return { skip: 'not a regular file' };
    size = st.size;
  } catch (e) {
    return { skip: (e as NodeJS.ErrnoException).code ?? 'unreadable' };
  }
  if (size > MAX_FILE_BYTES) return { skip: `larger than ${MAX_FILE_BYTES / 1024 / 1024} MB` };
  try {
    const buf = readFileSync(path);
    fsCache?.digests.set(path, digest(buf));
    return decodeText(buf, path);
  } catch (e) {
    return { skip: (e as NodeJS.ErrnoException).code ?? 'unreadable' };
  }
}

/** Text and code files up to this size are scanned whole (in parts); larger ones only at their ends. */
export const MAX_WHOLE_BYTES = 16 * 1024 * 1024;
/** Larger than this: not read at all. */
export const MAX_ANY_BYTES = 64 * 1024 * 1024;

/**
 * A text/code file over MAX_FILE_BYTES, in parts of about a megabyte that start on a line (with the line each
 * starts on), so nothing in the middle is skipped: a payload padded into the middle of a big file was missed when
 * only the first and last megabyte were read. Over MAX_WHOLE_BYTES: only the first and last megabyte (`whole`
 * false); over MAX_ANY_BYTES: nothing.
 */
export function readParts(path: string): { parts: { text: string; line: number }[]; whole: boolean } {
  if (!isTextFile(path) && !isCodeFile(path)) return { parts: [], whole: false };
  let buf: Buffer;
  try {
    if ((stat(path)?.size ?? 0) > MAX_ANY_BYTES) return { parts: [], whole: false };
    buf = readFileSync(path);
  } catch {
    return { parts: [], whole: false };
  }
  const part = 1024 * 1024;
  const lineAt = (end: number) => {
    let line = 1;
    for (let i = 0; i < end; i++) if (buf[i] === 10) line++;
    return line;
  };
  if (buf.length > MAX_WHOLE_BYTES) {
    const tailStart = buf.length - part;
    return { parts: [{ text: buf.subarray(0, part).toString('utf8'), line: 1 }, { text: buf.subarray(tailStart).toString('utf8'), line: lineAt(tailStart) }], whole: false };
  }
  const parts: { text: string; line: number }[] = [];
  let start = 0;
  let line = 1;
  while (start < buf.length) {
    let end = Math.min(buf.length, start + part);
    // End on a newline when there is one in the last 64 KB, so a line is not cut in two; a single giant line is cut.
    if (end < buf.length) {
      const nl = buf.lastIndexOf(10, end - 1);
      if (nl > end - 64 * 1024 && nl > start) end = nl + 1;
    }
    parts.push({ text: buf.subarray(start, end).toString('utf8'), line });
    for (let i = start; i < end; i++) if (buf[i] === 10) line++;
    start = end;
  }
  return { parts, whole: true };
}

/** Content hash used by lock files (sha256, first 32 hex chars). Changing it would invalidate every lock. */
export function digest(data: string | Buffer): string {
  return createHash('sha256').update(data).digest('hex').slice(0, 32);
}

/** The digest of a file's bytes, reusing the read done for scanning when there was one. */
export function fileDigest(path: string): string {
  const hit = fsCache?.digests.get(path);
  if (hit) return hit;
  try {
    const d = digest(readFileSync(path));
    fsCache?.digests.set(path, d);
    return d;
  } catch {
    return 'unreadable';
  }
}

function decodeText(buf: Buffer, path: string): { text: string } | { skip: string } {
  // UTF-16 with a BOM (PowerShell scripts saved by Windows tools): decode, do not call it binary.
  if (buf[0] === 0xff && buf[1] === 0xfe) return { text: buf.subarray(2).toString('utf16le') };
  if (buf[0] === 0xfe && buf[1] === 0xff) return { text: Buffer.from(buf.subarray(2)).swap16().toString('utf16le') };
  // NUL bytes mean binary — unless the extension says text or code, where a planted NUL must not hide the file.
  if (buf.subarray(0, 8192).includes(0) && !isTextFile(path)) return { skip: 'binary' };
  let text = buf.toString('utf8');
  if (text.charCodeAt(0) === 0xfeff) text = text.slice(1);
  // Old Mac line endings (a bare CR): read as newlines, same length, so lines are counted and frontmatter parsed.
  if (text.includes('\r')) text = text.replace(/\r(?!\n)/g, '\n');
  return { text };
}

/** Like withFsCache, for async work (see prefetch). */
export async function withFsCacheAsync<T>(fn: () => Promise<T>): Promise<T> {
  if (fsCache) return fn();
  fsCache = { stat: new Map(), dirs: new Map(), texts: new Map(), digests: new Map() };
  try {
    return await fn();
  } finally {
    fsCache = null;
  }
}

/**
 * Read files into the active cache in parallel. Synchronous reads wait for each open in turn
 * (slow on Windows with real-time scanning); overlapping them is ~4× faster on a full machine.
 * Results are identical to readText(); outside a cache scope this does nothing.
 */
export async function prefetch(paths: string[], concurrency = 16): Promise<void> {
  const cache = fsCache;
  if (!cache) return;
  const todo = [...new Set(paths)].filter((p) => !cache.texts.has(p));
  let next = 0;
  const worker = async () => {
    while (next < todo.length) {
      const p = todo[next++] as string;
      let r: { text: string } | { skip: string };
      try {
        const st = await statAsync(p);
        if (st.size > MAX_FILE_BYTES) r = { skip: `larger than ${MAX_FILE_BYTES / 1024 / 1024} MB` };
        else {
          const buf = await readFileAsync(p);
          cache.digests.set(p, digest(buf));
          r = decodeText(buf, p);
        }
      } catch (e) {
        r = { skip: (e as NodeJS.ErrnoException).code ?? 'unreadable' };
      }
      cache.texts.set(p, r);
    }
  };
  await Promise.all(Array.from({ length: Math.min(concurrency, todo.length) }, worker));
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
export function tildify(raw: string): string {
  // File names are untrusted too (a name can contain an escape sequence on Linux).
  const p = visible(raw);
  const h = home();
  if (!p || !h) return p;
  const a = process.platform === 'win32' ? p.toLowerCase() : p;
  const b = process.platform === 'win32' ? h.toLowerCase() : h;
  if (a === b) return '~';
  if (a.startsWith(b + sep) || a.startsWith(b + '/')) return '~' + p.slice(h.length).replace(/\\/g, '/');
  return p;
}

/**
 * Control characters from scanned files, made visible (\x1b, \x07, …). Raw, they reach the
 * terminal — an ESC sequence in a skill could erase or rewrite lines of the report about it.
 */
export function visible(text: string): string {
  return text
    .replace(/[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f\u2028\u2029]/g, (ch) => '\\x' + ch.charCodeAt(0).toString(16).padStart(2, '0'))
    // Bidirectional controls reorder what the terminal shows: a file "scripts/<U+202E>hs.txt" displays as "txt.sh".
    .replace(/[\u061c\u200e\u200f\u202a-\u202e\u2066-\u2069]/g, (ch) => `<U+${ch.charCodeAt(0).toString(16).toUpperCase().padStart(4, '0')}>`);
}

/** Mask anything that looks like a credential before it is printed (and neutralise control characters). */
export function maskSecrets(text: string): string {
  return visible(text)
    .replace(/\b(sk-(?:ant-|proj-)?[A-Za-z0-9_-]{6})[A-Za-z0-9_-]{10,}/g, '$1…')
    .replace(/\b(gh[pousr]_[A-Za-z0-9]{4})[A-Za-z0-9]{20,}/g, '$1…')
    .replace(/\b(github_pat_[A-Za-z0-9]{4})[A-Za-z0-9_]{20,}/g, '$1…')
    .replace(/\b((?:AKIA|ASIA)[A-Z0-9]{4})[A-Z0-9]{12}\b/g, '$1…')
    .replace(/\b(AIza[0-9A-Za-z_-]{4})[0-9A-Za-z_-]{20,}/g, '$1…')
    .replace(/\b(xox[abposr]-[A-Za-z0-9]{4})[A-Za-z0-9-]{8,}/g, '$1…')
    .replace(/\b(eyJ[A-Za-z0-9_-]{6})[A-Za-z0-9_-]*\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+/g, '$1…')
    .replace(/(Bearer\s+[A-Za-z0-9._~+/=-]{4})[A-Za-z0-9._~+/=-]{8,}/g, '$1…');
}
