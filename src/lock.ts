import { createHash } from 'node:crypto';
import { mkdirSync, readFileSync, renameSync, writeFileSync } from 'node:fs';
import { dirname, join, relative } from 'node:path';
import type { Capability, Item } from './types.ts';
import { exists, home, isDir } from './util.ts';

/**
 * Trust-on-first-use pinning. Reviewing a skill or MCP server once proves
 * nothing about the next update: plugins can add hooks, remote servers can
 * change tool descriptions, `npx -y` can fetch a new release. The lock file
 * records a content hash of everything an agent loads, so `skill-guard diff`
 * can show exactly what changed since you last looked.
 */

export interface LockEntry {
  kind: Item['kind'];
  host: Item['host'];
  name: string;
  path: string;
  /** Hash over the item's definition and every file in it. */
  hash: string;
  /** Per-file hashes (relative path → hash) so a diff can name the changed files. */
  files: Record<string, string>;
  /** For hooks and MCP servers: the command/URL as approved, for display in diffs. */
  summary?: string;
  /** What the item could do when locked (absent in locks written before 0.4). */
  capabilities?: Capability[];
}

export interface LockFile {
  version: 1;
  createdBy: string;
  updated: string;
  items: Record<string, LockEntry>;
}

const sha = (data: string | Buffer) => createHash('sha256').update(data).digest('hex').slice(0, 32);

function fileHash(file: string): string {
  try {
    return sha(readFileSync(file));
  } catch {
    return 'unreadable';
  }
}

function summary(item: Item): string | undefined {
  if (item.hook) return item.hook.command ?? item.hook.type;
  if (item.mcp) return item.mcp.url ?? [item.mcp.command ?? '', ...item.mcp.args].join(' ').trim();
  return undefined;
}

export function fingerprint(item: Item): LockEntry {
  const base = isDir(item.path) ? item.path : dirname(item.path);
  const files: Record<string, string> = {};
  for (const f of item.files) files[relative(base, f).replace(/\\/g, '/') || f] = fileHash(f);
  // The definition itself (hook command, MCP command/env/url) is part of what was approved.
  const def = JSON.stringify({ kind: item.kind, name: item.name, hook: item.hook ?? null, mcp: item.mcp ?? null, meta: item.kind === 'mcp-server' || item.kind === 'hook' ? item.meta : null });
  const hash = sha(def + JSON.stringify(Object.entries(files).sort()));
  const entry: LockEntry = { kind: item.kind, host: item.host, name: item.name, path: item.path, hash, files };
  const s = summary(item);
  if (s) entry.summary = s;
  return entry;
}

export function buildLock(items: Item[], version: string, capabilities: Record<string, Capability[]> = {}): LockFile {
  const out: LockFile = { version: 1, createdBy: `skill-guard ${version}`, updated: new Date().toISOString(), items: {} };
  for (const item of items) out.items[item.id] = { ...fingerprint(item), capabilities: capabilities[item.id] ?? [] };
  return out;
}

export function defaultLockPath(target?: string): string {
  if (target) return join(target, 'skill-guard.lock.json');
  const base = process.env.XDG_CONFIG_HOME || (process.platform === 'win32' ? process.env.APPDATA || join(home(), 'AppData', 'Roaming') : join(home(), '.config'));
  return join(base, 'skill-guard', 'lock.json');
}

export function readLock(path: string): LockFile | null {
  if (!exists(path)) return null;
  try {
    const j = JSON.parse(readFileSync(path, 'utf8')) as LockFile;
    return j && j.version === 1 && j.items ? j : null;
  } catch {
    return null;
  }
}

export function writeLock(path: string, lock: LockFile): void {
  mkdirSync(dirname(path), { recursive: true });
  const tmp = `${path}.${process.pid}.tmp`;
  writeFileSync(tmp, JSON.stringify(lock, null, 2) + '\n');
  renameSync(tmp, path);
}

export interface ItemChange {
  id: string;
  status: 'added' | 'removed' | 'changed';
  entry: LockEntry;
  /** For changed items: which files were added, removed or modified. */
  files?: { added: string[]; removed: string[]; modified: string[] };
  /** For hooks / MCP servers whose command changed: before → after. */
  before?: string;
  /** Capabilities now (added and changed items), and what was gained or lost since the lock. */
  capabilities?: { now: Capability[]; gained: Capability[]; lost: Capability[] };
}

/**
 * Attach capability information from a scan of the new and changed items. "Now also talks to
 * the network" is usually the most important line of a plugin update. Locks written before
 * capabilities were recorded only get `now`.
 */
export function annotateCapabilities(changes: ItemChange[], lock: LockFile, capabilities: Record<string, Capability[]> = {}): void {
  for (const ch of changes) {
    if (ch.status === 'removed') continue;
    const now = capabilities[ch.id] ?? [];
    const before = ch.status === 'changed' ? lock.items[ch.id]?.capabilities : undefined;
    ch.capabilities = { now, gained: before ? now.filter((c) => !before.includes(c)) : [], lost: before ? before.filter((c) => !now.includes(c)) : [] };
  }
}

export function diffLock(lock: LockFile, items: Item[]): ItemChange[] {
  const changes: ItemChange[] = [];
  const now = new Map(items.map((i) => [i.id, fingerprint(i)]));
  for (const [id, entry] of now) {
    const prev = lock.items[id];
    if (!prev) {
      changes.push({ id, status: 'added', entry });
      continue;
    }
    if (prev.hash === entry.hash) continue;
    const added = Object.keys(entry.files).filter((f) => !(f in prev.files));
    const removed = Object.keys(prev.files).filter((f) => !(f in entry.files));
    const modified = Object.keys(entry.files).filter((f) => f in prev.files && prev.files[f] !== entry.files[f]);
    const change: ItemChange = { id, status: 'changed', entry, files: { added, removed, modified } };
    if (prev.summary !== entry.summary && prev.summary !== undefined) change.before = prev.summary;
    changes.push(change);
  }
  for (const [id, entry] of Object.entries(lock.items)) if (!now.has(id)) changes.push({ id, status: 'removed', entry });
  const order = { added: 0, changed: 1, removed: 2 };
  return changes.sort((a, b) => order[a.status] - order[b.status] || a.id.localeCompare(b.id));
}
