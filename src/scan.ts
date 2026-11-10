import { basename, dirname, join, relative } from 'node:path';
import { parseFrontmatter } from './parse.ts';
import { RULE_BY_ID, isBinaryAsset, scanHook, scanMcp, scanPackageJson, scanSkillMeta, scanUnit } from './rules.ts';
import { capabilitiesOf } from './capabilities.ts';
import { toolDescriptions } from './tooldesc.ts';
import type { Capability, Finding, Item, ScanResult, Severity, TextUnit, UnitKind } from './types.ts';
import { SEVERITY_ORDER } from './types.ts';
import { exists, isCodeFile, isObject, readJson, readText, walkFiles, withFsCache } from './util.ts';

export interface Suppression {
  rule: string;
  /** Glob matched against the item id. */
  item?: string;
  /** Glob matched against the file path (forward slashes). */
  path?: string;
  reason?: string;
}

export interface ScanOptions {
  suppressions?: Suppression[];
}

const DOC_NAMES = /^(readme|license|licence|changelog|changes|history|contributing|code_of_conduct|security|notice|authors)(\.[a-z]+)?$/i;

/** How a file inside an item should be read. */
function unitKindFor(item: Item, file: string): UnitKind {
  const name = basename(file);
  if (isCodeFile(file)) return 'code';
  if (DOC_NAMES.test(name)) return 'docs';
  if (/\.(md|mdx|markdown|txt|mdc)$/i.test(name) || name === '.cursorrules') {
    // Everything markdown in a skill, command, agent or context file is something the model may read and follow.
    return item.kind === 'plugin' || item.kind === 'dsh-plugin' ? 'docs' : 'instructions';
  }
  if (/plugin\.json$|package\.json$|\.ya?ml$|\.toml$/i.test(name)) return 'metadata';
  return 'docs';
}

function unitsFor(item: Item, skipped: ScanResult['skipped']): TextUnit[] {
  const units: TextUnit[] = [];
  if (item.kind === 'hook' && item.hook?.command) units.push({ item, kind: 'command', text: item.hook.command, file: item.path });
  if (item.kind === 'mcp-server' && item.mcp) {
    const cmd = [item.mcp.command ?? '', ...item.mcp.args].join(' ').trim();
    if (cmd) units.push({ item, kind: 'command', text: cmd, file: item.path });
  }
  for (const file of item.files) {
    const r = readText(file);
    if (!('text' in r)) {
      skipped.push({ file, reason: r.skip });
      continue;
    }
    const kind = item.kind === 'hook' ? 'code' : unitKindFor(item, file);
    if (kind === 'instructions' && /\.(md|mdx|markdown|mdc)$/i.test(file)) {
      // Frontmatter description is metadata (it decides when the item loads); the body is instructions.
      const fm = parseFrontmatter(r.text);
      if (fm.bodyLine > 1) units.push({ item, file, kind: 'metadata', text: r.text.split(/\r?\n/).slice(0, fm.bodyLine - 1).join('\n'), lineOffset: 1 });
      units.push({ item, file, kind: 'instructions', text: fm.body, lineOffset: fm.bodyLine });
    } else units.push({ item, file, kind, text: r.text, lineOffset: 1 });
    // Tool descriptions in MCP server source are read by the model: scan them as instructions.
    if (kind === 'code') for (const d of toolDescriptions(r.text)) units.push({ item, file, kind: 'instructions', text: d.text, lineOffset: d.line, origin: 'tool-description' });
  }
  return units;
}

/** Item-level checks that look at structure rather than text. */
function structural(item: Item): Finding[] {
  const out: Finding[] = [];
  if (item.kind === 'mcp-server') out.push(...scanMcp(item));
  if (item.kind === 'hook') out.push(...scanHook(item));
  if (item.kind === 'skill') {
    const md = ['SKILL.md', 'skill.md', 'Skill.md'].map((n) => join(item.path, n)).find(exists) ?? join(item.path, 'SKILL.md');
    out.push(...scanSkillMeta(item, md));
  }
  // package.json lifecycle scripts (DeepSeek Harness plugins, plugin roots, skills that ship node code)
  if (item.kind === 'dsh-plugin' || item.kind === 'plugin' || item.kind === 'skill') {
    const pj = join(item.kind === 'plugin' && !exists(join(item.path, 'package.json')) ? dirname(item.path) : item.path, 'package.json');
    const pkg = exists(pj) ? readJson(pj) : undefined;
    if (isObject(pkg)) out.push(...scanPackageJson(item, pj, pkg));
  }
  // compiled binaries bundled with a skill or plugin
  if ((item.kind === 'skill' || item.kind === 'plugin') && exists(item.path)) {
    const bins = walkFiles(item.path, 5, 2000).filter(isBinaryAsset);
    if (bins.length) {
      const r = RULE_BY_ID.get('SG802')!;
      out.push({
        rule: 'SG802',
        severity: 'medium',
        title: r.title,
        message: `Ships ${bins.length} compiled file${bins.length > 1 ? 's' : ''} (${bins
          .slice(0, 3)
          .map((b) => relative(item.path, b).replace(/\\/g, '/'))
          .join(', ')}${bins.length > 3 ? ', …' : ''}).`,
        item: item.id,
        file: bins[0] as string,
      });
    }
  }
  return out;
}

// ---------------------------------------------------------------- suppressions

function globToRegExp(glob: string): RegExp {
  const re = glob
    .replace(/[.+^${}()|[\]\\]/g, '\\$&')
    .replace(/\*\*/g, '\u0000')
    .replace(/\*/g, '[^/]*')
    .replace(/\?/g, '[^/]')
    .split('\u0000')
    .join('.*');
  return new RegExp(`^${re}$`, 'i');
}

/** `skill-guard-ignore SG203` on the same or previous line, or `skill-guard-ignore-file SG203` anywhere. */
function inlineSuppressed(f: Finding, texts: Map<string, string[]>): boolean {
  if (!f.file) return false;
  let lines = texts.get(f.file);
  if (!lines) {
    const r = readText(f.file);
    lines = 'text' in r ? r.text.split(/\r?\n/) : [];
    texts.set(f.file, lines);
  }
  const mentions = (line: string | undefined, fileWide: boolean) => {
    if (!line) return false;
    const m = (fileWide ? /skill-guard-ignore-file\b([^\n]*)/ : /skill-guard-ignore(?!-file)\b([^\n]*)/).exec(line);
    if (!m) return false;
    const ids = (m[1] ?? '').match(/SG\d{3}/g);
    return !ids || ids.includes(f.rule);
  };
  if (lines.some((l) => mentions(l, true))) return true;
  if (f.line && (mentions(lines[f.line - 1], false) || mentions(lines[f.line - 2], false))) return true;
  return false;
}

function suppressed(f: Finding, rules: Suppression[]): Suppression | undefined {
  return rules.find(
    (s) =>
      (s.rule === '*' || s.rule === f.rule) &&
      (!s.item || globToRegExp(s.item).test(f.item)) &&
      (!s.path || (f.file !== undefined && globToRegExp(s.path).test(f.file.replace(/\\/g, '/')))),
  );
}

// ---------------------------------------------------------------- entry point

export function scanItems(items: Item[], opts: ScanOptions = {}): ScanResult & { suppressed: number } {
  return withFsCache(() => scanItemsUncached(items, opts));
}

function scanItemsUncached(items: Item[], opts: ScanOptions): ScanResult & { suppressed: number } {
  const findings: Finding[] = [];
  const skipped: ScanResult['skipped'] = [];
  const capabilities: Record<string, Capability[]> = {};
  // Several items can contain the same file (hooks sharing a script, a plugin and its skills):
  // run the rules once per file and kind, then attribute the findings to each item.
  const memo = new Map<string, Finding[]>();
  for (const item of items) {
    const units = unitsFor(item, skipped);
    const own: Finding[] = [];
    for (const unit of units) {
      const key = unit.file && unit.kind !== 'command' ? `${unit.kind}|${unit.origin ?? ''}|${unit.lineOffset ?? 1}|${unit.file}` : undefined;
      let found = key ? memo.get(key) : undefined;
      if (!found) {
        found = scanUnit(unit);
        if (key) memo.set(key, found);
      }
      own.push(...(found[0]?.item === item.id ? found : found.map((f) => ({ ...f, item: item.id }))));
    }
    own.push(...structural(item));
    // Capabilities describe the item, so they use findings before suppression.
    const caps = capabilitiesOf(item, units, own);
    if (caps.length) capabilities[item.id] = caps;
    findings.push(...own);
  }
  // De-duplicate: one finding per rule, item, file and line (keep the most severe).
  const best = new Map<string, Finding>();
  for (const f of findings) {
    const key = `${f.rule}|${f.item}|${f.file ?? ''}|${f.line ?? ''}`;
    const prev = best.get(key);
    if (!prev || SEVERITY_ORDER[f.severity] > SEVERITY_ORDER[prev.severity]) best.set(key, f);
  }
  const texts = new Map<string, string[]>();
  let hidden = 0;
  const kept: Finding[] = [];
  for (const f of best.values()) {
    if (inlineSuppressed(f, texts) || (opts.suppressions && suppressed(f, opts.suppressions))) hidden++;
    else kept.push(f);
  }
  kept.sort((a, b) => SEVERITY_ORDER[b.severity] - SEVERITY_ORDER[a.severity] || a.item.localeCompare(b.item) || (a.line ?? 0) - (b.line ?? 0));
  return { items, findings: kept, capabilities, skipped, suppressed: hidden };
}

/** Worst severity per item (items with no findings are absent). */
export function itemRisk(findings: Finding[]): Map<string, Severity> {
  const m = new Map<string, Severity>();
  for (const f of findings) {
    const prev = m.get(f.item);
    if (!prev || SEVERITY_ORDER[f.severity] > SEVERITY_ORDER[prev]) m.set(f.item, f.severity);
  }
  return m;
}
