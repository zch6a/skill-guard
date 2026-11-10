import { basename, dirname, relative } from 'node:path';
import { pathToFileURL } from 'node:url';
import { c, fit, pad, plural, width } from './format.ts';
import type { ItemChange } from './lock.ts';
import { RULE_BY_ID, RULES } from './rules.ts';
import { itemRisk } from './scan.ts';
import { HOST_LABELS, SEVERITY_ORDER, atLeast, type Finding, type Item, type ScanResult, type Severity } from './types.ts';
import { tildify } from './util.ts';
import { VERSION } from './version.ts';

const SEV_LABEL: Record<Severity, string> = { critical: 'CRITICAL', high: 'HIGH', medium: 'MEDIUM', low: 'LOW', info: 'INFO' };
const SEV_ICON: Record<Severity, string> = { critical: '✖', high: '▲', medium: '●', low: '·', info: '·' };

export function sevColor(s: Severity): (x: string) => string {
  return s === 'critical' ? (x) => c.bold(c.red(x)) : s === 'high' ? c.red : s === 'medium' ? c.yellow : s === 'low' ? c.cyan : c.gray;
}

const KIND_LABEL: Record<Item['kind'], string> = {
  skill: 'skill',
  plugin: 'plugin',
  command: 'command',
  subagent: 'agent',
  hook: 'hook',
  'mcp-server': 'MCP server',
  context: 'context file',
  'dsh-plugin': 'DSH plugin',
};

export function inventoryLine(items: Item[]): string {
  const count = (k: Item['kind']) => items.filter((i) => i.kind === k).length;
  const parts = [
    [count('skill'), 'skill'],
    [count('plugin') + count('dsh-plugin'), 'plugin'],
    [count('command') + count('subagent'), 'command/agent', 'commands/agents'],
    [count('hook'), 'hook'],
    [count('mcp-server'), 'MCP server'],
    [count('context'), 'context file'],
  ] as [number, string, string?][];
  return parts
    .filter(([n]) => n > 0)
    .map(([n, w, many]) => plural(n, w, many))
    .join(', ');
}

function counts(findings: Finding[]): Record<Severity, number> {
  const out: Record<Severity, number> = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const f of findings) out[f.severity]++;
  return out;
}

function shortFile(item: Item, file?: string): string {
  if (!file) return '';
  if (file === item.path) return basename(file);
  // Hooks and MCP servers live in a config file; show their scripts relative to that file's folder.
  const base = /\.(json|toml|jsonc|md)$/i.test(item.path) || item.path.includes(' (') ? dirname(item.path.replace(/ \(.*\)$/, '')) : item.path;
  const rel = relative(base, file).replace(/\\/g, '/');
  return rel && !rel.startsWith('../..') ? rel : tildify(file);
}

export interface TerminalOptions {
  min: Severity;
  verbose: boolean;
  elapsedMs: number;
  suppressed: number;
  title?: string;
}

export function renderTerminal(result: ScanResult, opts: TerminalOptions): string {
  const out: string[] = [];
  const { items, findings } = result;
  const shown = findings.filter((f) => atLeast(f.severity, opts.min));
  const byItem = new Map<string, Finding[]>();
  for (const f of shown) {
    if (!byItem.has(f.item)) byItem.set(f.item, []);
    byItem.get(f.item)!.push(f);
  }
  const itemsById = new Map(items.map((i) => [i.id, i]));
  const risk = itemRisk(shown);
  out.push(`${c.bold('skill-guard')} ${c.dim(VERSION)} ${c.dim('·')} ${opts.title ?? 'scanned'} ${plural(items.length, 'item')} ${c.dim(`(${inventoryLine(items) || 'nothing installed'}) in ${(opts.elapsedMs / 1000).toFixed(1)}s`)}`);
  out.push('');
  const ordered = [...byItem.keys()].sort((a, b) => SEVERITY_ORDER[risk.get(b)!] - SEVERITY_ORDER[risk.get(a)!] || a.localeCompare(b));
  const cols = process.stdout.columns || 110;
  for (const id of ordered) {
    const item = itemsById.get(id);
    if (!item) continue;
    const sev = risk.get(id)!;
    const head = `${sevColor(sev)(`${SEV_ICON[sev]} ${SEV_LABEL[sev]}`)}  ${c.dim(HOST_LABELS[item.host])} ${KIND_LABEL[item.kind]}  ${c.bold(fit(item.name, 60))}`;
    out.push(`${head}  ${c.dim(fit(tildify(item.path), Math.max(20, cols - width(head) - 4)))}`);
    const list = byItem.get(id)!.sort((a, b) => SEVERITY_ORDER[b.severity] - SEVERITY_ORDER[a.severity]);
    const limit = opts.verbose ? Infinity : 4;
    for (const f of list.slice(0, limit)) {
      out.push(`   ${sevColor(f.severity)(pad(f.rule, 6))} ${c.bold(f.title)} ${c.dim('—')} ${f.message}`);
      const where = f.file ? `${shortFile(item, f.file)}${f.line ? `:${f.line}` : ''}` : '';
      if (where || f.evidence) out.push(`          ${c.dim(where)}${where && f.evidence ? '  ' : ''}${f.evidence ? fit(f.evidence, Math.max(30, cols - 14 - width(where))) : ''}`);
    }
    if (list.length > limit) out.push(c.dim(`          … ${list.length - limit} more (--verbose)`));
    out.push('');
  }
  const n = counts(findings);
  const hiddenLow = findings.filter((f) => !atLeast(f.severity, opts.min)).length;
  const summary = (['critical', 'high', 'medium', 'low', 'info'] as Severity[])
    .filter((s) => n[s])
    .map((s) => sevColor(s)(`${n[s]} ${s}`))
    .join(c.dim(' · '));
  if (!shown.length) out.push(`${c.green('✓')} ${c.bold(`No ${opts.min === 'info' ? '' : opts.min + '+ '}findings.`)}${hiddenLow ? c.dim(` (${plural(hiddenLow, 'lower-severity finding')} hidden; --min low to see)`) : ''}`);
  else {
    out.push(`${c.bold('Findings:')} ${summary}${hiddenLow ? c.dim(`  (${hiddenLow} below ${opts.min} hidden; --min low to see)`) : ''}${opts.suppressed ? c.dim(` · ${opts.suppressed} suppressed`) : ''}`);
    const top = shown[0]!;
    out.push(c.dim(`Run \`skill-guard explain ${top.rule}\` for why a rule matters and how to fix it.`));
  }
  if (result.skipped.length && opts.verbose) out.push(c.dim(`Skipped ${plural(result.skipped.length, 'file')}: ${result.skipped.slice(0, 5).map((s) => `${tildify(s.file)} (${s.reason})`).join(', ')}`));
  return out.join('\n');
}

export function renderInventory(result: ScanResult): string {
  const risk = itemRisk(result.findings.filter((f) => atLeast(f.severity, 'medium')));
  const rows = [...result.items].sort((a, b) => a.host.localeCompare(b.host) || a.kind.localeCompare(b.kind) || a.name.localeCompare(b.name));
  const out: string[] = [`${c.bold(plural(rows.length, 'item'))} ${c.dim(`(${inventoryLine(rows)})`)}`, ''];
  let lastHost = '';
  for (const i of rows) {
    if (i.host !== lastHost) {
      out.push(c.bold(HOST_LABELS[i.host]));
      lastHost = i.host;
    }
    const r = risk.get(i.id);
    const flag = r ? sevColor(r)(SEV_LABEL[r]) : c.green('ok');
    const detail = i.hook ? c.dim(fit(i.hook.command ?? '', 60)) : i.mcp ? c.dim(fit(i.mcp.url ?? [i.mcp.command ?? '', ...i.mcp.args].join(' '), 60)) : c.dim(fit(i.description ?? '', 60));
    out.push(`  ${pad(flag, 9)} ${pad(KIND_LABEL[i.kind], 12)} ${pad(fit(i.name, 44), 44)} ${detail}`);
  }
  return out.join('\n');
}

export function renderExplain(id: string): string | null {
  const r = RULE_BY_ID.get(id.toUpperCase());
  if (!r) return null;
  return [`${c.bold(r.id)} ${c.bold(r.title)} ${sevColor(r.severity)(`(${r.severity})`)}`, '', c.bold('Why it matters'), r.why, '', c.bold('What to do'), r.fix, '', c.dim(`Suppress with a comment containing "skill-guard-ignore ${r.id}" on or above the line, or in .skill-guard.json.`)].join('\n');
}

export function renderRules(): string {
  return RULES.map((r) => `${sevColor(r.severity)(pad(r.id, 6))} ${pad(r.severity, 8)} ${r.title}`).join('\n');
}

export function renderDiff(changes: ItemChange[], lockPath: string): string {
  if (!changes.length) return `${c.green('✓')} Nothing changed since ${tildify(lockPath)}.`;
  const out: string[] = [c.bold(`${plural(changes.length, 'change')} since ${tildify(lockPath)}`), ''];
  const icon = { added: c.green('+ new    '), removed: c.dim('- removed'), changed: c.yellow('~ changed') };
  for (const ch of changes) {
    out.push(`${icon[ch.status]}  ${KIND_LABEL[ch.entry.kind]}  ${c.bold(ch.entry.name)}  ${c.dim(HOST_LABELS[ch.entry.host])}`);
    if (ch.before !== undefined) out.push(`             ${c.red('was ' + fit(ch.before, 100))}\n             ${c.green('now ' + fit(ch.entry.summary ?? '', 100))}`);
    else if (ch.status === 'added' && ch.entry.summary) out.push(`             ${c.dim(fit(ch.entry.summary, 100))}`);
    if (ch.files) {
      for (const f of ch.files.added.slice(0, 5)) out.push(`             ${c.green('+ ' + f)}`);
      for (const f of ch.files.modified.slice(0, 5)) out.push(`             ${c.yellow('~ ' + f)}`);
      for (const f of ch.files.removed.slice(0, 5)) out.push(`             ${c.dim('- ' + f)}`);
    }
  }
  out.push('', c.dim('Review the changes, then run `skill-guard lock` to accept them.'));
  return out.join('\n');
}

// ---------------------------------------------------------------- machine-readable

export function toJson(result: ScanResult & { suppressed?: number }, changes?: ItemChange[]): string {
  const items = result.items.map((i) => ({ id: i.id, kind: i.kind, host: i.host, name: i.name, path: i.path, description: i.description, parent: i.parent, files: i.files.length, mcp: i.mcp, hook: i.hook }));
  return JSON.stringify({ tool: 'skill-guard', version: VERSION, summary: counts(result.findings), items, findings: result.findings, skipped: result.skipped, ...(changes ? { changes } : {}) }, null, 2);
}

const SARIF_LEVEL: Record<Severity, 'error' | 'warning' | 'note'> = { critical: 'error', high: 'error', medium: 'warning', low: 'note', info: 'note' };
const SECURITY_SEVERITY: Record<Severity, string> = { critical: '9.5', high: '8.0', medium: '5.0', low: '2.0', info: '0.0' };

/** SARIF 2.1.0 for GitHub code scanning and other CI dashboards. */
export function toSarif(result: ScanResult, baseDir = process.cwd()): string {
  const itemsById = new Map(result.items.map((i) => [i.id, i]));
  const uri = (file: string) => {
    const rel = relative(baseDir, file).replace(/\\/g, '/');
    return rel && !rel.startsWith('..') ? rel : pathToFileURL(file).href;
  };
  const sarif = {
    $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
    version: '2.1.0',
    runs: [
      {
        tool: {
          driver: {
            name: 'skill-guard',
            version: VERSION,
            informationUri: 'https://www.npmjs.com/package/skill-guard',
            rules: RULES.map((r) => ({
              id: r.id,
              name: r.title.replace(/[^A-Za-z0-9]+/g, ''),
              shortDescription: { text: r.title },
              fullDescription: { text: r.why },
              help: { text: `${r.why}\n\nFix: ${r.fix}`, markdown: `${r.why}\n\n**Fix:** ${r.fix}` },
              defaultConfiguration: { level: SARIF_LEVEL[r.severity] },
              properties: { tags: ['security', 'ai-agent'], 'security-severity': SECURITY_SEVERITY[r.severity] },
            })),
          },
        },
        results: result.findings.map((f) => {
          const item = itemsById.get(f.item);
          const file = f.file ?? item?.path ?? '';
          return {
            ruleId: f.rule,
            level: SARIF_LEVEL[f.severity],
            message: { text: `${f.message}${item ? ` (${KIND_LABEL[item.kind]} "${item.name}")` : ''}` },
            locations: [{ physicalLocation: { artifactLocation: { uri: uri(file) }, ...(f.line ? { region: { startLine: f.line, ...(f.column ? { startColumn: f.column } : {}) } } : {}) } }],
            properties: { severity: f.severity, item: f.item, 'security-severity': SECURITY_SEVERITY[f.severity] },
            partialFingerprints: { 'skillGuard/v1': `${f.rule}:${f.item}:${f.file ?? ''}:${f.evidence ?? ''}`.slice(0, 300) },
          };
        }),
      },
    ],
  };
  return JSON.stringify(sarif, null, 2);
}

/** Markdown for PR comments and step summaries. */
export function toMarkdown(result: ScanResult, min: Severity): string {
  const n = counts(result.findings);
  const shown = result.findings.filter((f) => atLeast(f.severity, min));
  const items = new Map(result.items.map((i) => [i.id, i]));
  const out = [`## skill-guard`, '', `Scanned ${plural(result.items.length, 'item')} (${inventoryLine(result.items) || 'none'}).`, ''];
  out.push(`| Critical | High | Medium | Low |`, `|---:|---:|---:|---:|`, `| ${n.critical} | ${n.high} | ${n.medium} | ${n.low} |`, '');
  if (!shown.length) {
    out.push(`✅ No ${min}+ findings.`);
    return out.join('\n');
  }
  out.push('| Severity | Rule | Item | Location | Finding |', '|---|---|---|---|---|');
  for (const f of shown.slice(0, 200)) {
    const item = items.get(f.item);
    const loc = f.file && item ? `\`${shortFile(item, f.file)}${f.line ? `:${f.line}` : ''}\`` : '';
    const esc = (s: string) => s.replace(/\|/g, '\\|').replace(/\n/g, ' ');
    out.push(`| ${f.severity} | ${f.rule} ${esc(f.title)} | ${esc(item ? `${KIND_LABEL[item.kind]} ${item.name}` : f.item)} | ${loc} | ${esc(f.message)} |`);
  }
  if (shown.length > 200) out.push('', `…and ${shown.length - 200} more.`);
  return out.join('\n');
}
