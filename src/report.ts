import { basename, dirname, relative } from 'node:path';
import { pathToFileURL } from 'node:url';
import { c, fit, pad, plural, width } from './format.ts';
import { CAPABILITY_HELP, CAPABILITY_LABEL } from './capabilities.ts';
import type { ItemChange } from './lock.ts';
import { RULE_BY_ID, RULES } from './rules.ts';
import { itemRisk } from './scan.ts';
import { HOST_LABELS, SEVERITY_ORDER, atLeast, type Capability, type Finding, type Item, type ScanResult, type Severity } from './types.ts';
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
  settings: 'settings',
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
  out.push(`${c.bold('skill-guard')} ${c.dim(VERSION)} ${c.dim('·')} ${opts.title ?? 'scanned'} ${plural(items.length, 'item')} ${c.dim(`(${inventoryLine(items) || 'nothing found'}) in ${(opts.elapsedMs / 1000).toFixed(1)}s`)}`);
  out.push('');
  const ordered = [...byItem.keys()].sort((a, b) => SEVERITY_ORDER[risk.get(b)!] - SEVERITY_ORDER[risk.get(a)!] || a.localeCompare(b));
  const cols = process.stdout.columns || 110;
  for (const id of ordered) {
    const item = itemsById.get(id);
    if (!item) continue;
    const sev = risk.get(id)!;
    const head = `${sevColor(sev)(`${SEV_ICON[sev]} ${SEV_LABEL[sev]}`)}  ${c.dim(HOST_LABELS[item.host])} ${KIND_LABEL[item.kind]}  ${c.bold(fit(displayName(item, itemsById), 70))}`;
    out.push(`${head}  ${c.dim(fitPath(tildify(item.path), Math.max(24, cols - width(head) - 4)))}`);
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
  // A suppressed count is always shown: "no findings" must never hide that something was silenced.
  if (!shown.length) out.push(`${c.green('✓')} ${c.bold(`No ${opts.min === 'info' ? '' : opts.min + '+ '}findings.`)}${hiddenLow ? c.dim(` (${plural(hiddenLow, 'lower-severity finding')} hidden; --min low to see)`) : ''}${opts.suppressed ? c.yellow(` ${plural(opts.suppressed, 'finding')} suppressed.`) : ''}`);
  else {
    out.push(`${c.bold('Findings:')} ${summary}${hiddenLow ? c.dim(`  (${hiddenLow} below ${opts.min} hidden; --min low to see)`) : ''}${opts.suppressed ? c.dim(` · ${opts.suppressed} suppressed`) : ''}`);
    const top = shown[0]!;
    out.push(c.dim(`Run \`skill-guard explain ${top.rule}\` for why a rule matters and how to fix it.`));
  }
  if (result.skipped.length && opts.verbose) out.push(c.dim(`Skipped ${plural(result.skipped.length, 'file')}: ${result.skipped.slice(0, 5).map((s) => `${tildify(s.file)} (${s.reason})`).join(', ')}`));
  return out.join('\n');
}

/**
 * How an item is named in reports. Hooks are stored under their command; the command is
 * already on the evidence line, so they are named by event, matcher and owning plugin.
 */
export function displayName(item: Item, byId?: Map<string, Item>): string {
  if (!item.hook) return item.name;
  const owner = item.parent ? byId?.get(item.parent)?.name : undefined;
  return `${item.hook.event}${item.hook.matcher ? ` [${item.hook.matcher}]` : ''}${owner ? ` from ${owner}` : ''}`;
}

/** "3 run automatically · 2 talk to the network · 1 reads credentials", or '' when nothing can do anything. */
export function capabilitySummary(result: ScanResult): string {
  const PHRASE: Record<Capability, [string, string]> = {
    'auto-runs': ['runs automatically', 'run automatically'],
    'runs-code': ['ships code', 'ship code'],
    network: ['talks to the network', 'talk to the network'],
    'writes-files': ['writes files', 'write files'],
    shell: ['has unrestricted shell access', 'have unrestricted shell access'],
    binaries: ['bundles binaries', 'bundle binaries'],
    credentials: ['reads credentials', 'read credentials'],
  };
  const parts: string[] = [];
  for (const cap of Object.keys(PHRASE) as Capability[]) {
    const n = result.items.filter((i) => result.capabilities?.[i.id]?.includes(cap)).length;
    if (n) parts.push(`${n} ${PHRASE[cap][n === 1 ? 0 : 1]}`);
  }
  return parts.join(' · ');
}

/** Shorten a path in the middle so both the root (`~/.claude`) and the file name survive. */
export function fitPath(p: string, max: number): string {
  if (p.length <= max) return p;
  const parts = p.split(/[\\/]/);
  const sepChar = p.includes('/') ? '/' : '\\';
  const head = parts.slice(0, Math.min(2, parts.length - 1)).join(sepChar);
  let tail = parts.slice(-1);
  // Keep as many trailing segments as fit after "<head>/…/".
  for (let i = parts.length - 2; i >= 2; i--) {
    const next = [parts[i] as string, ...tail];
    if (head.length + 3 + next.join(sepChar).length > max) break;
    tail = next;
  }
  const out = `${head}${sepChar}…${sepChar}${tail.join(sepChar)}`;
  return out.length <= max ? out : '…' + p.slice(-(max - 1));
}

/** "from <plugin>: ‹plugin›/hooks/run.sh start" — who installed the hook and what it runs, without the noise. */
function hookDetail(i: Item, byId: Map<string, Item>): string {
  const cmd = (i.hook?.command ?? '')
    .replace(/\$\{CLAUDE_PLUGIN_ROOT\}\/?|\$CLAUDE_PLUGIN_ROOT\/?/g, '‹plugin›/')
    .replace(/"([^"\s]*)"|'([^'\s]*)'/g, '$1$2')
    .replace(/\s+/g, ' ');
  const parent = i.parent ? byId.get(i.parent)?.name : undefined;
  return fit(parent ? `${parent}: ${cmd}` : cmd, 50);
}

/** `only`: show just these item ids (e.g. `--can`), while still resolving parents from the full list. */
export function renderInventory(result: ScanResult, only?: Set<string>): string {
  const risk = itemRisk(result.findings.filter((f) => atLeast(f.severity, 'medium')));
  const rows = result.items.filter((i) => !only || only.has(i.id)).sort((a, b) => a.host.localeCompare(b.host) || a.kind.localeCompare(b.kind) || a.name.localeCompare(b.name));
  const out: string[] = [`${c.bold(plural(rows.length, 'item'))} ${c.dim(`(${inventoryLine(rows)})`)}`, ''];
  const capsOf = (id: string) => result.capabilities?.[id] ?? [];
  const byId = new Map(result.items.map((i) => [i.id, i]));
  const used = new Set<Capability>();
  let lastHost = '';
  for (const i of rows) {
    if (i.host !== lastHost) {
      out.push(c.bold(HOST_LABELS[i.host]));
      lastHost = i.host;
    }
    const r = risk.get(i.id);
    const flag = r ? sevColor(r)(SEV_LABEL[r]) : c.green('ok');
    const caps = capsOf(i.id);
    for (const cap of caps) used.add(cap);
    const capText = caps.map((cap) => (cap === 'auto-runs' || cap === 'credentials' ? c.yellow(CAPABILITY_LABEL[cap]) : CAPABILITY_LABEL[cap])).join(' ');
    const detail = i.hook ? hookDetail(i, byId) : i.mcp ? fit(i.mcp.url ?? [i.mcp.command ?? '', ...i.mcp.args].join(' '), 50) : fit((i.description ?? '').replace(/\s+/g, ' ').trim(), 50);
    // The owning plugin is already in the detail column for hooks.
    const name = i.hook ? displayName({ ...i, parent: undefined }) : i.name;
    out.push(`  ${pad(flag, 9)} ${pad(KIND_LABEL[i.kind], 12)} ${pad(fit(name, 36), 36)} ${pad(capText, 24)} ${c.dim(detail)}`);
  }
  if (used.size) {
    out.push('', c.dim('Capabilities (what an item can do, not a verdict):'));
    for (const cap of Object.keys(CAPABILITY_LABEL) as Capability[]) if (used.has(cap)) out.push(c.dim(`  ${pad(CAPABILITY_LABEL[cap], 6)} ${CAPABILITY_HELP[cap]} (${rows.filter((i) => capsOf(i.id).includes(cap)).length})`));
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
    const caps = ch.capabilities;
    if (caps?.gained.length) out.push(`             ${c.yellow('now also: ' + caps.gained.map((x) => CAPABILITY_LABEL[x]).join(' '))}`);
    if (caps?.lost.length) out.push(`             ${c.dim('no longer: ' + caps.lost.map((x) => CAPABILITY_LABEL[x]).join(' '))}`);
    if (ch.status === 'added' && caps?.now.length) out.push(`             ${c.dim('can: ' + caps.now.map((x) => CAPABILITY_LABEL[x]).join(' '))}`);
    if (ch.before !== undefined) out.push(`             ${c.red('was ' + fit(ch.before, 100))}\n             ${c.green('now ' + fit(ch.entry.summary ?? '', 100))}`);
    // A hook's name already contains its command; only show the summary when it adds something.
    else if (ch.status === 'added' && ch.entry.summary && !ch.entry.name.includes(ch.entry.summary)) out.push(`             ${c.dim(fit(ch.entry.summary, 100))}`);
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
  const items = result.items.map((i) => ({ id: i.id, kind: i.kind, host: i.host, name: i.name, path: i.path, description: i.description, parent: i.parent, files: i.files.length, capabilities: result.capabilities?.[i.id] ?? [], mcp: i.mcp, hook: i.hook }));
  // `schema` changes only on a breaking change to this shape (see docs/COMPATIBILITY.md); fields may be added without one.
  return JSON.stringify({ tool: 'skill-guard', version: VERSION, schema: 1, summary: counts(result.findings), items, findings: result.findings, skipped: result.skipped, ...(changes ? { changes } : {}) }, null, 2);
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
  const caps = capabilitySummary(result);
  if (caps) out.push(`**What they can do:** ${caps}`, '');
  if (!shown.length) {
    out.push(`✅ No ${min}+ findings.`);
    return out.join('\n');
  }
  out.push('| Severity | Rule | Item | Location | Finding |', '|---|---|---|---|---|');
  for (const f of shown.slice(0, 200)) {
    const item = items.get(f.item);
    const loc = f.file && item ? `\`${shortFile(item, f.file)}${f.line ? `:${f.line}` : ''}\`` : '';
    const esc = (s: string) => s.replace(/\|/g, '\\|').replace(/\n/g, ' ');
    out.push(`| ${f.severity} | ${f.rule} ${esc(f.title)} | ${esc(item ? `${KIND_LABEL[item.kind]} ${displayName(item, items)}` : f.item)} | ${loc} | ${esc(f.message)} |`);
  }
  if (shown.length > 200) out.push('', `…and ${shown.length - 200} more.`);
  return out.join('\n');
}
