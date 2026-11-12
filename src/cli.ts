import { writeFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { parseArgs, type ParseArgsConfig } from 'node:util';
import { discoverMachine, discoverPath } from './discover.ts';
import { c, plural, setColor } from './format.ts';
import { annotateCapabilities, buildLock, defaultLockPath, diffLock, readLock, writeLock } from './lock.ts';
import { parseJsonc } from './parse.ts';
import { renderDiff, renderExplain, renderInventory, renderRules, renderTerminal, toJson, toMarkdown, toSarif } from './report.ts';
import { checkRegistries, packageRefs } from './registry.ts';
import { itemUnits, mergeFindings, scanItems, type Suppression } from './scan.ts';
import { HOST_LABELS, SEVERITY_ORDER, atLeast, type Capability, type Finding, type Host, type Item, type ScanResult, type Severity } from './types.ts';
import { exists, home, isObject, prefetch, readText, takeTruncatedWalks, tildify, withFsCacheAsync } from './util.ts';
import { VERSION } from './version.ts';

const HELP = `${c.bold('skill-guard')} — find prompt injection, exfiltration and hidden instructions
in the Skills, plugins, hooks and MCP servers your AI agents run.

${c.bold('Usage')}
  skill-guard [command] [path…] [options]

${c.bold('Commands')}
  scan [path…]     Scan everything installed on this machine, or the given folders (default)
  list [path…]     Inventory: every skill, plugin, hook and MCP server, with its risk and capabilities
  lock [path]      Record what is installed now, so later changes are flagged
  diff [path]      Show what changed since the last lock (new hooks, edited skills, swapped servers)
  explain <rule>   Why a rule matters and how to fix it
  rules            List all rules

${c.bold('Options')}
      --host <name>      Only these agents: claude, codex, cursor, opencode, deepseek, desktop, vscode, agents
      --can <caps>       Only items with all of these capabilities: code, auto, net, write, shell, bin, creds
      --min <level>      Show findings at or above: critical, high, medium (default), low, info
      --fail-on <level>  Exit with code 1 if a finding is at or above this level (default: high; "none" to disable)
      --json             JSON report on stdout
      --sarif <file>     Write SARIF 2.1.0 (for GitHub code scanning); "-" for stdout
      --md               Markdown report (PR comments, CI summaries)
      --check-registries Look up the packages that install steps name (npm, PyPI): flags names that do not exist
                         (an AI invented them; anyone can register them), very new or barely used ones, and
                         ones removed as malware. Sends only package names, to the registries; off by default
      --trust-ignores    Honour skill-guard-ignore comments and .skill-guard.json in the scanned files
                         (only for repositories you own: scanned content could otherwise ignore itself)
      --config <file>    Suppressions file (default: .skill-guard.json in the scanned folder or ~/.config/skill-guard/)
      --lock <file>      Lock file for lock/diff (default: ~/.config/skill-guard/lock.json, or <path>/skill-guard.lock.json)
  -v, --verbose          Show every finding and skipped file
      --no-color         Disable colors

${c.bold('Examples')}
  skill-guard                               scan every agent on this machine
  skill-guard scan ./some-skill             check a skill before installing it
  skill-guard scan . --sarif out.sarif      CI: scan a repository's agent config
  skill-guard list --can auto,net           what runs by itself and talks to the network?
  skill-guard lock && skill-guard diff      get told when a plugin update adds a hook

Everything runs locally. Nothing is executed, nothing is uploaded.
`;

const OPTIONS = {
  host: { type: 'string', multiple: true },
  can: { type: 'string', multiple: true },
  'trust-ignores': { type: 'boolean' },
  'check-registries': { type: 'boolean' },
  min: { type: 'string' },
  'fail-on': { type: 'string' },
  json: { type: 'boolean' },
  sarif: { type: 'string' },
  md: { type: 'boolean' },
  config: { type: 'string' },
  lock: { type: 'string' },
  verbose: { type: 'boolean', short: 'v' },
  'no-color': { type: 'boolean' },
  help: { type: 'boolean', short: 'h' },
  version: { type: 'boolean' },
} satisfies ParseArgsConfig['options'];

type Values = ReturnType<typeof parseArgs<{ options: typeof OPTIONS; allowPositionals: true }>>['values'];

class UsageError extends Error {}

const LEVELS: Severity[] = ['critical', 'high', 'medium', 'low', 'info'];

function level(v: string | undefined, fallback: Severity, name: string): Severity {
  if (v === undefined) return fallback;
  if (!LEVELS.includes(v as Severity)) throw new UsageError(`${name} must be one of: ${LEVELS.join(', ')}`);
  return v as Severity;
}

const HOST_ALIASES: Record<string, Host> = {
  claude: 'claude-code',
  'claude-code': 'claude-code',
  cc: 'claude-code',
  codex: 'codex',
  cursor: 'cursor',
  opencode: 'opencode',
  deepseek: 'deepseek-harness',
  dsh: 'deepseek-harness',
  'deepseek-harness': 'deepseek-harness',
  desktop: 'claude-desktop',
  'claude-desktop': 'claude-desktop',
  vscode: 'vscode',
  code: 'vscode',
  agents: 'agents',
};

function hosts(v: Values): Host[] {
  const out: Host[] = [];
  for (const raw of v.host ?? []) {
    for (const name of raw.split(',').filter(Boolean)) {
      const h = HOST_ALIASES[name.toLowerCase()];
      if (!h) throw new UsageError(`Unknown host "${name}". Use: ${Object.keys(HOST_ALIASES).join(', ')}`);
      out.push(h);
    }
  }
  return out;
}

/**
 * Suppressions inside the scanned content are written by whoever wrote that content — a
 * malicious skill would simply ignore itself, and `cd downloaded-skill && skill-guard scan .`
 * is exactly how people check one. So inline comments and `.skill-guard.json` files in the
 * scanned folder or the current directory count only with `--trust-ignores` (your own
 * repository in CI). `--config <file>` and ~/.config/skill-guard/config.json always count.
 */
function loadSuppressions(v: Values, targets: string[]): Suppression[] {
  const local = v['trust-ignores'] ? [...targets.map((t) => join(resolve(t), '.skill-guard.json')), join(process.cwd(), '.skill-guard.json')] : [];
  const candidates = v.config ? [resolve(v.config)] : [...local, join(home(), '.config', 'skill-guard', 'config.json')];
  for (const file of candidates) {
    if (!exists(file)) {
      if (v.config) throw new UsageError(`Config file not found: ${file}`);
      continue;
    }
    const r = readText(file);
    const cfg = 'text' in r ? parseJsonc(r.text) : undefined;
    if (!isObject(cfg)) throw new UsageError(`Could not parse ${file}`);
    const list = Array.isArray(cfg.ignore) ? cfg.ignore : [];
    return list.filter(isObject).map((s) => {
      const out: Suppression = { rule: String(s.rule ?? '*') };
      if (typeof s.item === 'string') out.item = s.item;
      if (typeof s.path === 'string') out.path = s.path;
      if (typeof s.reason === 'string') out.reason = s.reason;
      return out;
    });
  }
  return [];
}

function discover(v: Values, targets: string[]): Item[] {
  if (!targets.length) return discoverMachine({ hosts: hosts(v) });
  const items: Item[] = [];
  for (const t of targets) {
    const p = resolve(t);
    if (!exists(p)) throw new UsageError(`No such file or folder: ${t}`);
    items.push(...discoverPath(p));
  }
  return items;
}

/** Discover, then read every file the scan will need in parallel (see prefetch). */
async function load(v: Values, targets: string[]): Promise<Item[]> {
  const items = discover(v, targets);
  await prefetch(items.flatMap((i) => i.files));
  // A capped listing means some files were not looked at: never silent.
  for (const root of takeTruncatedWalks()) console.error(c.yellow(`warning: stopped listing files under ${tildify(root)} at the file limit; some files there were not scanned.`));
  return items;
}

/**
 * `--check-registries`: the packages install steps name, looked up on npm and PyPI. A name that could not be
 * looked up (no network, a registry error) is said on stderr, never taken as missing. SKILL_GUARD_NPM_REGISTRY,
 * SKILL_GUARD_NPM_DOWNLOADS and SKILL_GUARD_PYPI point it at other registries (a mirror, or a test server).
 */
async function registryFindings(items: Item[]): Promise<Finding[]> {
  const refs = packageRefs(items, itemUnits);
  if (!refs.length) return [];
  const env = process.env;
  const r = await checkRegistries(refs, { npm: env.SKILL_GUARD_NPM_REGISTRY, npmDownloads: env.SKILL_GUARD_NPM_DOWNLOADS, pypi: env.SKILL_GUARD_PYPI });
  console.error(c.dim(`registry check: ${plural(r.checked, 'package')} looked up (npm, PyPI)`));
  if (r.failed.length) {
    const list = r.failed.slice(0, 5).map((f) => `${f.name} (${f.reason})`).join(', ');
    console.error(c.yellow(`warning: could not check ${plural(r.failed.length, 'package')}: ${list}${r.failed.length > 5 ? ', …' : ''}`));
  }
  return r.findings;
}

async function cmdScan(v: Values, targets: string[]): Promise<number> {
  // One document on stdout: `--sarif - --json` printed two JSON documents back to back (not parseable), and
  // `--md --json` dropped the Markdown without a word.
  const onStdout = [v.json && '--json', v.md && '--md', v.sarif === '-' && '--sarif -'].filter(Boolean);
  if (onStdout.length > 1) throw new UsageError(`${onStdout.join(' and ')} both write to stdout; pick one${v.sarif === '-' ? ' (or write SARIF to a file with --sarif <file>)' : ''}.`);
  const t0 = performance.now();
  const want = capabilityFilter(v);
  const scanOptions = { suppressions: loadSuppressions(v, targets), inlineIgnores: !!v['trust-ignores'] };
  let full = scanItems(await load(v, targets), scanOptions);
  if (v['check-registries']) full = mergeFindings(full, await registryFindings(full.items), scanOptions);
  const result = restrict(full, withCapabilities(full, want));
  const items = result.items;
  const elapsed = performance.now() - t0;
  const min = level(v.min, 'medium', '--min');
  const failOn = v['fail-on'] === 'none' ? null : level(v['fail-on'], 'high', '--fail-on');
  if (v.sarif) {
    const sarif = toSarif(result, targets[0] ? resolve(targets[0]) : process.cwd());
    if (v.sarif === '-') process.stdout.write(sarif + '\n');
    else {
      // Exit 1 means "findings": a SARIF file that cannot be written is an error (2), so CI can tell them apart.
      try {
        writeFileSync(v.sarif, sarif);
      } catch (e) {
        console.error(c.red(`Could not write ${v.sarif}: ${(e as NodeJS.ErrnoException).code ?? (e as Error).message}`));
        return 2;
      }
    }
  }
  if (v.json) process.stdout.write(toJson(result) + '\n');
  else if (v.md) process.stdout.write(toMarkdown(result, min) + '\n');
  else if (v.sarif !== '-') {
    const title = targets.length ? `scanned ${targets.map((t) => tildify(resolve(t))).join(', ')}:` : 'scanned';
    console.log(renderTerminal(result, { min, verbose: !!v.verbose, elapsedMs: elapsed, suppressed: result.suppressed, title }));
    if (!items.length && full.items.length) console.log(c.dim(`\nNone of the ${plural(full.items.length, 'item')} found has all of: ${want.join(', ')}.`));
    else if (!items.length) console.log(c.dim(targets.length ? '\nNothing an agent would load was found here (no SKILL.md, plugin.json, hooks, MCP config or CLAUDE.md/AGENTS.md).' : '\nNo agents found. Pass a folder to scan it, e.g. `skill-guard scan ./my-skill`.'));
    if (v.sarif && v.sarif !== '-') console.log(c.dim(`SARIF written to ${v.sarif}`));
  }
  if (failOn && result.findings.some((f) => atLeast(f.severity, failOn))) return 1;
  return 0;
}

const CAP_ALIASES: Record<string, Capability> = {
  code: 'runs-code',
  'runs-code': 'runs-code',
  auto: 'auto-runs',
  'auto-runs': 'auto-runs',
  net: 'network',
  network: 'network',
  write: 'writes-files',
  writes: 'writes-files',
  'writes-files': 'writes-files',
  shell: 'shell',
  bin: 'binaries',
  binaries: 'binaries',
  creds: 'credentials',
  credentials: 'credentials',
};

function capabilityFilter(v: Values): Capability[] {
  const out: Capability[] = [];
  for (const name of (v.can ?? []).flatMap((s) => s.split(',')).filter(Boolean)) {
    const cap = CAP_ALIASES[name.toLowerCase()];
    if (!cap) throw new UsageError(`Unknown capability "${name}". Use: code, auto, net, write, shell, bin, creds`);
    out.push(cap);
  }
  return out;
}

/** Ids of items with every requested capability: `--can auto,net` = "runs by itself AND talks to the network". */
function withCapabilities(result: ScanResult, want: Capability[]): Set<string> | undefined {
  if (!want.length) return undefined;
  return new Set(result.items.filter((i) => want.every((cap) => result.capabilities?.[i.id]?.includes(cap))).map((i) => i.id));
}

function restrict<T extends ScanResult>(result: T, keep: Set<string> | undefined): T {
  return keep ? { ...result, items: result.items.filter((i) => keep.has(i.id)), findings: result.findings.filter((f) => keep.has(f.item)) } : result;
}

async function cmdList(v: Values, targets: string[]): Promise<number> {
  const want = capabilityFilter(v);
  const result = scanItems(await load(v, targets), { suppressions: loadSuppressions(v, targets), inlineIgnores: !!v['trust-ignores'] });
  const keep = withCapabilities(result, want);
  if (v.json) process.stdout.write(toJson(restrict(result, keep)) + '\n');
  else console.log(renderInventory(result, keep));
  return 0;
}

function lockPath(v: Values, targets: string[]): string {
  return v.lock ? resolve(v.lock) : defaultLockPath(targets[0] ? resolve(targets[0]) : undefined);
}

async function cmdLock(v: Values, targets: string[]): Promise<number> {
  const items = await load(v, targets);
  const path = lockPath(v, targets);
  // Scanning records what each item can do, so a later diff can say "now also talks to the network".
  writeLock(path, buildLock(items, VERSION, scanItems(items).capabilities));
  console.log(`${c.green('✓')} Locked ${items.length} items → ${tildify(path)}`);
  console.log(c.dim('Run `skill-guard diff` any time to see what changed since now.'));
  return 0;
}

async function cmdDiff(v: Values, targets: string[]): Promise<number> {
  const path = lockPath(v, targets);
  const lock = readLock(path);
  if (!lock) throw new UsageError(`No lock file at ${tildify(path)}. Run \`skill-guard lock\` first.`);
  const items = await load(v, targets);
  const changes = diffLock(lock, items);
  // Scan only what is new or changed: that is what you have not reviewed yet.
  const touched = new Set(changes.filter((ch) => ch.status !== 'removed').map((ch) => ch.id));
  const result = scanItems(
    items.filter((i) => touched.has(i.id)),
    { suppressions: loadSuppressions(v, targets), inlineIgnores: !!v['trust-ignores'] },
  );
  annotateCapabilities(changes, lock, result.capabilities);
  if (v.json) {
    process.stdout.write(toJson(result, changes) + '\n');
  } else {
    console.log(renderDiff(changes, path));
    if (result.findings.some((f) => SEVERITY_ORDER[f.severity] >= SEVERITY_ORDER.medium)) {
      console.log('');
      console.log(renderTerminal(result, { min: level(v.min, 'medium', '--min'), verbose: !!v.verbose, elapsedMs: 0, suppressed: result.suppressed, title: 'findings in new or changed items:' }));
    }
  }
  const failOn = v['fail-on'] === 'none' ? null : level(v['fail-on'], 'high', '--fail-on');
  return failOn && result.findings.some((f) => atLeast(f.severity, failOn)) ? 1 : 0;
}

export async function main(argv: string[]): Promise<number> {
  let parsed;
  try {
    parsed = parseArgs({ args: argv, options: OPTIONS, allowPositionals: true, strict: true });
  } catch (err) {
    console.error(c.red((err as Error).message));
    console.error(c.dim('Run `skill-guard --help` for usage.'));
    return 2;
  }
  const v = parsed.values;
  if (v['no-color'] || v.json || v.sarif === '-' || v.md) setColor(false);
  if (v.version) {
    console.log(VERSION);
    return 0;
  }
  const COMMANDS = ['scan', 'list', 'ls', 'lock', 'diff', 'explain', 'rules', 'help'];
  let [cmd = 'scan', ...rest] = parsed.positionals;
  // `skill-guard ./path` means `skill-guard scan ./path`
  if (!COMMANDS.includes(cmd)) {
    rest = [cmd, ...rest];
    cmd = 'scan';
  }
  if (v.help || cmd === 'help') {
    console.log(HELP);
    return 0;
  }
  try {
    switch (cmd) {
      // One command = one consistent view of the filesystem, read once.
      case 'scan':
        return await withFsCacheAsync(() => cmdScan(v, rest));
      case 'list':
      case 'ls':
        return await withFsCacheAsync(() => cmdList(v, rest));
      case 'lock':
        return await withFsCacheAsync(() => cmdLock(v, rest));
      case 'diff':
        return await withFsCacheAsync(() => cmdDiff(v, rest));
      case 'explain': {
        const text = rest[0] ? renderExplain(rest[0]) : null;
        if (!text) {
          console.error(c.red(rest[0] ? `Unknown rule "${rest[0]}".` : 'Usage: skill-guard explain <rule>') + c.dim(' Run `skill-guard rules` for the list.'));
          return 2;
        }
        console.log(text);
        return 0;
      }
      case 'rules':
        console.log(renderRules());
        return 0;
    }
  } catch (err) {
    if (err instanceof UsageError) {
      console.error(c.red(err.message));
      return 2;
    }
    console.error(c.red('Error: ') + ((err as Error)?.stack ?? String(err)));
    return 1;
  }
  return 0;
}

export { HOST_LABELS };
