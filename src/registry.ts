/**
 * Packages that install commands in skills, plugins, hooks and instruction files would install, checked against
 * their registry (`--check-registries`, off by default).
 *
 * The case this is for: an AI model invents a package name, the name ends up in a skill or a README as an install
 * step, and whoever registers that name gets their code run by every agent that follows the step ("slopsquatting").
 * A made-up npm name spread this way through AI-written skill files. Hooks that watch the command an agent is about
 * to run do not see files that are only sitting in a repository; this does.
 *
 * Offline, the names are only extracted. Online, each distinct name is looked up once: the npm registry (and its
 * download counts) for npm, PyPI for Python. Only package names are sent, never file contents or paths.
 */
import type { Finding, Item, TextUnit } from './types.ts';
import { RULE_BY_ID } from './rules.ts';

export type Ecosystem = 'npm' | 'pypi';

export interface PackageRef {
  ecosystem: Ecosystem;
  name: string;
  item: Item;
  file?: string;
  line?: number;
  /** The command as written (trimmed). */
  command: string;
}

/** A command that installs or runs packages, and which registry its arguments come from. */
interface Installer {
  re: RegExp;
  ecosystem: Ecosystem;
  /** Options that take a value (the next word is not a package). */
  valued: Set<string>;
  /** Only the first package-like word is a package (runners: the rest are its arguments). */
  firstOnly?: boolean;
}

const NPM_VALUED = new Set(['--registry', '--prefix', '--tag', '--workspace', '--cache', '--userconfig', '--omit', '--include', '--save-prefix', '--filter', '-C', '--dir', '--cwd', '-c', '--call']);
const PY_VALUED = new Set(['-r', '--requirement', '-c', '--constraint', '-e', '--editable', '-i', '--index-url', '--extra-index-url', '-f', '--find-links', '-t', '--target', '--python', '-p', '--prefix', '--root', '--platform', '--implementation', '--abi', '--python-version', '--trusted-host', '--cert', '--client-cert', '--proxy', '--group', '--extra', '--with', '--from', '--source', '-G', '--index', '--only-binary', '--no-binary', '--progress-bar', '--src', '--upgrade-strategy', '--log', '--cache-dir', '--jobs', '-j', '--optional', '--package']);

// Each command where a shell would start one: line start, after a separator, inside $( or a backtick, or after
// `sudo`/`env X=y`. The words after it run to the next separator.
const START = String.raw`(?:^|[;&|(\x60]\s*|\$\(\s*|\bsudo\s+|\bthen\s+|\bdo\s+)`;
const INSTALLERS: Installer[] = [
  { re: new RegExp(`${START}(?:npm|cnpm|pnpm|yarn|bun)(?:\\.cmd)?\\s+(?:install|i|add|in|isntall)\\b`, 'gim'), ecosystem: 'npm', valued: NPM_VALUED },
  { re: new RegExp(`${START}(?:npx|bunx|pnpx)(?:\\.cmd)?\\b|${START}(?:pnpm|yarn)\\s+dlx\\b|${START}npm\\s+exec\\b`, 'gim'), ecosystem: 'npm', valued: new Set([...NPM_VALUED, '-p', '--package']), firstOnly: true },
  { re: new RegExp(`${START}(?:python3?(?:\\.\\d+)?\\s+-m\\s+)?pip3?(?:\\.exe)?\\s+install\\b|${START}uv\\s+pip\\s+install\\b|${START}uv\\s+(?:add|tool\\s+install)\\b|${START}(?:poetry|pdm|rye)\\s+add\\b|${START}pipx\\s+install\\b`, 'gim'), ecosystem: 'pypi', valued: PY_VALUED },
  { re: new RegExp(`${START}uvx\\b|${START}pipx\\s+run\\b|${START}uv\\s+tool\\s+run\\b`, 'gim'), ecosystem: 'pypi', valued: PY_VALUED, firstOnly: true },
];

/** Where a command's words end: a separator, a subshell, a new line, a redirect (`<` or `>` not part of `>=`/`<=`, which
 * version specifiers use), or a shell comment (`  # Update lock file only` is not three packages). */
const END = /[;&|)\x60]|\$\(|\n|[<>](?!=)|\s#/;

/** Words that stand for a package in documentation rather than name one. */
const PLACEHOLDER = /^(<.*>|\[.*\]|\{.*\}|\$.+|%.+%|\.\.\.|…|(your|my|some|the|a|an|new|other)[-_]?(package|pkg|module|lib|library|name|tool|dependency|dep|project|app)s?([-_]name)?|(package|pkg|module|dependency|dep)([-_]?(name|\d+))?|name|x|foo|bar|baz|example([-_].*)?|placeholder|something|whatever|etc|@repo\/.*)$/i;
const NPM_NAME = /^(@[a-z0-9][a-z0-9._~-]*\/)?[a-z0-9][a-z0-9._~-]*$/;
const PYPI_NAME = /^[A-Za-z0-9]([A-Za-z0-9._-]*[A-Za-z0-9])?$/;

/** The package name in one word of an install command, or null when the word is not a registry package. */
export function packageName(word: string, ecosystem: Ecosystem): string | null {
  let w = word.replace(/^['"]|['"]$/g, '');
  if (!w || /^[-+]/.test(w) || PLACEHOLDER.test(w)) return null;
  // Placeholders with a version (`package@latest`) or a specifier (`package1==1.0`) too.
  if (PLACEHOLDER.test(w.replace(/(?<=.)@[^/]*$/, '').split(/[[\]=<>!~;]/)[0] ?? '')) return null;
  // Paths, URLs, git and file specs, archives, requirement files: not a registry name.
  if (/^(\.{0,2}[\\/]|~|[A-Za-z]:[\\/])|:\/\/|^(git\+|git@|github:|gitlab:|bitbucket:|file:|link:|workspace:|npm:)|\.(whl|tgz|tar\.gz|zip|txt|toml|cfg|lock)$/i.test(w)) return null;
  if (ecosystem === 'npm') {
    // name@version, @scope/name@version
    const at = w.lastIndexOf('@');
    if (at > 0) w = w.slice(0, at);
    w = w.toLowerCase();
    if (w.includes('/') && !w.startsWith('@')) return null; // user/repo: a GitHub shorthand
    // `@repo/…` is Turborepo's convention for packages of the workspace itself, not of the registry.
    return NPM_NAME.test(w) && w.length <= 214 && !w.startsWith('@repo/') ? w : null;
  }
  // name[extra]==1.0, name>=1, name~=1, name@ url
  w = w.split(/[[\]=<>!~;@\s]/)[0] ?? '';
  // A bare number is an option's value (`--jobs 4`) far more often than a project name.
  return PYPI_NAME.test(w) && !/^\d+$/.test(w) ? w.toLowerCase().replace(/[-_.]+/g, '-') : null;
}

/** Every registry package that install commands in this text would install. */
export function packagesIn(text: string): { ecosystem: Ecosystem; name: string; index: number; command: string }[] {
  const out: { ecosystem: Ecosystem; name: string; index: number; command: string }[] = [];
  for (const inst of INSTALLERS) {
    inst.re.lastIndex = 0;
    for (const m of text.matchAll(inst.re)) {
      const start = (m.index ?? 0) + m[0].length;
      const LIMIT = 4000;
      let rest = text.slice(start, start + LIMIT);
      const end = rest.search(END);
      if (end < 0 && rest.length === LIMIT) rest = rest.slice(0, rest.search(/\s\S*$/) + 1); // the last word may be cut
      const args = (end < 0 ? rest : rest.slice(0, end)).trim();
      const command = text.slice(m.index ?? 0, start).replace(/^[;&|(\x60$\s]+/, '').trim() + (args ? ` ${args}` : '');
      const words = args.split(/\s+/).filter(Boolean);
      for (let i = 0; i < words.length; i++) {
        const w = words[i] as string;
        if (w.startsWith('-')) {
          if (inst.valued.has(w.split('=')[0] as string) && !w.includes('=')) i++;
          continue;
        }
        const name = packageName(w, inst.ecosystem);
        if (name) out.push({ ecosystem: inst.ecosystem, name, index: m.index ?? 0, command: command.slice(0, 200) });
        if (inst.firstOnly) break;
      }
    }
  }
  return out;
}

/** The packages that the scanned items' install commands name, with where. Offline. */
export function packageRefs(items: Item[], unitsOf: (item: Item) => TextUnit[]): PackageRef[] {
  const out: PackageRef[] = [];
  for (const item of items) {
    for (const unit of unitsOf(item)) {
      if (unit.kind === 'metadata') continue;
      for (const p of packagesIn(unit.text)) {
        const line = unit.lineOffset !== undefined ? unit.lineOffset + (unit.text.slice(0, p.index).match(/\n/g)?.length ?? 0) : undefined;
        out.push({ ecosystem: p.ecosystem, name: p.name, item, file: unit.file, line, command: p.command });
      }
    }
  }
  return out;
}

/** What the registry says about a name. */
export type Lookup =
  /** For a scoped npm name: whether anything is published under its scope (then only its owner can publish this). */
  | { status: 'missing'; scopeTaken?: boolean }
  | { status: 'removed' }
  | { status: 'found'; created?: Date; weeklyDownloads?: number }
  | { status: 'error'; reason: string };

export interface RegistryOptions {
  /** fetch, replaceable in tests. */
  fetch?: typeof fetch;
  /** Registry base URLs (tests point them at a local server). */
  npm?: string;
  npmDownloads?: string;
  pypi?: string;
  now?: Date;
  timeoutMs?: number;
  concurrency?: number;
}

const DAY = 24 * 60 * 60 * 1000;
/** A package younger than this is "new". */
export const NEW_DAYS = 90;
/** An npm package with fewer downloads in the last week than this is "barely used". */
export const FEW_DOWNLOADS = 50;

async function getJson(f: typeof fetch, url: string, timeoutMs: number): Promise<{ status: number; body?: unknown }> {
  const res = await f(url, { headers: { accept: 'application/json', 'user-agent': 'skill-guard (registry check)' }, signal: AbortSignal.timeout(timeoutMs), redirect: 'follow' });
  if (res.status === 404) return { status: 404 };
  if (!res.ok) return { status: res.status };
  return { status: res.status, body: await res.json() };
}

/** Looks a name up. Network and registry errors are `error`, never `missing`: a timeout is not a missing package. */
export async function lookup(ecosystem: Ecosystem, name: string, o: RegistryOptions = {}): Promise<Lookup> {
  const f = o.fetch ?? fetch;
  const timeout = o.timeoutMs ?? 15_000;
  try {
    if (ecosystem === 'npm') {
      const enc = name.startsWith('@') ? `@${encodeURIComponent(name.slice(1))}` : encodeURIComponent(name);
      const downloads = await getJson(f, `${o.npmDownloads ?? 'https://api.npmjs.org'}/downloads/point/last-week/${enc}`, timeout);
      const weekly = downloads.status === 200 && typeof (downloads.body as { downloads?: unknown })?.downloads === 'number' ? (downloads.body as { downloads: number }).downloads : undefined;
      // Popular packages: no need to fetch their (large) document.
      if (weekly !== undefined && weekly >= 10_000) return { status: 'found', weeklyDownloads: weekly };
      const doc = await getJson(f, `${o.npm ?? 'https://registry.npmjs.org'}/${enc}`, timeout);
      if (doc.status === 404) {
        if (!name.startsWith('@')) return { status: 'missing' };
        // Under a scope only its owner publishes: a missing name under a scope that has packages is a broken step, not
        // an opening. An empty scope may be free for anyone to claim.
        const scope = name.slice(1, name.indexOf('/'));
        // The registry lists a scope's packages (users and organisations alike); "Scope not found" means nobody has it.
        // (Its search API's `scope:` qualifier answers 0 even for @eslint: not usable for this.)
        const owner = await getJson(f, `${o.npm ?? 'https://registry.npmjs.org'}/-/org/${encodeURIComponent(scope)}/package`, timeout);
        return { status: 'missing', scopeTaken: owner.status === 200 ? true : owner.status === 404 ? false : undefined };
      }
      if (doc.status !== 200 || typeof doc.body !== 'object' || !doc.body) return { status: 'error', reason: `npm registry answered ${doc.status}` };
      const body = doc.body as { 'dist-tags'?: { latest?: string }; time?: Record<string, string>; versions?: Record<string, unknown> };
      // npm replaces a package it removed for malware with a "0.0.1-security" placeholder.
      if (body['dist-tags']?.latest?.endsWith('-security') && Object.keys(body.versions ?? {}).every((v) => v.endsWith('-security'))) return { status: 'removed' };
      // A name whose versions were all unpublished: anyone may be able to take it over.
      if (!Object.keys(body.versions ?? {}).length) return { status: 'missing' };
      const created = body.time?.created ? new Date(body.time.created) : undefined;
      return { status: 'found', created: created && !Number.isNaN(created.getTime()) ? created : undefined, weeklyDownloads: weekly };
    }
    const doc = await getJson(f, `${o.pypi ?? 'https://pypi.org'}/pypi/${encodeURIComponent(name)}/json`, timeout);
    if (doc.status === 404) return { status: 'missing' };
    if (doc.status !== 200 || typeof doc.body !== 'object' || !doc.body) return { status: 'error', reason: `PyPI answered ${doc.status}` };
    const releases = (doc.body as { releases?: Record<string, { upload_time_iso_8601?: string; upload_time?: string }[]> }).releases ?? {};
    const times = Object.values(releases).flat().map((r) => new Date(r.upload_time_iso_8601 ?? r.upload_time ?? '').getTime()).filter((t) => !Number.isNaN(t));
    if (!times.length) return { status: 'missing' }; // a project with no files: nothing to install, the name can be claimed
    return { status: 'found', created: new Date(Math.min(...times)) };
  } catch (e) {
    return { status: 'error', reason: (e as Error).name === 'TimeoutError' ? 'timed out' : String((e as Error).message ?? e) };
  }
}

export interface RegistryResult {
  findings: Finding[];
  /** Distinct names looked up, and those that could not be checked. */
  checked: number;
  failed: { ecosystem: Ecosystem; name: string; reason: string }[];
}

function finding(rule: string, ref: PackageRef, message: string): Finding {
  const r = RULE_BY_ID.get(rule);
  return { rule, severity: r?.severity ?? 'medium', title: r?.title ?? rule, message, item: ref.item.id, file: ref.file, line: ref.line, evidence: ref.command };
}

const REGISTRY_NAME: Record<Ecosystem, string> = { npm: 'npm', pypi: 'PyPI' };

/** Looks up every distinct name once, a few at a time, and turns what it finds into findings. */
export async function checkRegistries(refs: PackageRef[], o: RegistryOptions = {}): Promise<RegistryResult> {
  const now = (o.now ?? new Date()).getTime();
  const keys = [...new Set(refs.map((r) => `${r.ecosystem}:${r.name}`))];
  const results = new Map<string, Lookup>();
  let next = 0;
  const worker = async () => {
    while (next < keys.length) {
      const key = keys[next++] as string;
      const [eco, ...rest] = key.split(':');
      results.set(key, await lookup(eco as Ecosystem, rest.join(':'), o));
    }
  };
  await Promise.all(Array.from({ length: Math.min(o.concurrency ?? 8, keys.length) }, worker));
  const findings: Finding[] = [];
  const failed: RegistryResult['failed'] = [];
  for (const key of keys) {
    const r = results.get(key);
    if (r?.status === 'error') {
      const [eco, ...rest] = key.split(':');
      failed.push({ ecosystem: eco as Ecosystem, name: rest.join(':'), reason: r.reason });
    }
  }
  for (const ref of refs) {
    const r = results.get(`${ref.ecosystem}:${ref.name}`);
    const where = REGISTRY_NAME[ref.ecosystem];
    if (r?.status === 'missing' && r.scopeTaken) {
      const scope = ref.name.slice(0, ref.name.indexOf('/'));
      findings.push({ ...finding('SG901', ref, `\`${ref.name}\` is not on npm. Its scope ${scope} has packages, so only the scope's owner could publish it: this step fails, and the name is most likely made up (check what the project really means).`), severity: 'medium' });
    } else if (r?.status === 'missing') {
      const scoped = ref.name.startsWith('@') ? (r.scopeTaken === false ? ` Nobody owns the scope ${ref.name.slice(0, ref.name.indexOf('/'))} either: it is free to claim.` : ` Whether anyone owns the scope ${ref.name.slice(0, ref.name.indexOf('/'))} could not be checked.`) : '';
      findings.push(finding('SG901', ref, `\`${ref.name}\` is not on ${where}: anyone can register that name, and this install step would then run their code.${scoped}`));
    } else if (r?.status === 'removed') {
      findings.push(finding('SG903', ref, `npm removed \`${ref.name}\` as malicious; only a security placeholder is left under that name.`));
    } else if (r?.status === 'found') {
      const age = r.created ? Math.floor((now - r.created.getTime()) / DAY) : undefined;
      const young = age !== undefined && age >= 0 && age < NEW_DAYS;
      const unused = r.weeklyDownloads !== undefined && r.weeklyDownloads < FEW_DOWNLOADS;
      if (young || unused) {
        const parts = [young ? `first published ${age === 0 ? 'today' : `${age} day${age === 1 ? '' : 's'} ago`}` : '', unused ? `${r.weeklyDownloads} download${r.weeklyDownloads === 1 ? '' : 's'} last week` : ''].filter(Boolean);
        findings.push(finding('SG902', ref, `\`${ref.name}\` on ${where}: ${parts.join(', ')}. A name an AI made up and someone then registered looks like this.`));
      }
    }
  }
  return { findings, checked: keys.length, failed };
}
