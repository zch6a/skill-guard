import { realpathSync } from 'node:fs';
import { basename, dirname, isAbsolute, join, relative, resolve } from 'node:path';
import { parseFrontmatter, parseJsonc, parseToml } from './parse.ts';
import type { Hook, Host, Item, ItemKind, McpServer } from './types.ts';
import { baseName, exists, hasShebang, home, visible, isCodeFile, isDir, isFile, isObject, isTextFile, listDir, obj, readJson, readText, str, stringRecord, strings, walkFiles, withFsCache } from './util.ts';

/**
 * Discovery: find every skill, plugin, hook, MCP server and always-loaded
 * instruction file that an agent on this machine (or in a repository) would
 * load. Nothing is executed; files are only read.
 */

class Collector {
  readonly items: Item[] = [];
  private readonly ids = new Map<string, number>();
  private readonly seenPaths = new Set<string>();

  add(item: Omit<Item, 'id'> & { id?: string }): Item | null {
    // The same folder can be reachable twice (e.g. a skill symlinked into two agents): scan it once per host.
    const pathKey = `${item.host}|${item.kind}|${item.path}|${item.hook ? JSON.stringify(item.hook) : ''}|${item.kind === 'mcp-server' ? (item.id ?? item.name) : ''}`;
    if (this.seenPaths.has(pathKey)) return null;
    this.seenPaths.add(pathKey);
    const base = item.id ?? `${item.host}:${item.kind}:${item.name}`;
    const n = (this.ids.get(base) ?? 0) + 1;
    this.ids.set(base, n);
    // Names and descriptions come from the scanned files: neutralise control characters once, here.
    const full: Item = { ...item, id: visible(n === 1 ? base : `${base}#${n}`), name: visible(item.name), ...(item.description ? { description: visible(item.description) } : {}) };
    this.items.push(full);
    return full;
  }
}

/**
 * While one folder is scanned (`discoverPath`): the paths that configs, manifests and instructions inside it point
 * at are followed only inside it. Text in the folder is untrusted, and so is a hook command or a plugin.json:
 * without this, `"commands": ["/home/me/notes"]` or a `scripts/run.sh` that links to `~/.ssh/config` made the scanner
 * read a file outside the folder and print its lines in the report (and in SARIF uploaded by CI).
 */
let confineRoot: string | null = null;

function realOf(p: string): string {
  try {
    return realpathSync(p);
  } catch {
    return resolve(p);
  }
}

/** `p` is inside `base`, or is `base`, by real location: a symbolic link out of the tree is out. */
function within(p: string, base: string): boolean {
  const rel = relative(realOf(base), realOf(p));
  return rel === '' || (!rel.startsWith('..') && !isAbsolute(rel));
}

// ------------------------------------------------------------------ skills

/** Text files in a skill, scripts without an extension, and links that leave the folder. */
function skillFiles(dir: string): { files: string[]; outsideLinks: string[] } {
  const outsideLinks: string[] = [];
  const files = walkFiles(dir, { maxDepth: 5, maxFiles: 400, filter: (f) => isTextFile(f) || hasShebang(f), onOutsideLink: (l) => outsideLinks.push(l) });
  return { files, outsideLinks };
}

/** A folder containing SKILL.md (Agent Skills format: Claude Code, Codex, Cursor, ~/.agents, …). */
function addSkill(c: Collector, dir: string, host: Host, parent?: Item): void {
  const skillMd = ['SKILL.md', 'skill.md', 'Skill.md'].map((n) => join(dir, n)).find(exists);
  if (!skillMd) return;
  const r = readText(skillMd);
  const fm = 'text' in r ? parseFrontmatter(r.text).data : {};
  const name = str(fm.name) || basename(dir);
  const { files, outsideLinks } = skillFiles(dir);
  // Scripts SKILL.md tells the agent to run, even where the walk does not go (node_modules/, .venv/).
  const mentioned = scriptsMentioned(skillMd, dir);
  // Files SKILL.md names (`spec/usage.md`, [guide](docs/guide.md)): what the agent is told to read or run is
  // never "just a test file", whatever folder it is in.
  const body = 'text' in r ? r.text.replace(/\\/g, '/') : '';
  const named = files.filter((f) => {
    const rel = relative(dir, f).replace(/\\/g, '/');
    return rel.includes('/') && body.includes(rel);
  });
  c.add({
    id: `${host}:skill:${parent ? parent.name + '/' : ''}${name}`,
    kind: 'skill',
    host,
    name,
    path: dir,
    files: [...new Set([...files, ...mentioned])],
    mentioned: [...new Set([...mentioned, ...named])],
    ...(outsideLinks.length ? { outsideLinks } : {}),
    description: str(fm.description) || undefined,
    parent: parent?.id,
    meta: fm,
  });
}

/** Every SKILL.md folder under `root` (skills can be nested in category folders). */
function addSkillsUnder(c: Collector, root: string, host: Host, parent?: Item, depth = 4): void {
  if (!isDir(root)) return;
  const visit = (dir: string, d: number) => {
    // In a folder scan, a skills folder (or a skill) linked in from outside it is not part of it.
    if (confineRoot && !within(dir, confineRoot)) return;
    if (['SKILL.md', 'skill.md', 'Skill.md'].some((n) => exists(join(dir, n)))) {
      addSkill(c, dir, host, parent);
      return;
    }
    if (d >= depth) return;
    for (const name of listDir(dir)) {
      if (name === 'node_modules' || name.startsWith('.git')) continue;
      const p = join(dir, name);
      if (isDir(p)) visit(p, d + 1);
    }
  };
  visit(root, 0);
}

// ------------------------------------------------------------------ MCP

export function normalizeMcp(def: unknown): McpServer {
  const d = obj(def);
  // OpenCode: { type: 'local', command: ['npx', 'x'] } / { type: 'remote', url }
  let command = str(d.command);
  let args = strings(d.args);
  if (Array.isArray(d.command)) {
    const parts = strings(d.command);
    command = parts[0] ?? '';
    args = parts.slice(1);
  }
  const url = str(d.url) || str(d.serverUrl) || str(d.httpUrl) || str(d.endpoint);
  const type = str(d.type) || str(d.transport);
  const transport: McpServer['transport'] = /sse/i.test(type) ? 'sse' : url || /http|remote|streamable/i.test(type) ? 'http' : command ? 'stdio' : 'unknown';
  const env = { ...stringRecord(d.env), ...stringRecord(d.environment) };
  // Codex: env_vars = ["NAME"] forwards variables from the parent environment.
  for (const name of strings(d.env_vars)) if (!(name in env)) env[name] = '${' + name + '}';
  const server: McpServer = { transport, args, env, headers: { ...stringRecord(d.headers), ...stringRecord(d.http_headers) } };
  if (command) server.command = command;
  if (url) server.url = url;
  if (d.disabled === true || d.enabled === false) server.disabled = true;
  return server;
}

/**
 * `project`: for servers scoped to one project in ~/.claude.json (`projects["<path>"].mcpServers`).
 * The project goes into the id so the same server name in two projects gets two stable ids.
 */
function addMcpServers(c: Collector, servers: unknown, host: Host, configPath: string, parent?: Item, project?: string): void {
  for (const [name, def] of Object.entries(obj(servers))) {
    if (!isObject(def)) continue;
    const mcp = normalizeMcp(def);
    // A local server's own source is where tool descriptions (and tool poisoning) live — including
    // the modules it imports (tools are often defined in a separate file).
    const entries = mcp.command ? referencedFiles([mcp.command, ...mcp.args], dirname(configPath), parent?.path) : [];
    const files = [...new Set(entries.flatMap((e) => localImports(e)))];
    c.add({
      id: `${host}:mcp-server:${parent ? parent.name + '/' : ''}${name}${project ? `@${project.replace(/\\/g, '/')}` : ''}`,
      kind: 'mcp-server',
      host,
      // "db (work/app)": the last two folders tell projects apart without the full path.
      name: project ? `${name} (${project.replace(/\\/g, '/').replace(/\/+$/, '').split('/').slice(-2).join('/') || project})` : name,
      path: configPath,
      files,
      parent: parent?.id,
      mcp,
      meta: project ? { ...def, project } : def,
    });
  }
}

function addMcpJson(c: Collector, path: string, host: Host, parent?: Item): void {
  if (!exists(path)) return;
  const r = readText(path);
  if (!('text' in r)) return;
  const j = obj(parseJsonc(r.text));
  // .mcp.json / claude_desktop_config.json: { mcpServers }; VS Code mcp.json: { servers }; Cursor: { mcpServers }
  addMcpServers(c, j.mcpServers ?? j.servers ?? (j.mcp && obj(j.mcp).servers), host, path, parent);
}

// ------------------------------------------------------------------ hooks

/**
 * Script files a hook command or MCP server points at, so their contents get scanned too.
 * A string is split like a shell would; an array (MCP `command` + `args`) is used token by token.
 */
const JS_IMPORT = /(?:\bfrom\s*|\bimport\s*\(\s*|\brequire\s*\(\s*|^\s*import\s+)['"](\.{1,2}\/[^'"\n]{1,200})['"]/gm;
const PY_IMPORT = /^\s*from\s+(\.*)([\w.]{0,100})\s+import\b|^\s*import\s+([\w.]{1,100})/gm;

/**
 * `entry` plus the local modules it imports, transitively (relative JS/TS imports, Python
 * relative imports and sibling modules). Bounded, and never outside the entry's folder tree.
 */
function localImports(entry: string, limit = 50): string[] {
  const root = dirname(entry);
  const seen = new Set<string>([entry]);
  const queue = [entry];
  const add = (p: string) => {
    const r = relative(root, p);
    if (r.startsWith('..') || isAbsolute(r) || seen.has(p) || seen.size >= limit || !isFile(p)) return;
    seen.add(p);
    queue.push(p);
  };
  while (queue.length) {
    const f = queue.shift() as string;
    const r = readText(f);
    if (!('text' in r)) continue;
    const dir = dirname(f);
    if (/\.(py|pyw)$/i.test(f)) {
      for (const m of r.text.matchAll(PY_IMPORT)) {
        const dots = m[1] ?? '';
        const mod = (m[2] || m[3] || '').replace(/\./g, '/');
        if (!mod) continue;
        const base = dots.length > 1 ? resolve(dir, '../'.repeat(dots.length - 1)) : dir;
        for (const cand of [join(base, `${mod}.py`), join(base, mod, '__init__.py')]) add(cand);
      }
    } else {
      for (const m of r.text.matchAll(JS_IMPORT)) {
        const spec = resolve(dir, m[1] as string);
        for (const cand of [spec, ...['.js', '.mjs', '.cjs', '.ts', '.mts', '.tsx', '.jsx'].map((e) => spec + e), ...['index.js', 'index.ts', 'index.mjs'].map((i) => join(spec, i)), spec.replace(/\.js$/, '.ts')]) add(cand);
      }
    }
  }
  return [...seen];
}

/**
 * Split a command line like a shell does for words: quotes group and are removed, and a quoted
 * part joins whatever touches it — `"$CLAUDE_PROJECT_DIR"/.claude/hooks/x.sh` is one word.
 */
export function shellWords(s: string): string[] {
  const out: string[] = [];
  let cur = '';
  let quote: string | null = null;
  let has = false;
  for (const ch of s) {
    if (quote) {
      if (ch === quote) quote = null;
      else cur += ch;
    } else if (ch === '"' || ch === "'") {
      quote = ch;
      has = true;
    } else if (/\s/.test(ch)) {
      if (has || cur) out.push(cur);
      cur = '';
      has = false;
    } else cur += ch;
  }
  if (has || cur) out.push(cur);
  return out;
}

const SCRIPT_EXT = /\.(sh|bash|zsh|fish|py|pyw|js|mjs|cjs|ts|mts|cts|ps1|psm1|cmd|bat|vbs|vbe|wsf|rb|pl|php|lua)$/i;
/** A file given to one of these is a script whatever its name: `bash scripts/install.conf`, `python tools/setup`. */
const INTERPRETER = /^(sudo|bash|sh|zsh|dash|ksh|fish|source|\.|python[0-9.]*|py|node|deno|bun|ruby|perl|php|lua|pwsh|powershell|cscript|wscript)(\.exe)?$/i;

function referencedFiles(command: string | string[], base: string, pluginRoot?: string): string[] {
  const expand = (s: string) =>
    s
      .replace(/\$\{?CLAUDE_PLUGIN_ROOT\}?|\$\{?PLUGIN_ROOT\}?|%CLAUDE_PLUGIN_ROOT%/g, pluginRoot ?? base)
      .replace(/\$\{?CLAUDE_PROJECT_DIR\}?|%CLAUDE_PROJECT_DIR%/g, base)
      .replace(/^~(?=[\\/])/, home());
  const tokens = Array.isArray(command) ? command.map(expand) : shellWords(expand(command));
  const out: string[] = [];
  let runner = false;
  for (const tok of tokens) {
    if (!tok) continue;
    if (tok.startsWith('-')) continue;
    const byInterpreter = runner;
    runner = INTERPRETER.test(baseName(tok));
    // resolve() normalises separators so the path matches what a directory walk returns
    const p = isAbsolute(tok) ? resolve(tok) : resolve(base, tok);
    if (confineRoot && !within(p, confineRoot)) continue;
    // A script by extension, a file given to an interpreter, or an extensionless file with a shebang (`./bin/setup`).
    // Regular files only: a device such as `/dev/stdin` exists, is no folder, and blocks a read forever.
    if (isFile(p) && (SCRIPT_EXT.test(tok) || (byInterpreter && /[\\/.]/.test(tok)) || (/[\\/]/.test(tok) && hasShebang(p)))) out.push(p);
  }
  return [...new Set(out)];
}

function addHooks(c: Collector, hooks: unknown, host: Host, configPath: string, base: string, parent?: Item, pluginRoot?: string): void {
  for (const [event, groups] of Object.entries(obj(hooks))) {
    if (!Array.isArray(groups)) continue;
    groups.forEach((g) => {
      const group = obj(g);
      const list = Array.isArray(group.hooks) ? group.hooks : [group];
      for (const h of list) {
        const hd = obj(h);
        const hook: Hook = { event, type: str(hd.type) || 'command' };
        if (str(group.matcher)) hook.matcher = str(group.matcher);
        if (str(hd.command)) hook.command = str(hd.command);
        if (str(hd.prompt)) hook.prompt = str(hd.prompt);
        if (!hook.command && hook.type === 'command') continue;
        const label = hook.command ? hook.command.replace(/\s+/g, ' ').slice(0, 48) : hook.type;
        c.add({
          id: `${host}:hook:${parent ? parent.name + '/' : ''}${event}`,
          kind: 'hook',
          host,
          name: `${event}${hook.matcher ? ` [${hook.matcher}]` : ''}: ${label}`,
          path: configPath,
          files: hook.command ? referencedFiles(hook.command, base, pluginRoot) : [],
          parent: parent?.id,
          hook,
          meta: hd,
        });
      }
    });
  }
}

/** Settings keys whose value is a shell command the agent runs by itself. */
const SETTINGS_COMMANDS = ['apiKeyHelper', 'awsAuthRefresh', 'awsCredentialExport', 'otelHeadersHelper'];

/**
 * Claude Code settings.json: hooks, plus everything else in it that runs code or changes what
 * the agent may do — status-line and credential-helper commands, permission rules, env.
 */
function addSettingsHooks(c: Collector, path: string, host: Host, base: string): void {
  if (!exists(path)) return;
  const r = readText(path);
  const j = obj('text' in r ? parseJsonc(r.text) : undefined);
  addHooks(c, j.hooks, host, path, base);
  // Commands that run without being asked: model them as hooks so their scripts are scanned too.
  const commands: [string, string][] = [];
  const status = obj(j.statusLine);
  if (str(status.command)) commands.push(['statusLine', str(status.command)]);
  for (const k of SETTINGS_COMMANDS) if (str(j[k])) commands.push([k, str(j[k])]);
  for (const [event, command] of commands)
    c.add({ id: `${host}:hook:${event}`, kind: 'hook', host, name: `${event}: ${command.replace(/\s+/g, ' ').slice(0, 48)}`, path, files: referencedFiles(command, base), hook: { event, type: 'command', command }, meta: {} });
  // The settings themselves (permissions, env, MCP auto-approval) are checked structurally.
  if (j.permissions !== undefined || j.env !== undefined || j.enableAllProjectMcpServers !== undefined || j.defaultMode !== undefined)
    c.add({ id: `${host}:settings:${relative(base, path).replace(/\\/g, '/') || basename(path)}`, kind: 'settings', host, name: basename(path), path, files: [], meta: j });
}

// ------------------------------------------------------------------ plugins

/** `"commands": "./custom"` or `["./a.md", "./more"]` in a plugin manifest, resolved against the plugin root. */
function manifestPaths(v: unknown, root: string): string[] {
  // Only inside the plugin, by real location: a manifest is untrusted text, and agents resolve these against the root.
  return strings(Array.isArray(v) ? v : [v])
    .map((p) => resolve(root, p))
    .filter((p) => within(p, root));
}

/** A Claude Code (`.claude-plugin/plugin.json`) or Codex (`.codex-plugin/plugin.json`) plugin and everything inside it. */
function addPlugin(c: Collector, root: string, host: Host, manifestPath: string): void {
  const manifest = obj(readJson(manifestPath));
  const name = str(manifest.name) || basename(root);
  const plugin = c.add({
    id: `${host}:plugin:${name}`,
    kind: 'plugin',
    host,
    name,
    path: root,
    // The plugin's own files: manifest plus top-level scripts (skills, commands etc. are separate items).
    files: [manifestPath, ...walkFiles(root, { maxDepth: 2, maxFiles: 200, filter: (f) => (isCodeFile(f) || hasShebang(f)) && !/[\\/](skills|commands|agents)[\\/]/.test(f) })],
    description: str(manifest.description) || undefined,
    meta: manifest,
  });
  if (!plugin) return;
  addSkillsUnder(c, join(root, 'skills'), host, plugin);
  for (const p of manifestPaths(manifest.skills, root)) addSkillsUnder(c, p, host, plugin);
  for (const kind of ['commands', 'agents'] as const) {
    // The default folder plus any custom paths (files or folders) the manifest declares.
    const mds = new Set<string>();
    for (const dir of [join(root, kind), ...manifestPaths(manifest[kind], root)]) {
      if (isDir(dir)) for (const f of walkFiles(dir, { maxDepth: 3, maxFiles: 300, filter: (p) => /\.md$/i.test(p) })) mds.add(f);
      else if (/\.md$/i.test(dir) && exists(dir)) mds.add(dir);
    }
    for (const f of mds) {
      const r = readText(f);
      const fm = 'text' in r ? parseFrontmatter(r.text).data : {};
      const itemKind: ItemKind = kind === 'commands' ? 'command' : 'subagent';
      const n = str(fm.name) || basename(f, '.md');
      c.add({ id: `${host}:${itemKind}:${name}/${n}`, kind: itemKind, host, name: n, path: f, files: [f, ...scriptsMentioned(f, root)], description: str(fm.description) || undefined, parent: plugin.id, meta: fm });
    }
  }
  // hooks: hooks/hooks.json, or inline / referenced from the manifest
  const hookFiles = [join(root, 'hooks', 'hooks.json'), ...manifestPaths(typeof manifest.hooks === 'string' ? manifest.hooks : [], root)];
  for (const hf of hookFiles) if (exists(hf)) addHooks(c, obj(readJson(hf)).hooks, host, hf, root, plugin, root);
  if (isObject(manifest.hooks)) addHooks(c, manifest.hooks, host, manifestPath, root, plugin, root);
  // MCP servers: .mcp.json, or inline in the manifest
  addMcpJson(c, join(root, '.mcp.json'), host, plugin);
  if (isObject(manifest.mcpServers)) addMcpServers(c, manifest.mcpServers, host, manifestPath, plugin);
  else if (typeof manifest.mcpServers === 'string') for (const p of manifestPaths(manifest.mcpServers, root)) addMcpJson(c, p, host, plugin);
  // Scripts that a hook or MCP server points at are scanned as part of it, not again as part of the plugin.
  const owned = new Set(c.items.filter((i) => i.parent === plugin.id && (i.kind === 'hook' || i.kind === 'mcp-server')).flatMap((i) => i.files));
  plugin.files = plugin.files.filter((f) => !owned.has(f));
}

function addPluginsUnder(c: Collector, root: string, host: Host, depth = 6): void {
  if (!isDir(root)) return;
  const marker = host === 'codex' ? '.codex-plugin' : '.claude-plugin';
  for (const f of walkFiles(root, depth, 20000, 'repo')) {
    if (basename(f) !== 'plugin.json' || basename(dirname(f)) !== marker) continue;
    addPlugin(c, dirname(dirname(f)), host, f);
  }
}

// ------------------------------------------------------------------ DeepSeek Harness

/** DeepSeek Harness plugins are npm packages with a `dsh` field, installed into `~/.dsh/profiles/<profile>`. */
function addDshPlugins(c: Collector, dshHome: string): void {
  for (const profile of listDir(join(dshHome, 'profiles'))) {
    const pdir = join(dshHome, 'profiles', profile);
    const pkg = obj(readJson(join(pdir, 'package.json')));
    for (const dep of Object.keys({ ...obj(pkg.dependencies), ...obj(pkg.devDependencies) })) {
      const dir = join(pdir, 'node_modules', dep);
      const pj = obj(readJson(join(dir, 'package.json')));
      if (!Object.keys(pj).length) continue;
      c.add({
        id: `deepseek-harness:dsh-plugin:${dep}`,
        kind: 'dsh-plugin',
        host: 'deepseek-harness',
        name: dep,
        path: dir,
        files: [join(dir, 'package.json'), ...walkFiles(dir, { maxDepth: 4, maxFiles: 300, filter: (f) => isCodeFile(f) && !/\.d\.ts$/.test(f) && !/\.map$/.test(f) })],
        description: str(pj.description) || undefined,
        meta: { ...pj, profile },
      });
    }
  }
}

// ------------------------------------------------------------------ context files

function addContext(c: Collector, path: string, host: Host, root?: string): void {
  if (!exists(path)) return;
  c.add({ id: `${host}:context:${basename(path)}`, kind: 'context', host, name: basename(path), path, files: [path, ...scriptsMentioned(path, root)], meta: {} });
}

/**
 * Local scripts that a Markdown instruction file tells the agent to run (`bash scripts/setup.sh`
 * in backticks). A poisoned CLAUDE.md does not need to contain the payload — only to point at it.
 */
function scriptsMentioned(md: string, root?: string): string[] {
  const r = readText(md);
  if (!('text' in r)) return [];
  const bases = [...new Set([dirname(md), root].filter((b): b is string => !!b))];
  // Text in a file being checked is untrusted: a path it mentions is followed only inside the file's own folder tree
  // (or the scan root), so `/etc/passwd` or `~/.ssh/config` in backticks never makes the scanner read it.
  // By real location: `scripts/run.sh` that is a link to a file elsewhere is not inside.
  const inside = (f: string) => bases.some((b) => within(f, b) && realOf(f) !== realOf(b));
  const out = new Set<string>();
  for (const m of r.text.matchAll(/`([^`\n]{1,300})`|^\s*(?:\$\s+)?((?:bash|sh|zsh|python3?|node|pwsh|powershell|\.\/)[^\n]{0,300})$/gm)) {
    const span = m[1] ?? m[2] ?? '';
    for (const base of bases) for (const f of referencedFiles(span, base)) if (inside(f)) out.add(f);
  }
  out.delete(resolve(md));
  return [...out];
}

// ------------------------------------------------------------------ entry points

export interface DiscoverOptions {
  /** Only these hosts (machine scan). */
  hosts?: Host[];
}

function appData(): string {
  if (process.env.APPDATA) return process.env.APPDATA;
  return process.platform === 'darwin' ? join(home(), 'Library', 'Application Support') : process.env.XDG_CONFIG_HOME || join(home(), '.config');
}

/** Everything installed for the current user, across every supported agent. */
export function discoverMachine(opts: DiscoverOptions = {}): Item[] {
  return withFsCache(() => discoverMachineUncached(opts));
}

function discoverMachineUncached(opts: DiscoverOptions): Item[] {
  const c = new Collector();
  const want = (h: Host) => !opts.hosts?.length || opts.hosts.includes(h);
  const H = home();

  if (want('claude-code')) {
    const claudeHome = process.env.CLAUDE_CONFIG_DIR || join(H, '.claude');
    addSkillsUnder(c, join(claudeHome, 'skills'), 'claude-code');
    addPluginsUnder(c, join(claudeHome, 'plugins'), 'claude-code');
    for (const kind of ['commands', 'agents'] as const) {
      for (const f of walkFiles(join(claudeHome, kind), 3, 300).filter((p) => /\.md$/i.test(p))) {
        const itemKind: ItemKind = kind === 'commands' ? 'command' : 'subagent';
        c.add({ kind: itemKind, host: 'claude-code', name: basename(f, '.md'), path: f, files: [f], meta: {} });
      }
    }
    addSettingsHooks(c, join(claudeHome, 'settings.json'), 'claude-code', H);
    addSettingsHooks(c, join(claudeHome, 'settings.local.json'), 'claude-code', H);
    const claudeJson = obj(readJson(join(H, '.claude.json')));
    addMcpServers(c, claudeJson.mcpServers, 'claude-code', join(H, '.claude.json'));
    for (const [proj, cfg] of Object.entries(obj(claudeJson.projects))) {
      const servers = obj(obj(cfg).mcpServers);
      if (Object.keys(servers).length) addMcpServers(c, servers, 'claude-code', join(H, '.claude.json'), undefined, proj);
    }
    addContext(c, join(claudeHome, 'CLAUDE.md'), 'claude-code');
  }

  if (want('codex')) {
    const codexHome = process.env.CODEX_HOME || join(H, '.codex');
    addSkillsUnder(c, join(codexHome, 'skills'), 'codex');
    addPluginsUnder(c, join(codexHome, 'plugins'), 'codex', 7);
    const cfgPath = join(codexHome, 'config.toml');
    const r = exists(cfgPath) ? readText(cfgPath) : null;
    if (r && 'text' in r) addMcpServers(c, obj(parseToml(r.text)).mcp_servers, 'codex', cfgPath);
    addContext(c, join(codexHome, 'AGENTS.md'), 'codex');
  }

  if (want('agents')) addSkillsUnder(c, join(H, '.agents', 'skills'), 'agents');

  if (want('cursor')) {
    addSkillsUnder(c, join(H, '.cursor', 'skills'), 'cursor');
    addSkillsUnder(c, join(H, '.cursor', 'skills-cursor'), 'cursor');
    addMcpJson(c, join(H, '.cursor', 'mcp.json'), 'cursor');
  }

  if (want('opencode')) {
    const ocHome = join(process.env.XDG_CONFIG_HOME || join(H, '.config'), 'opencode');
    for (const f of ['opencode.json', 'opencode.jsonc', 'config.json']) {
      const p = join(ocHome, f);
      const r = exists(p) ? readText(p) : null;
      if (r && 'text' in r) addMcpServers(c, obj(parseJsonc(r.text)).mcp, 'opencode', p);
    }
    for (const dir of ['plugin', 'plugins']) {
      for (const f of walkFiles(join(ocHome, dir), 2, 200).filter(isCodeFile)) c.add({ kind: 'plugin', host: 'opencode', name: basename(f), path: f, files: [f], meta: {} });
    }
    for (const kind of ['agent', 'command'] as const) {
      for (const f of walkFiles(join(ocHome, kind), 2, 200).filter((p) => /\.md$/i.test(p))) {
        c.add({ kind: kind === 'agent' ? 'subagent' : 'command', host: 'opencode', name: basename(f, '.md'), path: f, files: [f], meta: {} });
      }
    }
    addSkillsUnder(c, join(ocHome, 'skill'), 'opencode');
    addSkillsUnder(c, join(ocHome, 'skills'), 'opencode');
    addContext(c, join(ocHome, 'AGENTS.md'), 'opencode');
  }

  if (want('deepseek-harness')) addDshPlugins(c, process.env.DSH_HOME || join(H, '.dsh'));

  if (want('claude-desktop')) addMcpJson(c, join(appData(), 'Claude', 'claude_desktop_config.json'), 'claude-desktop');

  if (want('vscode')) {
    addMcpJson(c, join(appData(), 'Code', 'User', 'mcp.json'), 'vscode');
    const settings = join(appData(), 'Code', 'User', 'settings.json');
    const r = exists(settings) ? readText(settings) : null;
    if (r && 'text' in r) addMcpServers(c, obj(obj(parseJsonc(r.text)).mcp).servers, 'vscode', settings);
  }

  return c.items;
}

/**
 * Everything an agent would pick up from one folder: a repository you are
 * about to open, a skill you are about to install, or a plugin checkout.
 */
export function discoverPath(target: string): Item[] {
  const saved = confineRoot;
  confineRoot = resolve(target);
  try {
    return withFsCache(() => discoverPathUncached(target));
  } finally {
    confineRoot = saved;
  }
}

/** Instruction files agents load into every conversation in a repository. */
const CONTEXT_FILE = /^(CLAUDE|CLAUDE\.local|AGENTS|GEMINI)\.md$|^\.(cursorrules|windsurfrules|clinerules)$/i;
const CONTEXT_PATH = /(^|\/)\.(cursor|windsurf)\/rules\/.+\.mdc?$|(^|\/)\.clinerules\/.+\.md$|(^|\/)\.github\/(copilot-instructions\.md|instructions\/.+\.instructions\.md)$/;
/** File names that can be, or define, an item in a repository. */
const DISCOVERY_NAME = /^(skill\.md|plugin\.json|\.mcp\.json|mcp\.json|claude_desktop_config\.json|settings(\.local)?\.json|config\.toml|opencode\.jsonc?|(CLAUDE|CLAUDE\.local|AGENTS|GEMINI)\.md|\.(cursorrules|windsurfrules|clinerules))$|\.(md|mdc)$/i;

function discoverPathUncached(target: string): Item[] {
  const root = resolve(target);
  const c = new Collector();
  if (!isDir(root)) {
    // A single file: scan it as instructions (SKILL.md, CLAUDE.md, …) or code.
    if (exists(root)) c.add({ kind: /\.md$/i.test(root) ? 'context' : 'plugin', host: 'repo', name: basename(root), path: root, files: [root], meta: {} });
    return c.items;
  }
  // Only names that can be (or define) an item count toward the cap, so padding with other files cannot push them out.
  const files = walkFiles(root, { maxDepth: 8, maxFiles: 20000, mode: 'repo', filter: (f) => DISCOVERY_NAME.test(basename(f)) });
  const rel = (f: string) => relative(root, f).replace(/\\/g, '/');

  // plugins first, so their skills/hooks/MCP servers are attributed to them
  const pluginRoots = new Set<string>();
  for (const f of files) {
    const marker = basename(dirname(f));
    if (basename(f) === 'plugin.json' && (marker === '.claude-plugin' || marker === '.codex-plugin')) {
      const pr = dirname(dirname(f));
      pluginRoots.add(pr);
      addPlugin(c, pr, 'repo', f);
    }
  }
  // A plugin owns its manifest, skills, commands, agents, hooks and .mcp.json — not everything under its
  // folder: a plugin.json at a repository's root must not hide that repository's CLAUDE.md or settings.
  const PLUGIN_OWNED = /^(\.claude-plugin|\.codex-plugin|skills|commands|agents|hooks)(\/|$)|^\.mcp\.json$/;
  const inPlugin = (f: string) => [...pluginRoots].some((pr) => {
    const r = relative(pr, f).replace(/\\/g, '/');
    return !r.startsWith('..') && !isAbsolute(r) && PLUGIN_OWNED.test(r);
  });

  for (const f of files) {
    if (inPlugin(f)) continue;
    const name = basename(f);
    const r = rel(f);
    if (/^skill\.md$/i.test(name)) addSkill(c, dirname(f), 'repo');
    else if (name === '.mcp.json' || /(^|\/)\.(cursor|vscode)\/mcp\.json$/.test(r) || name === 'claude_desktop_config.json') addMcpJson(c, f, 'repo');
    else if (/(^|\/)\.claude\/settings(\.local)?\.json$/.test(r)) addSettingsHooks(c, f, 'repo', root);
    else if (/(^|\/)\.codex\/config\.toml$/.test(r)) {
      const t = readText(f);
      if ('text' in t) addMcpServers(c, obj(parseToml(t.text)).mcp_servers, 'repo', f);
    } else if (/^opencode\.jsonc?$/.test(name)) {
      const t = readText(f);
      if ('text' in t) addMcpServers(c, obj(parseJsonc(t.text)).mcp, 'repo', f);
    } else if (CONTEXT_FILE.test(name) || CONTEXT_PATH.test(r)) addContext(c, f, 'repo', root);
    else if (/(^|\/)\.claude\/(commands|agents)\/.+\.md$/.test(r)) {
      const kind: ItemKind = r.includes('/commands/') ? 'command' : 'subagent';
      c.add({ kind, host: 'repo', name: basename(f, '.md'), path: f, files: [f, ...scriptsMentioned(f, root)], meta: {} });
    }
  }
  // Test-path detection starts at the scanned folder: a repository's tests/fixtures are tests, but the
  // folder the repository happens to be cloned into (~/test/…) is not.
  for (const i of c.items) i.scanRoot = root;
  return c.items;
}
