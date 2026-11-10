import { basename, dirname, isAbsolute, join, relative, resolve } from 'node:path';
import { parseFrontmatter, parseJsonc, parseToml } from './parse.ts';
import type { Hook, Host, Item, ItemKind, McpServer } from './types.ts';
import { exists, home, isCodeFile, isDir, isObject, isTextFile, listDir, obj, readJson, readText, str, stringRecord, strings, walkFiles, withFsCache } from './util.ts';

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
    const full: Item = { ...item, id: n === 1 ? base : `${base}#${n}` };
    this.items.push(full);
    return full;
  }
}

// ------------------------------------------------------------------ skills

function skillFiles(dir: string): string[] {
  return walkFiles(dir, 5, 400).filter(isTextFile);
}

/** A folder containing SKILL.md (Agent Skills format: Claude Code, Codex, Cursor, ~/.agents, …). */
function addSkill(c: Collector, dir: string, host: Host, parent?: Item): void {
  const skillMd = ['SKILL.md', 'skill.md', 'Skill.md'].map((n) => join(dir, n)).find(exists);
  if (!skillMd) return;
  const r = readText(skillMd);
  const fm = 'text' in r ? parseFrontmatter(r.text).data : {};
  const name = str(fm.name) || basename(dir);
  c.add({
    id: `${host}:skill:${parent ? parent.name + '/' : ''}${name}`,
    kind: 'skill',
    host,
    name,
    path: dir,
    files: skillFiles(dir),
    description: str(fm.description) || undefined,
    parent: parent?.id,
    meta: fm,
  });
}

/** Every SKILL.md folder under `root` (skills can be nested in category folders). */
function addSkillsUnder(c: Collector, root: string, host: Host, parent?: Item, depth = 4): void {
  if (!isDir(root)) return;
  const visit = (dir: string, d: number) => {
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
    // A local server's own source is where tool descriptions (and tool poisoning) live.
    const files = mcp.command ? referencedFiles([mcp.command, ...mcp.args], dirname(configPath), parent?.path) : [];
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
function referencedFiles(command: string | string[], base: string, pluginRoot?: string): string[] {
  const expand = (s: string) =>
    s
      .replace(/\$\{?CLAUDE_PLUGIN_ROOT\}?|\$\{?PLUGIN_ROOT\}?|%CLAUDE_PLUGIN_ROOT%/g, pluginRoot ?? base)
      .replace(/\$\{?CLAUDE_PROJECT_DIR\}?|%CLAUDE_PROJECT_DIR%/g, base)
      .replace(/^~(?=[\\/])/, home());
  const tokens = Array.isArray(command) ? command.map(expand) : [...expand(command).matchAll(/(?:"([^"]+)"|'([^']+)'|(\S+))/g)].map((m) => m[1] ?? m[2] ?? m[3] ?? '');
  const out: string[] = [];
  for (const tok of tokens) {
    if (!/\.(sh|bash|py|js|mjs|cjs|ts|mts|ps1|cmd|bat|rb)$/i.test(tok)) continue;
    // resolve() normalises separators so the path matches what a directory walk returns
    const p = isAbsolute(tok) ? resolve(tok) : resolve(base, tok);
    if (exists(p)) out.push(p);
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

function addSettingsHooks(c: Collector, path: string, host: Host, base: string): void {
  if (!exists(path)) return;
  const j = obj(readJson(path));
  addHooks(c, j.hooks, host, path, base);
}

// ------------------------------------------------------------------ plugins

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
    files: [manifestPath, ...walkFiles(root, 2, 200).filter((f) => isCodeFile(f) && !/[\\/](skills|commands|agents)[\\/]/.test(f))],
    description: str(manifest.description) || undefined,
    meta: manifest,
  });
  if (!plugin) return;
  addSkillsUnder(c, join(root, 'skills'), host, plugin);
  for (const kind of ['commands', 'agents'] as const) {
    const dir = join(root, kind);
    for (const f of walkFiles(dir, 3, 300).filter((p) => /\.md$/i.test(p))) {
      const r = readText(f);
      const fm = 'text' in r ? parseFrontmatter(r.text).data : {};
      const itemKind: ItemKind = kind === 'commands' ? 'command' : 'subagent';
      const n = str(fm.name) || basename(f, '.md');
      c.add({ id: `${host}:${itemKind}:${name}/${n}`, kind: itemKind, host, name: n, path: f, files: [f], description: str(fm.description) || undefined, parent: plugin.id, meta: fm });
    }
  }
  // hooks: hooks/hooks.json, or inline / referenced from the manifest
  const hookFiles = [join(root, 'hooks', 'hooks.json'), ...strings([manifest.hooks]).map((p) => resolve(root, p))];
  for (const hf of hookFiles) if (exists(hf)) addHooks(c, obj(readJson(hf)).hooks, host, hf, root, plugin, root);
  if (isObject(manifest.hooks)) addHooks(c, manifest.hooks, host, manifestPath, root, plugin, root);
  // MCP servers: .mcp.json, or inline in the manifest
  addMcpJson(c, join(root, '.mcp.json'), host, plugin);
  if (isObject(manifest.mcpServers)) addMcpServers(c, manifest.mcpServers, host, manifestPath, plugin);
  else if (typeof manifest.mcpServers === 'string') addMcpJson(c, resolve(root, manifest.mcpServers), host, plugin);
  // Scripts that a hook or MCP server points at are scanned as part of it, not again as part of the plugin.
  const owned = new Set(c.items.filter((i) => i.parent === plugin.id && (i.kind === 'hook' || i.kind === 'mcp-server')).flatMap((i) => i.files));
  plugin.files = plugin.files.filter((f) => !owned.has(f));
}

function addPluginsUnder(c: Collector, root: string, host: Host, depth = 6): void {
  if (!isDir(root)) return;
  const marker = host === 'codex' ? '.codex-plugin' : '.claude-plugin';
  for (const f of walkFiles(root, depth, 20000)) {
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
        files: [join(dir, 'package.json'), ...walkFiles(dir, 4, 300).filter((f) => isCodeFile(f) && !/\.d\.ts$/.test(f) && !/\.map$/.test(f))],
        description: str(pj.description) || undefined,
        meta: { ...pj, profile },
      });
    }
  }
}

// ------------------------------------------------------------------ context files

function addContext(c: Collector, path: string, host: Host): void {
  if (!exists(path)) return;
  c.add({ id: `${host}:context:${basename(path)}`, kind: 'context', host, name: basename(path), path, files: [path], meta: {} });
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
  return withFsCache(() => discoverPathUncached(target));
}

function discoverPathUncached(target: string): Item[] {
  const root = resolve(target);
  const c = new Collector();
  if (!isDir(root)) {
    // A single file: scan it as instructions (SKILL.md, CLAUDE.md, …) or code.
    if (exists(root)) c.add({ kind: /\.md$/i.test(root) ? 'context' : 'plugin', host: 'repo', name: basename(root), path: root, files: [root], meta: {} });
    return c.items;
  }
  const files = walkFiles(root, 8, 20000);
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
  const inPlugin = (f: string) => [...pluginRoots].some((pr) => f.startsWith(pr + '/') || f.startsWith(pr + '\\'));

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
    } else if (/^(CLAUDE|AGENTS|GEMINI)\.md$/i.test(name) || name === '.cursorrules' || /(^|\/)\.cursor\/rules\/.+\.mdc?$/.test(r) || /(^|\/)\.github\/copilot-instructions\.md$/.test(r)) addContext(c, f, 'repo');
    else if (/(^|\/)\.claude\/(commands|agents)\/.+\.md$/.test(r)) {
      const kind: ItemKind = r.includes('/commands/') ? 'command' : 'subagent';
      c.add({ kind, host: 'repo', name: basename(f, '.md'), path: f, files: [f], meta: {} });
    }
  }
  return c.items;
}
