/** Rules that look at structure rather than text: hooks, package.json lifecycle scripts, skill metadata, binaries. */
import type { Finding, Item } from '../types.ts';
import { RULE_BY_ID } from './catalog.ts';
import { maskSecrets } from '../util.ts';
import { talksToNetwork } from './text.ts';

export function scanHook(item: Item): Finding[] {
  const out: Finding[] = [];
  const h = item.hook;
  if (!h) return out;
  const r701 = RULE_BY_ID.get('SG701')!;
  out.push({
    rule: 'SG701',
    severity: 'info',
    title: r701.title,
    message: `Runs on ${h.event}${h.matcher ? ` for ${h.matcher}` : ''}.`,
    item: item.id,
    file: item.path,
    ...(h.command ? { evidence: maskSecrets(h.command.slice(0, 200)) } : {}),
  });
  if (h.command && talksToNetwork(h.command)) {
    const r = RULE_BY_ID.get('SG702')!;
    out.push({ rule: 'SG702', severity: 'medium', title: r.title, message: `The ${h.event} hook contacts the network.`, item: item.id, file: item.path, evidence: maskSecrets(h.command.slice(0, 200)) });
  }
  return out;
}

const LIFECYCLE = ['preinstall', 'install', 'postinstall', 'prepare', 'preprepare', 'postprepare'];

export function scanPackageJson(item: Item, file: string, pkg: Record<string, unknown>): Finding[] {
  const out: Finding[] = [];
  const scripts = pkg.scripts && typeof pkg.scripts === 'object' ? (pkg.scripts as Record<string, unknown>) : {};
  for (const name of LIFECYCLE) {
    const cmd = typeof scripts[name] === 'string' ? (scripts[name] as string) : '';
    if (!cmd) continue;
    // `prepare: tsc` / husky are routine for developers; only flag when the script does more than build.
    const routine = /^(tsc|tsdown|tsup|unbuild|vite build|rollup|esbuild|bun run build|bun build|husky( install)?|(npm|pnpm|yarn) (run )?build|node-gyp rebuild|patch-package|ts-patch install|simple-git-hooks|lefthook install)\b/.test(cmd.trim()) && !talksToNetwork(cmd);
    if (routine && name === 'prepare') continue;
    const r = RULE_BY_ID.get('SG801')!;
    out.push({ rule: 'SG801', severity: talksToNetwork(cmd) ? 'high' : 'medium', title: r.title, message: `"${name}" runs \`${cmd.slice(0, 80)}\` at install time.`, item: item.id, file, evidence: `${name}: ${maskSecrets(cmd.slice(0, 200))}` });
  }
  return out;
}

export function scanSkillMeta(item: Item, skillMd: string): Finding[] {
  const out: Finding[] = [];
  const tools = item.meta['allowed-tools'] ?? item.meta.tools;
  const list = Array.isArray(tools) ? tools.map(String) : typeof tools === 'string' ? tools.split(/[,\s]+(?![^(]*\))/) : [];
  const broad = list.find((t) => /^(Bash|Shell|PowerShell|run_shell_command|exec|\*)$/i.test(t.trim()) || /^(Bash|Shell)\(\s*\*\s*\)$/i.test(t.trim()));
  if (broad) {
    const r = RULE_BY_ID.get('SG803')!;
    out.push({ rule: 'SG803', severity: 'low', title: r.title, message: `allowed-tools includes "${broad.trim()}".`, item: item.id, file: skillMd });
  }
  return out;
}

const BROAD_ALLOW = /^(Bash|Shell|PowerShell)(\(\s*\*?\s*\))?$|^\*$|^Bash\(\s*(curl|wget|sh|bash|zsh|python3?|node|sudo|rm|chmod|eval|iwr|irm)\b[^)]*\*\s*\)$/i;
const LOCAL_URL = /^https?:\/\/(localhost|127\.\d+\.\d+\.\d+|\[::1\]|0\.0\.0\.0)(:|\/|$)/i;
const SECRET_KEY = /(KEY|TOKEN|SECRET|PASSWORD|PASS|AUTH|CREDENTIAL)/i;

/**
 * Claude Code settings: permission rules, API redirection and MCP auto-approval. A repository's
 * settings come with a clone and get full severity; your own user settings are your choice.
 */
export function scanSettings(item: Item): Finding[] {
  const out: Finding[] = [];
  const m = item.meta;
  const own = item.host !== 'repo';
  const push = (rule: string, sev: 'high' | 'medium' | 'low', message: string, evidence?: string) => {
    const r = RULE_BY_ID.get(rule)!;
    const severity = own ? (sev === 'high' ? 'low' : 'info') : sev;
    out.push({ rule, severity, title: r.title, message: own ? `${message} (your user settings)` : message, item: item.id, file: item.path, ...(evidence ? { evidence: maskSecrets(evidence) } : {}) });
  };
  const perms = m.permissions && typeof m.permissions === 'object' ? (m.permissions as Record<string, unknown>) : {};
  const mode = String(perms.defaultMode ?? m.defaultMode ?? '');
  if (/^bypassPermissions$/i.test(mode)) push('SG108', 'high', 'Sets the default permission mode to bypassPermissions: no approval prompts.', `defaultMode: ${mode}`);
  const allow = Array.isArray(perms.allow) ? perms.allow.map(String) : [];
  const broad = allow.filter((a) => BROAD_ALLOW.test(a.trim()));
  if (broad.length) push('SG404', 'high', `Pre-approves ${broad.map((b) => `"${b}"`).join(', ')} — commands run without asking.`, `permissions.allow: ${broad.join(', ')}`);
  if (m.enableAllProjectMcpServers === true) push('SG404', 'medium', 'Auto-approves every MCP server the project defines.', 'enableAllProjectMcpServers: true');
  const env = m.env && typeof m.env === 'object' ? (m.env as Record<string, unknown>) : {};
  for (const [k, raw] of Object.entries(env)) {
    const v = String(raw ?? '');
    if (/(_BASE_URL|_API_URL|_ENDPOINT|^HTTPS?_PROXY|^ALL_PROXY)$/i.test(k) && /^https?:\/\//i.test(v) && !LOCAL_URL.test(v)) push('SG404', 'high', `Sends the agent's API traffic through ${k}=${v.slice(0, 80)}.`, `env.${k} = ${v}`);
    else if (SECRET_KEY.test(k) && v.length >= 16 && !/^\$\{?\w+\}?$/.test(v)) push('SG603', 'medium', `A credential is written in plain text (env ${k}).`, `env.${k} = ${v}`);
  }
  return out;
}

/** Symbolic links that leave the item (not followed during the scan). */
export function scanOutsideLinks(item: Item): Finding[] {
  const r = RULE_BY_ID.get('SG804')!;
  const links = item.outsideLinks ?? [];
  return [{ rule: 'SG804', severity: 'medium', title: r.title, message: `${links.length} link${links.length > 1 ? 's' : ''} point${links.length > 1 ? '' : 's'} outside the item and ${links.length > 1 ? 'were' : 'was'} not scanned.`, item: item.id, file: links[0] as string, evidence: links.slice(0, 3).join(', ') }];
}

const BINARY_EXT =/\.(exe|dll|so|dylib|bin|node|msi|scr|com|jar|wasm|pyd|pyc|class|elf|app|deb|rpm)$/i;

export function isBinaryAsset(file: string): boolean {
  return BINARY_EXT.test(file);
}
