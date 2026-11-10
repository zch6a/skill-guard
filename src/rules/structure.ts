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

const BINARY_EXT = /\.(exe|dll|so|dylib|bin|node|msi|scr|com|jar|wasm|pyd|pyc|class|elf|app|deb|rpm)$/i;

export function isBinaryAsset(file: string): boolean {
  return BINARY_EXT.test(file);
}
