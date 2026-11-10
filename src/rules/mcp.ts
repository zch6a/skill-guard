/** Rules for MCP server definitions: what runs, from where, with which secrets and how much access. */
import type { Finding, Item, Severity } from '../types.ts';
import { RULE_BY_ID } from './catalog.ts';
import { home, maskSecrets } from '../util.ts';

const KNOWN_PACKAGES = [
  '@modelcontextprotocol/server-filesystem',
  '@modelcontextprotocol/server-github',
  '@modelcontextprotocol/server-gitlab',
  '@modelcontextprotocol/server-git',
  '@modelcontextprotocol/server-postgres',
  '@modelcontextprotocol/server-sqlite',
  '@modelcontextprotocol/server-slack',
  '@modelcontextprotocol/server-memory',
  '@modelcontextprotocol/server-puppeteer',
  '@modelcontextprotocol/server-brave-search',
  '@modelcontextprotocol/server-google-maps',
  '@modelcontextprotocol/server-fetch',
  '@modelcontextprotocol/server-everything',
  '@modelcontextprotocol/server-sequential-thinking',
  '@modelcontextprotocol/server-redis',
  '@modelcontextprotocol/server-gdrive',
  '@playwright/mcp',
  '@upstash/context7-mcp',
  'chrome-devtools-mcp',
  'mcp-server-fetch',
  'mcp-server-git',
  'mcp-server-time',
  '@notionhq/notion-mcp-server',
  '@stripe/mcp',
  '@sentry/mcp-server',
  'figma-developer-mcp',
  'firecrawl-mcp',
  '@browserbasehq/mcp',
  '@cloudflare/mcp-server-cloudflare',
  'mcp-remote',
  '@supabase/mcp-server-supabase',
  '@azure/mcp',
  '@heroku/mcp-server',
  '@linear/mcp',
  'exa-mcp-server',
  'tavily-mcp',
];

function editDistance(a: string, b: string, max = 3): number {
  if (Math.abs(a.length - b.length) > max) return max + 1;
  const prev = Array.from({ length: b.length + 1 }, (_, i) => i);
  for (let i = 1; i <= a.length; i++) {
    let diag = prev[0] as number;
    prev[0] = i;
    let rowMin = i;
    for (let j = 1; j <= b.length; j++) {
      const tmp = prev[j] as number;
      prev[j] = Math.min((prev[j] as number) + 1, (prev[j - 1] as number) + 1, diag + (a[i - 1] === b[j - 1] ? 0 : 1));
      diag = tmp;
      rowMin = Math.min(rowMin, prev[j] as number);
    }
    if (rowMin > max) return max + 1;
  }
  return prev[b.length] as number;
}

/** Split `pkg@1.2.3`, `@scope/pkg@^1` (npm) or `pkg==1.2.3` / `pkg>=1` (Python) into name and version. */
export function splitPackage(spec: string): { name: string; version: string } {
  const py = /^([A-Za-z0-9_.\-[\]]+)\s*(==|~=|>=|<=|!=|===)\s*(.+)$/.exec(spec);
  if (py) return { name: py[1] as string, version: (py[2] === '==' || py[2] === '===' ? '' : py[2]) + (py[3] as string) };
  const at = spec.lastIndexOf('@');
  if (at > 0) return { name: spec.slice(0, at), version: spec.slice(at + 1) };
  return { name: spec, version: '' };
}

const RUNNERS = /^(npx|bunx|pnpx)(\.cmd|\.exe)?$|^(uvx|pipx)(\.exe)?$/i;
const SECRET_VALUE = /\b(sk-(ant-|proj-)?[A-Za-z0-9_-]{20,}|gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{40,}|(AKIA|ASIA)[A-Z0-9]{16}|AIza[0-9A-Za-z_-]{35}|xox[abposr]-[A-Za-z0-9-]{10,}|glpat-[A-Za-z0-9_-]{20,}|eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}|Bearer\s+[A-Za-z0-9._~+/=-]{20,}|(sk|rk)_live_[A-Za-z0-9]{20,})\b/;

export function scanMcp(item: Item): Finding[] {
  const out: Finding[] = [];
  const s = item.mcp;
  if (!s) return out;
  const push = (rule: string, severity: Severity, message: string, evidence?: string) => {
    const r = RULE_BY_ID.get(rule)!;
    const f: Finding = { rule, severity, title: r.title, message, item: item.id, file: item.path };
    if (evidence) f.evidence = maskSecrets(evidence);
    out.push(f);
  };
  const cmd = (s.command ?? '').replace(/^.*[\\/]/, '');
  const args = s.args;
  const full = [s.command ?? '', ...args].join(' ');

  // SG601 unpinned package runners
  if (RUNNERS.test(cmd)) {
    const pkgArg = args.find((a, i) => !a.startsWith('-') && !(i > 0 && /^--?(package|from|with|p)$/.test(args[i - 1] ?? '')) && !/^(run|exec|dlx)$/.test(a));
    if (pkgArg) {
      const { name, version } = /^(git\+|https?:|github:)/.test(pkgArg) ? { name: pkgArg, version: '' } : splitPackage(pkgArg);
      if (/^(git\+|https?:|github:)/.test(pkgArg)) push('SG601', 'high', `Runs code straight from ${pkgArg.slice(0, 80)} (not a registry release).`, full);
      else if (!version || /^(latest|next|\*|x)$/i.test(version)) push('SG601', 'medium', `Runs "${name}" without a pinned version, so every start may fetch a different release.`, full);
      // SG607 typosquat — a known name is never a typosquat of another known name (server-github vs server-gitlab)
      for (const known of KNOWN_PACKAGES.includes(name.toLowerCase()) ? [] : KNOWN_PACKAGES) {
        const d = editDistance(name.toLowerCase(), known);
        if (d > 0 && d <= 2 && name.length > 6) {
          push('SG607', 'high', `"${name}" is ${d} character${d > 1 ? 's' : ''} away from the well-known "${known}".`, full);
          break;
        }
      }
    }
  }
  // SG602 / SG608 remote servers
  if (s.url) {
    const local = /^https?:\/\/(localhost|127\.\d+\.\d+\.\d+|\[::1\]|0\.0\.0\.0)(:|\/|$)/i.test(s.url);
    if (/^http:\/\//i.test(s.url) && !local) push('SG602', 'high', `Connects to ${s.url} without TLS.`, s.url);
    else if (!local) push('SG608', 'low', `Tools come from ${new URL(s.url).host}.`, s.url);
  }
  // SG603 plaintext secrets
  const secretPlaces: [string, string][] = [...Object.entries(s.env).map(([k, v]) => [`env ${k}`, v] as [string, string]), ...Object.entries(s.headers).map(([k, v]) => [`header ${k}`, v] as [string, string]), ...args.map((a, i) => [`argument ${i + 1}`, a] as [string, string])];
  if (s.url) secretPlaces.push(['url', s.url]);
  for (const [where, value] of secretPlaces) {
    if (/^\$\{?[A-Z_][A-Z0-9_]*\}?$|^\{env:|^%[A-Z_]+%$/.test(value)) continue; // a reference, not a value
    const named = /^(env|header) .*(KEY|TOKEN|SECRET|PASSWORD|PASS|AUTH|CREDENTIAL)/i.test(where) && value.length >= 16 && !/\s/.test(value) && !/^(true|false|\d+)$/i.test(value);
    if (SECRET_VALUE.test(value) || named || /[?&](api[_-]?key|token|access_token|key)=[A-Za-z0-9_-]{16,}/i.test(value)) {
      push('SG603', 'medium', `A credential is written in plain text (${where}).`, `${where} = ${value}`);
      break;
    }
  }
  // SG604 shell wrappers
  if (/^(bash|sh|zsh|dash|cmd|cmd\.exe|powershell|powershell\.exe|pwsh|pwsh\.exe)$/i.test(cmd) && args.some((a) => /^(-c|\/c|\/k|-Command|-command|-EncodedCommand|-enc|-e)$/i.test(a))) {
    // Just launching a local script is ordinary; pipes, chaining or network access in the inline command are not.
    const inline = args.join(' ');
    const simple = !/[|&;`$<>]|\b(curl|wget|iwr|irm|Invoke-|http)/i.test(inline.replace(/^\/d \/s \/c\s+/, ''));
    push('SG604', simple ? 'low' : 'medium', `Starts through ${cmd} with an inline command${simple ? ' (launches a local script)' : ''}.`, full);
  }
  // SG605 broad filesystem
  const H = home().replace(/\\/g, '/').toLowerCase().replace(/\/$/, '');
  if (/filesystem|file-?system|server-fs|mcp-fs/i.test(full)) {
    for (const a of args) {
      if (!a || a.startsWith('-')) continue;
      const raw = a.replace(/\\/g, '/').toLowerCase();
      const p = raw === '/' ? '/' : raw.replace(/\/$/, '');
      if (p === '/' || /^[a-z]:\/?$/.test(p) || p === H || p === '~' || p === '$home' || p === '${home}' || p === '%userprofile%' || p === '/users' || p === '/home') {
        push('SG605', 'medium', `Gives the server access to ${a}.`, full);
        break;
      }
    }
  }
  // SG606 privileged containers
  if (/^(docker|podman)(\.exe)?$/i.test(cmd)) {
    const joined = args.join(' ');
    const bad = /--privileged\b|(-v|--volume|--mount)[\s=]+["']?(\/|[A-Za-z]:\\?):|\/var\/run\/docker\.sock|--(network|net)[\s=]+host\b|--pid[\s=]+host\b|--cap-add[\s=]+(ALL|SYS_ADMIN)\b/i.exec(joined);
    if (bad) push('SG606', 'high', `Container option ${bad[0].trim()}.`, full);
  }
  return out;
}
