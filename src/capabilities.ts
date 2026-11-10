/**
 * What an item can do, independent of whether it looks malicious:
 * "this skill ships code that talks to the network and writes files".
 * Shown by `skill-guard list` and included in JSON output.
 */
import { SHELL_FILE, isTestPath } from './rules/context.ts';
import type { Capability, Finding, Item, TextUnit } from './types.ts';

export const CAPABILITY_LABEL: Record<Capability, string> = {
  'runs-code': 'code',
  'auto-runs': 'auto',
  network: 'net',
  'writes-files': 'write',
  shell: 'shell',
  binaries: 'bin',
  credentials: 'creds',
};

export const CAPABILITY_HELP: Record<Capability, string> = {
  'runs-code': 'ships scripts or a command the agent can run',
  'auto-runs': 'runs without being asked (hook, MCP server start-up, install script)',
  network: 'its code or command makes network requests, or it is a remote MCP server',
  'writes-files': 'its code or command writes files',
  shell: 'asks for unrestricted shell access',
  binaries: 'bundles compiled executables',
  credentials: 'reads credential files or the whole environment',
};

const ORDER: Capability[] = ['auto-runs', 'runs-code', 'shell', 'network', 'writes-files', 'credentials', 'binaries'];

/** Network commands. In code they only count on a line that spawns a process — elsewhere they are usually help text. */
const SHELL_NET = /(?<![\\\w-])(curl|wget|Invoke-WebRequest|Invoke-RestMethod|iwr|irm|scp|rsync|ssh|nc|ncat)\s|\bgit\s+(clone|fetch|pull|push|ls-remote)\b|\bnpx\s|\buvx\s|\bpip3?\s+install\b|\bnpm\s+(i|install|ci)\b|\b(bun|pnpm|yarn)\s+(add|install)\b|['"](pip3?|npm|uv|pnpm|yarn|bun)['"]\s*,\s*['"](install|add|i|ci)['"]|['"](curl|wget)['"]\s*,/;
/** Network APIs in code. */
const CODE_NET = /\bfetch\s*\((?!\s*['"`]\.?\/)(?![^)\n]*\)\s*\{)|\brequests\.(get|post|put|patch|delete|head|request|Session)\b|\burllib\.request\b|\burlopen\s*\(|\bhttpx\.|\baiohttp\.|\baxios\b|\bhttps?\.(request|get)\s*\(|\brequire\s*\(\s*['"](node:)?https?['"]\s*\)\s*\.(get|request)\b|\bnet\.(connect|createConnection)\s*\(|\bsocket\.(connect|create_connection)\s*\(|\bnew\s+WebSocket\s*\(|\bXMLHttpRequest\b|\bhttp\.client\b|\bNet\.WebClient\b/;
const SPAWNS = /\b(subprocess|execSync|execFileSync|execFile|exec|spawn|spawnSync|os\.system|os\.popen|Popen|check_output|check_call|Bun\.\$|shell\.exec|child_process)\b|\$`/;

/** Lines that only talk to this machine (a local UI calling its own server, a named pipe) are not "network" in the sense users care about. */
const LOCAL_ONLY = /\b(localhost|127\.0\.0\.1|0\.0\.0\.0|location\.(host|origin)|window\.location|pipePath|socketPath)\b|\[::1\]|\.sock\b|\\\\\.\\pipe/;

export function makesNetworkCalls(text: string, shell: boolean): boolean {
  return text.split('\n').some((l) => !LOCAL_ONLY.test(l) && (CODE_NET.test(l) || (SHELL_NET.test(l) && (shell || SPAWNS.test(l)))));
}

/** File writes in code. Shell redirection only counts in shell context, where `>` is not a comparison. */
const WRITE_CODE = /\b(writeFile(Sync)?|appendFile(Sync)?|createWriteStream|copyFile(Sync)?|rename(Sync)?|unlink(Sync)?|rmSync|mkdirSync)\s*\(|\bopen\s*\([^)\n]*,\s*['"](w|a|x|r\+)b?\+?['"]|\.write_(text|bytes)\s*\(|\bshutil\.(copy\w*|move|rmtree)\s*\(|\bos\.(remove|rename|replace|makedirs|unlink)\s*\(|\b(Set-Content|Add-Content|Out-File|Copy-Item|Move-Item|Remove-Item|New-Item)\b|\bsed\s+-i\b|\btee\s/;
const WRITE_SHELL = /(^|[^<>=!\-0-9])>>?\s*["']?(?!&|\/dev\/null|NUL\b|\$null)[~$\w./\\-]|(?<![\w-])(cp|mv|rm|mkdir|touch)\s+-?\w/m;

/** Comments and docstrings, removed so documentation does not count as behaviour. */
export function stripComments(text: string): string {
  return text
    .replace(/"""[\s\S]*?"""|'''[\s\S]*?'''/g, '""')
    .replace(/\/\*[\s\S]*?\*\//g, '')
    .split(/\r?\n/)
    .filter((l) => !/^\s*(#|\/\/|\*|--\s|REM\s|;)/i.test(l))
    .map((l) => l.replace(/\s(#|\/\/)\s.*$/, ''))
    .join('\n');
}

export function capabilitiesOf(item: Item, units: TextUnit[], findings: Finding[]): Capability[] {
  const caps = new Set<Capability>();
  const has = (rule: string, min: Finding['severity'][] = ['low', 'medium', 'high', 'critical']) => findings.some((f) => f.item === item.id && f.rule === rule && min.includes(f.severity));

  const executable = units.filter((u) => u.kind === 'code' || u.kind === 'command');
  if (executable.length || item.kind === 'dsh-plugin') caps.add('runs-code');
  if (item.kind === 'hook' || (item.kind === 'mcp-server' && item.mcp?.transport === 'stdio' && !item.mcp.disabled) || has('SG801', ['info', 'low', 'medium', 'high', 'critical'])) caps.add('auto-runs');
  if (item.kind === 'mcp-server' && item.mcp && (item.mcp.transport === 'http' || item.mcp.transport === 'sse')) caps.add('network');

  // Test suites describe behaviour in strings and fixtures; they are not what the agent runs.
  for (const u of executable.filter((x) => !isTestPath(x.file))) {
    const text = u.kind === 'code' ? stripComments(u.text) : u.text;
    const shellish = u.kind === 'command' || SHELL_FILE.test(u.file ?? '');
    if (makesNetworkCalls(text, shellish)) caps.add('network');
    if (WRITE_CODE.test(text) || (shellish && WRITE_SHELL.test(text))) caps.add('writes-files');
  }

  // Install scripts live in package.json, not in a text unit: read them from the SG801 evidence.
  for (const f of findings) if (f.item === item.id && f.rule === 'SG801' && makesNetworkCalls(f.evidence ?? '', true)) caps.add('network');

  if (has('SG803')) caps.add('shell');
  if (has('SG802', ['info', 'low', 'medium', 'high', 'critical'])) caps.add('binaries');
  if (has('SG203', ['medium', 'high', 'critical']) || has('SG204', ['medium', 'high', 'critical']) || has('SG205')) caps.add('credentials');
  return ORDER.filter((c) => caps.has(c));
}
