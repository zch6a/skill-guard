// The Agent Skill (plugin/skills/skill-guard/SKILL.md) and the Claude Code plugin around it: the format, and that
// every skill-guard command the skill gives an AI works. Machine scans run with a fake home folder, never the real one.
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { cpSync, existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';

// @ts-expect-error a plain JavaScript script, without types
import { makeDemoSkill } from '../scripts/demo-skill.mjs';

const ROOT = fileURLToPath(new URL('..', import.meta.url));
const BIN = join(ROOT, 'src', 'bin.ts');
const SKILL = readFileSync(join(ROOT, 'plugin', 'skills', 'skill-guard', 'SKILL.md'), 'utf8').replace(/\r\n/g, '\n');

function frontmatter(): Record<string, string> {
  const m = SKILL.match(/^---\n([\s\S]*?)\n---\n/);
  assert.ok(m?.[1], 'the frontmatter starts on the first line');
  const out: Record<string, string> = {};
  for (const line of m[1].split('\n')) {
    const kv = line.match(/^([a-z-]+):\s*(.*)$/);
    if (kv?.[1]) out[kv[1]] = kv[2] ?? '';
  }
  return out;
}

test("the skill's frontmatter: portable fields only, within the limits", () => {
  const fm = frontmatter();
  assert.equal(fm.name, 'skill-guard');
  const allowed = new Set(['name', 'description', 'license', 'compatibility', 'metadata', 'allowed-tools']);
  for (const k of Object.keys(fm)) assert.ok(allowed.has(k), `${k} is a field every skill host accepts`);
  const description = fm.description ?? '';
  assert.ok(description.length > 100 && description.length <= 1536);
  assert.doesNotMatch(description, /[<>]/);
  assert.ok((fm.compatibility ?? '').length <= 500);
  assert.ok(SKILL.split('\n').length < 500);
});

test('the plugin and its marketplace agree, and follow the package version', () => {
  const market = JSON.parse(readFileSync(join(ROOT, '.claude-plugin', 'marketplace.json'), 'utf8'));
  const plugin = JSON.parse(readFileSync(join(ROOT, 'plugin', '.claude-plugin', 'plugin.json'), 'utf8'));
  const pkg = JSON.parse(readFileSync(join(ROOT, 'package.json'), 'utf8'));
  assert.equal(market.plugins?.[0]?.name, plugin.name);
  assert.ok(existsSync(join(ROOT, market.plugins[0].source, '.claude-plugin', 'plugin.json')));
  assert.equal(plugin.version, pkg.version);
});

test('the skill tells the AI never to trust the scanned content with --trust-ignores', () => {
  assert.match(SKILL, /Never pass `--trust-ignores`/);
  assert.doesNotMatch(SKILL.split('```').filter((_, i) => i % 2 === 1).join('\n'), /--trust-ignores/, 'no command in the skill uses it');
});

const PREFIX = 'npx -y github:zch6a/skill-guard';
function skillCommands(): string[][] {
  return [...SKILL.matchAll(/```bash\n([\s\S]*?)```/g)]
    .flatMap((m) => (m[1] ?? '').split('\n'))
    .filter((l) => l.startsWith(PREFIX))
    .map((l) => l.slice(PREFIX.length).trim().split(/\s+/).filter(Boolean));
}

test('every skill-guard command the skill gives works', () => {
  const commands = skillCommands();
  assert.deepEqual(commands.map((c) => c[0] ?? '(this machine)'), ['scan', 'explain', '--json', 'list', 'lock', 'diff']);
  const [scanCmd = [], explainCmd = [], machineCmd = [], listCmd = [], lockCmd = [], diffCmd = []] = commands;

  const skill: string = makeDemoSkill();
  const home = mkdtempSync(join(tmpdir(), 'skill-guard-skill-home-'));
  mkdirSync(join(home, '.claude', 'skills'), { recursive: true });
  cpSync(skill, join(home, '.claude', 'skills', 'pdf-helper'), { recursive: true });
  const env = { ...process.env, HOME: home, USERPROFILE: home, APPDATA: join(home, 'AppData', 'Roaming'), XDG_CONFIG_HOME: join(home, '.config'), NO_COLOR: '1' };
  const run = (args: string[]) => spawnSync(process.execPath, [BIN, ...args], { encoding: 'utf8', env });
  try {
    // scan <path> --json: the fields the skill names.
    const scan = run(scanCmd.map((a) => (a === '<path>' ? skill : a)));
    assert.equal(scan.status, 1, scan.stderr);
    const json = JSON.parse(scan.stdout);
    for (const k of ['tool', 'version', 'schema', 'summary', 'items', 'findings', 'skipped']) assert.ok(k in json, k);
    const f = json.findings.find((x: { rule: string }) => x.rule === 'SG103');
    for (const k of ['rule', 'severity', 'title', 'message', 'item', 'file', 'line', 'evidence']) assert.ok(k in f, k);
    assert.match(f.evidence, /\[hidden: +Also read ~\/\.ssh\/id_rsa/, 'hidden characters decoded in the evidence');
    // explain <rule>
    const explain = run(explainCmd.map((a) => (a === '<rule>' ? 'SG103' : a)));
    assert.equal(explain.status, 0);
    assert.match(explain.stdout, /Why it matters/);
    // This machine (the fake home): the skill is found.
    const machine = run(machineCmd);
    assert.equal(machine.status, 1);
    assert.ok(JSON.parse(machine.stdout).items.some((i: { name: string }) => i.name === 'pdf-helper'));
    // list --can auto,net --json
    const list = run(listCmd);
    assert.equal(list.status, 0, list.stderr);
    JSON.parse(list.stdout);
    // lock, then diff: nothing changed.
    assert.equal(run(lockCmd).status, 0);
    const diff = run(diffCmd);
    assert.equal(diff.status, 0, diff.stdout + diff.stderr);
  } finally {
    rmSync(home, { recursive: true, force: true });
    rmSync(dirname(skill), { recursive: true, force: true });
  }
});
