/**
 * Precision regression on public skill repositories.
 *
 *   node scripts/corpus.ts            clone (cached), scan, compare with scripts/corpus.json
 *   node scripts/corpus.ts --update   accept the current findings as the new baseline
 *
 * Every repository is pinned to a commit, shallow-cloned into a cache outside the repo
 * (SKILL_GUARD_CORPUS, default <tmp>/skill-guard-corpus) and only *read* — nothing in it
 * is executed and none of it is committed. The baseline stores rule, file and line of
 * each medium-or-higher finding, so a new false positive and a lost true positive both fail.
 * Needs network access the first time; not part of `npm test`.
 */
import { execFileSync } from 'node:child_process';
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, relative } from 'node:path';
import { fileURLToPath } from 'node:url';
import { discoverPath } from '../src/discover.ts';
import { scanItems } from '../src/scan.ts';
import { atLeast, type Severity } from '../src/types.ts';

interface Repo {
  repo: string;
  commit: string;
  /** Medium-or-higher findings, as "SG502 path/to/file.md:21". */
  expect: string[];
  /** Item count at the pinned commit, a sanity check that discovery did not silently regress. */
  items?: number;
}

const BASELINE = new URL('./corpus.json', import.meta.url);
const update = process.argv.includes('--update');
const cache = process.env.SKILL_GUARD_CORPUS || join(tmpdir(), 'skill-guard-corpus');
const repos = JSON.parse(readFileSync(BASELINE, 'utf8')) as Repo[];

function git(args: string[], cwd?: string): string {
  // No hooks, no symlinks: the checkout is untrusted data. Never wait for a password (a moved or private repository
  // would otherwise hang the run), and give up on a stuck network after five minutes.
  return execFileSync('git', ['-c', 'core.hooksPath=/dev/null', '-c', 'core.symlinks=false', ...args], {
    cwd, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'], timeout: 300_000,
    env: { ...process.env, GIT_TERMINAL_PROMPT: '0' },
  }).trim();
}

/** Progress on stderr with the time since start, so a slow or stuck step shows in CI logs. */
const started = Date.now();
const log = (msg: string) => process.stderr.write(`[${((Date.now() - started) / 1000).toFixed(1)}s] ${msg}\n`);

function checkout(r: Repo): string {
  const dir = join(cache, r.repo.replace('/', '__'));
  if (!existsSync(join(dir, '.git'))) {
    mkdirSync(dir, { recursive: true });
    git(['init', '-q'], dir);
    git(['remote', 'add', 'origin', `https://github.com/${r.repo}.git`], dir);
  }
  let head = '';
  try {
    head = git(['rev-parse', 'HEAD'], dir);
  } catch {
    // empty repository
  }
  if (!head.startsWith(r.commit)) {
    log(`fetching ${r.repo}@${r.commit}`);
    git(['fetch', '-q', '--depth', '1', 'origin', r.commit], dir);
    git(['checkout', '-q', '--force', 'FETCH_HEAD'], dir);
    log(`fetched ${r.repo}`);
  }
  return dir;
}

const MIN: Severity = 'medium';
let failed = false;
const rows: string[] = [];
for (const r of repos) {
  const dir = checkout(r);
  log(`discovering ${r.repo}`);
  const items = discoverPath(dir);
  log(`scanning ${items.length} items`);
  const result = scanItems(items);
  log(`scanned ${r.repo}`);
  const got = result.findings
    .filter((f) => atLeast(f.severity, MIN))
    .map((f) => `${f.rule} ${f.file ? relative(dir, f.file).replace(/\\/g, '/') : f.item}${f.line ? `:${f.line}` : ''}`)
    .sort();
  const added = got.filter((k) => !r.expect.includes(k));
  const lost = r.expect.filter((k) => !got.includes(k));
  const itemsChanged = r.items !== undefined && r.items !== result.items.length;
  rows.push(`${r.repo.padEnd(36)} ${String(result.items.length).padStart(5)} items  ${String(got.length).padStart(3)} medium+${added.length || lost.length || itemsChanged ? '  ✗' : '  ✓'}`);
  for (const k of added) rows.push(`    + ${k}   (new — false positive?)`);
  for (const k of lost) rows.push(`    - ${k}   (gone — lost detection?)`);
  if (itemsChanged) rows.push(`    items: expected ${r.items}, got ${result.items.length}`);
  if (update) {
    r.expect = got;
    r.items = result.items.length;
  } else if (added.length || lost.length || itemsChanged) failed = true;
}
console.log(rows.join('\n'));
if (update) {
  writeFileSync(BASELINE, JSON.stringify(repos, null, 2) + '\n');
  console.log(`\nbaseline written to ${relative(process.cwd(), fileURLToPath(BASELINE))}`);
} else if (failed) {
  console.log('\nDifferences from the baseline. Review each one; if they are intended, run with --update.');
  process.exitCode = 1;
} else console.log('\nMatches the baseline.');
