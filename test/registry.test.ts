// The registry check (--check-registries): which packages install steps name (offline), what a registry answer
// becomes, and the CLI end to end against a local stand-in for npm and PyPI (no real network).
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { createServer, type IncomingMessage, type ServerResponse } from 'node:http';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, it } from 'node:test';
import { fileURLToPath } from 'node:url';
import { checkRegistries, lookup, packageName, packagesIn, type PackageRef } from '../src/registry.ts';
import type { Item } from '../src/types.ts';

const BIN = fileURLToPath(new URL('../src/bin.ts', import.meta.url));
const names = (text: string) => packagesIn(text).map((p) => `${p.ecosystem}:${p.name}`);

describe('which packages an install step names', () => {
  it('npm, pnpm, yarn, bun and the runners', () => {
    assert.deepEqual(names('npm install react-codeshift'), ['npm:react-codeshift']);
    assert.deepEqual(names('npm i -D typescript @types/node@24'), ['npm:typescript', 'npm:@types/node']);
    assert.deepEqual(names('pnpm add zod && yarn add left-pad'), ['npm:zod', 'npm:left-pad']);
    assert.deepEqual(names('bun add hono'), ['npm:hono']);
    assert.deepEqual(names('npx -y create-thing@latest my-app --template x'), ['npm:create-thing'], 'a runner: only the package, not its arguments');
    assert.deepEqual(names('pnpm dlx some-cli init'), ['npm:some-cli']);
    assert.deepEqual(names('npm install --registry https://r.example express'), ['npm:express'], 'an option’s value is not a package');
  });

  it('pip, uv, pipx, poetry', () => {
    assert.deepEqual(names('pip install requests'), ['pypi:requests']);
    assert.deepEqual(names('python3 -m pip install -U "fastapi[all]>=0.110" uvicorn==0.30'), ['pypi:fastapi', 'pypi:uvicorn']);
    assert.deepEqual(names('uv pip install -r requirements.txt Pillow'), ['pypi:pillow'], 'a requirements file is skipped, names are normalised');
    assert.deepEqual(names('uv add httpx; uvx ruff check .'), ['pypi:httpx', 'pypi:ruff']);
    assert.deepEqual(names('pipx install black'), ['pypi:black']);
    assert.deepEqual(names('poetry add Some_Package.Name'), ['pypi:some-package-name']);
  });

  it('where a shell would start a command: after separators, in $( ) and backticks, after sudo', () => {
    assert.deepEqual(names('cd app && npm install express'), ['npm:express']);
    assert.deepEqual(names('Run `pip install pdfplumber` first.'), ['pypi:pdfplumber']);
    assert.deepEqual(names('x=$(npx vite --version)'), ['npm:vite']);
    assert.deepEqual(names('sudo pip install ansible'), ['pypi:ansible']);
  });

  it('not packages: paths, URLs, git, archives, placeholders, words in prose', () => {
    assert.deepEqual(names('npm install ./local-pkg ../other /abs/path'), []);
    assert.deepEqual(names('npm install git+https://github.com/a/b.git github:a/b user/repo'), []);
    assert.deepEqual(names('pip install https://example.com/x.whl ./dist/pkg-1.0.tar.gz -e .'), []);
    assert.deepEqual(names('npm install <package-name> your-package $PKG {name}'), []);
    assert.deepEqual(names('pip install package_name'), []);
    assert.deepEqual(names('npm install'), [], 'a bare install names nothing');
    assert.deepEqual(names('You can install it with your package manager.'), [], '"install" in prose is not a command');
    assert.deepEqual(names('the npm install step takes long'), [], 'not at a command start');
  });

  it('found in the public skill repositories: comments, option values, placeholders, workspace packages', () => {
    assert.deepEqual(names('npm install --legacy-peer-deps  # Ignore peer deps'), [], 'a shell comment');
    assert.deepEqual(names('pip install composio          # Python'), ['pypi:composio']);
    assert.deepEqual(names('uv pip install --jobs 4 requests'), ['pypi:requests'], 'an option value');
    assert.deepEqual(names('uv add --optional docs sphinx'), ['pypi:sphinx']);
    assert.deepEqual(names('npm install package@latest; pip install package1 package2 myproject new-package'), [], 'placeholders');
    assert.deepEqual(names('pnpm add @repo/ui --filter web'), [], 'a Turborepo workspace package');
    assert.deepEqual(names('pnpm add -w eslint'), ['npm:eslint'], 'pnpm -w is a flag');
    const long = `pnpm install ${Array.from({ length: 400 }, (_, i) => `@radix-ui/react-part${i}`).join(' ')}`;
    assert.ok(names(long).every((n) => /^npm:@radix-ui\/react-part\d+$/.test(n)), 'no word cut at the read limit');
  });

  it('package names are validated per registry', () => {
    assert.equal(packageName('React', 'npm'), 'react');
    assert.equal(packageName('@scope/pkg@^1', 'npm'), '@scope/pkg');
    assert.equal(packageName('-flag', 'npm'), null);
    assert.equal(packageName('torch==2.1', 'pypi'), 'torch');
    assert.equal(packageName('a_b.c', 'pypi'), 'a-b-c');
    // Names that start like a URL scheme are still names.
    assert.equal(packageName('httpx', 'pypi'), 'httpx');
    assert.equal(packageName('httpie', 'pypi'), 'httpie');
    assert.equal(packageName('https://x.example/p.whl', 'pypi'), null);
  });
});

/** A fetch that answers from a table of URL → [status, body]. */
function fakeFetch(table: Record<string, [number, unknown]>, seen: string[] = []): typeof fetch {
  return (async (input: string | URL | Request) => {
    const url = String(input);
    seen.push(url);
    const hit = Object.entries(table).find(([k]) => url.endsWith(k));
    if (!hit) return new Response('{}', { status: 404 });
    if (hit[1][0] === 0) throw new Error('getaddrinfo ENOTFOUND');
    return new Response(JSON.stringify(hit[1][1]), { status: hit[1][0], headers: { 'content-type': 'application/json' } });
  }) as typeof fetch;
}

const NOW = new Date('2026-11-12T00:00:00Z');
const item = { id: 'repo:skill:x', kind: 'skill', host: 'repo', name: 'x', path: '/x', files: [], meta: {} } as Item;
const ref = (ecosystem: 'npm' | 'pypi', name: string): PackageRef => ({ ecosystem, name, item, file: '/x/SKILL.md', line: 3, command: `install ${name}` });

describe('what a registry answer becomes', () => {
  const table: Record<string, [number, unknown]> = {
    '/last-week/react': [200, { downloads: 50_000_000 }],
    '/last-week/fresh-pkg': [200, { downloads: 3 }],
    '/fresh-pkg': [200, { 'dist-tags': { latest: '1.0.0' }, versions: { '1.0.0': {} }, time: { created: '2026-11-01T00:00:00Z' } }],
    '/last-week/old-quiet': [200, { downloads: 12 }],
    '/old-quiet': [200, { 'dist-tags': { latest: '2.0.0' }, versions: { '2.0.0': {} }, time: { created: '2015-01-01T00:00:00Z' } }],
    '/last-week/bad-pkg': [200, { downloads: 0 }],
    '/bad-pkg': [200, { 'dist-tags': { latest: '0.0.1-security' }, versions: { '0.0.1-security': {} }, time: { created: '2024-01-01T00:00:00Z' } }],
    '/last-week/flaky': [0, null],
    '/pypi/requests/json': [200, { releases: { '2.0': [{ upload_time_iso_8601: '2013-09-24T00:00:00Z' }] } }],
    '/pypi/brand-new/json': [200, { releases: { '0.1': [{ upload_time_iso_8601: '2026-11-10T00:00:00Z' }] } }],
    '/pypi/empty-project/json': [200, { releases: {} }],
  };

  it('missing, removed, new, barely used; popular packages are not fetched whole', async () => {
    const seen: string[] = [];
    const f = fakeFetch(table, seen);
    const refs = ['react', 'made-up-thing', 'fresh-pkg', 'old-quiet', 'bad-pkg'].map((n) => ref('npm', n));
    refs.push(ref('pypi', 'requests'), ref('pypi', 'brand-new'), ref('pypi', 'not-on-pypi'), ref('pypi', 'empty-project'));
    const r = await checkRegistries(refs, { fetch: f, now: NOW });
    const got = r.findings.map((x) => `${x.rule} ${x.message.match(/`([^`]+)`/)?.[1]}`).sort();
    assert.deepEqual(got, ['SG901 empty-project', 'SG901 made-up-thing', 'SG901 not-on-pypi', 'SG902 brand-new', 'SG902 fresh-pkg', 'SG902 old-quiet', 'SG903 bad-pkg']);
    assert.ok(!seen.some((u) => u.endsWith('registry.npmjs.org/react')), 'a popular package’s document is not downloaded');
    assert.equal(r.checked, 9);
    const fresh = r.findings.find((x) => x.message.includes('fresh-pkg'));
    assert.match(fresh?.message ?? '', /first published 11 days ago, 3 downloads last week/);
    assert.equal(fresh?.line, 3);
  });

  it('a missing name under a scope someone owns is a broken step (medium); under an empty scope, an opening (high)', async () => {
    const t2: Record<string, [number, unknown]> = {
      '/-/org/eslint/package': [200, { '@eslint/js': 'write' }],
      '/-/org/free-scope/package': [404, { error: 'Scope not found' }],
    };
    const r = await checkRegistries([ref('npm', '@eslint/plugin-security'), ref('npm', '@free-scope/tool')], { fetch: fakeFetch(t2), now: NOW });
    const [owned, free] = r.findings;
    assert.equal(owned?.severity, 'medium');
    assert.match(owned?.message ?? '', /only the scope's owner could publish it/);
    assert.equal(free?.severity, 'high');
    assert.match(free?.message ?? '', /Nobody owns the scope @free-scope either: it is free to claim/);
  });

  it('a network error is never taken for a missing package', async () => {
    const r = await checkRegistries([ref('npm', 'flaky')], { fetch: fakeFetch(table), now: NOW });
    assert.deepEqual(r.findings, []);
    assert.equal(r.failed.length, 1);
    assert.equal((await lookup('npm', 'flaky', { fetch: fakeFetch(table) })).status, 'error');
  });

  it('each name is looked up once, however often it appears', async () => {
    const seen: string[] = [];
    await checkRegistries([ref('pypi', 'requests'), ref('pypi', 'requests'), ref('pypi', 'requests')], { fetch: fakeFetch(table, seen) });
    assert.equal(seen.length, 1);
  });
});

/** A local stand-in for registry.npmjs.org, api.npmjs.org and pypi.org. */
function registries(): Promise<{ url: string; requests: string[]; close: () => void }> {
  const requests: string[] = [];
  const server = createServer((req: IncomingMessage, res: ServerResponse) => {
    requests.push(req.url ?? '');
    const send = (status: number, body: unknown) => res.writeHead(status, { 'content-type': 'application/json' }).end(JSON.stringify(body));
    const u = req.url ?? '';
    if (u === '/downloads/point/last-week/left-pad') return send(200, { downloads: 2_000_000 });
    if (u.startsWith('/downloads/')) return send(404, { error: 'not found' });
    if (u === '/pypi/requests/json') return send(200, { releases: { '2.0': [{ upload_time_iso_8601: '2013-01-01T00:00:00Z' }] } });
    return send(404, {});
  });
  return new Promise((resolve) => server.listen(0, '127.0.0.1', () => {
    const port = (server.address() as { port: number }).port;
    resolve({ url: `http://127.0.0.1:${port}`, requests, close: () => server.close() });
  }));
}

function cli(args: string[], env: Record<string, string>): Promise<{ code: number; out: string; err: string }> {
  return new Promise((resolve) => {
    const p = spawn(process.execPath, [BIN, ...args], { env: { ...process.env, NO_COLOR: '1', ...env } });
    let out = '';
    let err = '';
    p.stdout.on('data', (d) => (out += d));
    p.stderr.on('data', (d) => (err += d));
    p.on('close', (code) => resolve({ code: code ?? 1, out, err }));
  });
}

describe('the CLI with --check-registries', () => {
  it('flags the made-up package in a skill, keeps the real ones, and asks nothing without the flag', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'sg-registry-'));
    const reg = await registries();
    try {
      mkdirSync(join(dir, 'skills', 'codemod'), { recursive: true });
      writeFileSync(join(dir, 'skills', 'codemod', 'SKILL.md'), '---\nname: codemod\ndescription: Run codemods on React code.\n---\n\n# Codemod\n\nFirst run `npm install react-codeshift left-pad`, then `pip install requests`.\n');
      const env = { SKILL_GUARD_NPM_REGISTRY: reg.url, SKILL_GUARD_NPM_DOWNLOADS: reg.url, SKILL_GUARD_PYPI: reg.url };
      const off = await cli(['scan', dir, '--json', '--fail-on', 'none'], env);
      assert.equal(reg.requests.length, 0, 'offline by default: no request at all');
      assert.ok(!JSON.parse(off.out).findings.some((f: { rule: string }) => f.rule.startsWith('SG9')));

      const on = await cli(['scan', dir, '--json', '--check-registries'], env);
      const found = JSON.parse(on.out).findings.filter((f: { rule: string }) => f.rule.startsWith('SG9'));
      assert.deepEqual(found.map((f: { rule: string; message: string }) => `${f.rule} ${f.message.match(/`([^`]+)`/)?.[1]}`), ['SG901 react-codeshift']);
      assert.equal(found[0].line, 8);
      assert.equal(on.code, 1, 'high: fails the run by default');
      assert.match(on.err, /3 packages looked up/);
      assert.ok(reg.requests.every((u) => !u.includes('SKILL') && !u.includes(dir.replace(/\\/g, '/'))), 'only package names are sent');
    } finally {
      reg.close();
      rmSync(dir, { recursive: true, force: true });
    }
  });
});
