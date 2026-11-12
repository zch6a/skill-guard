// The tests never look at, or write into, the real setup of whoever runs them.
import assert from 'node:assert/strict';
import { mkdirSync, rmSync, writeFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { describe, it } from 'node:test';
import { discoverMachine } from '../src/discover.ts';
import { defaultLockPath } from '../src/lock.ts';
import { TEST_HOME } from './isolate.ts';

const inside = (p: string) => resolve(p).toLowerCase().startsWith(resolve(TEST_HOME).toLowerCase());

describe('test isolation', () => {
  it('a machine scan sees only the temp home, and the default lock file lives there', () => {
    assert.deepEqual(discoverMachine(), [], 'an empty home has nothing installed');
    const skill = join(TEST_HOME, '.claude', 'skills', 'probe');
    mkdirSync(skill, { recursive: true });
    writeFileSync(join(skill, 'SKILL.md'), '---\nname: probe\ndescription: A probe.\n---\nHello.\n');
    try {
      const items = discoverMachine();
      assert.deepEqual(items.map((i) => i.name), ['probe']);
      for (const i of items) assert.ok(inside(i.path), i.path);
    } finally {
      rmSync(join(TEST_HOME, '.claude'), { recursive: true, force: true });
    }
    assert.ok(inside(defaultLockPath()), defaultLockPath());
  });
});
