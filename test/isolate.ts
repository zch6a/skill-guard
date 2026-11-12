/**
 * Loaded before every test file (`node --import ./test/isolate.ts --test`, and from helpers.ts): the home folder and
 * every agent's own folder variable point into a new, empty temp folder. A test that forgets to pass a path then
 * finds nothing, instead of scanning (or writing a lock file into) the real setup of whoever runs the tests.
 */
import { mkdirSync, mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const KEY = 'SKILL_GUARD_TEST_HOME';

if (!process.env[KEY]) {
  const home = mkdtempSync(join(tmpdir(), 'sg-test-home-'));
  for (const sub of ['AppData/Roaming', 'AppData/Local', '.config']) mkdirSync(join(home, sub), { recursive: true });
  Object.assign(process.env, {
    [KEY]: home,
    SKILL_GUARD_HOME: home,
    HOME: home,
    USERPROFILE: home,
    APPDATA: join(home, 'AppData', 'Roaming'),
    LOCALAPPDATA: join(home, 'AppData', 'Local'),
    XDG_CONFIG_HOME: join(home, '.config'),
  });
  for (const name of ['CLAUDE_CONFIG_DIR', 'CODEX_HOME', 'DSH_HOME']) delete process.env[name];
  // Child processes (the CLI under test) inherit all of this; only the process that made the folder removes it.
  process.on('exit', () => rmSync(home, { recursive: true, force: true }));
}

export const TEST_HOME = process.env[KEY] as string;
