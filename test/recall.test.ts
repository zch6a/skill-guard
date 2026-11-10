import assert from 'node:assert/strict';
import { mkdirSync, mkdtempSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { after, describe, it } from 'node:test';
import { discoverPath } from '../src/discover.ts';
import { scanItems } from '../src/scan.ts';
import { atLeast, type Finding } from '../src/types.ts';
import { ATTACKS, type Attack } from './attacks.ts';

const roots: string[] = [];
after(() => {
  for (const r of roots) rmSync(r, { recursive: true, force: true });
});

/** Write the case to a temp repository and scan it. */
export function scanAttack(a: Attack): Finding[] {
  const root = mkdtempSync(join(tmpdir(), `sg-attack-${a.id}-`));
  roots.push(root);
  for (const [rel, content] of Object.entries(a.files)) {
    const p = join(root, rel);
    mkdirSync(dirname(p), { recursive: true });
    writeFileSync(p, content);
  }
  // 'junction' works without admin rights on Windows and is ignored elsewhere (a normal symlink).
  for (const [link, target] of Object.entries(a.links ?? {})) symlinkSync(join(root, target), join(root, link), 'junction');
  return scanItems(discoverPath(root), a.options ?? {}).findings;
}

const caught = (a: Attack, found: Finding[]) => a.expect.every((e) => found.some((f) => f.rule === e.rule && atLeast(f.severity, e.min)));
const describeFound = (found: Finding[]) => found.map((f) => `  ${f.rule} ${f.severity} ${f.message}`).join('\n') || '  nothing';

describe('recall corpus', () => {
  for (const a of ATTACKS) {
    if (a.gap) {
      // Known misses are reported, not asserted. If one starts being caught, move it out of the gaps.
      it(`${a.id} (known gap)`, { todo: a.gap }, (t) => {
        t.diagnostic(caught(a, scanAttack(a)) ? 'NOW CAUGHT — move this case out of the known gaps' : 'still missed');
      });
      continue;
    }
    it(`${a.id}: ${a.technique}`, () => {
      const found = scanAttack(a);
      for (const e of a.expect) {
        assert.ok(
          found.some((f) => f.rule === e.rule && atLeast(f.severity, e.min)),
          `${a.id} should trigger ${e.rule} (≥${e.min}); got:\n${describeFound(found)}`,
        );
      }
    });
  }
});
