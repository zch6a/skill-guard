# Contributing

skill-guard is a scanner people will trust with security decisions, so two things matter more than features: **it must catch real attacks** and **it must not cry wolf**.

## Setup

Development runs the TypeScript sources directly, which needs type stripping on by default: **Node.js 22.18+ or 24** (on 22.15–22.17 add `--experimental-strip-types`). The published package is plain JavaScript and runs on 22.15+.

Before changing anything users depend on — rule IDs, item IDs, options, JSON/SARIF shape, lock format — read [docs/COMPATIBILITY.md](docs/COMPATIBILITY.md).

```bash
npm install                 # dev dependencies only
npm run dev -- scan ./path  # run from source (Node runs .ts directly)
npm test
npm run check               # type-check (src, tests, scripts) + tests
node scripts/gen-rules.ts   # regenerate docs/RULES.md after changing rules
npm run corpus              # precision regression on public skill repos (needs network once)
```

## Layout

```
src/
  discover.ts        where each agent keeps skills, plugins, hooks, MCP configs → Item[]
  parse.ts           frontmatter, JSONC and TOML (no dependencies)
  scan.ts            splits items into text units, runs rules, suppressions, de-duplication
  rules.ts           re-exports everything below
  rules/catalog.ts   rule ids, severities, why and fix (docs/RULES.md is generated from it)
  rules/context.ts   how surroundings (docs, tests, warnings, quotes, fences) change severity
  rules/patterns.ts  the regular expressions
  rules/text.ts      rules over instructions, code and commands
  rules/mcp.ts       MCP server definitions
  rules/structure.ts hooks, package.json scripts, skill metadata, bundled binaries
  capabilities.ts    what an item can do (auto, code, net, write, shell, bin, creds)
  tooldesc.ts        MCP tool descriptions inside server source, scanned as instructions
  rules/shell.ts     joins quote-split words and simple variables so assembled commands are seen
  unicode.ts         invisible-character detection and decoding
  lock.ts            pinning and diff
  report.ts          terminal, JSON, SARIF, Markdown
test/
  helpers.ts         a fake home directory full of synthetic attacks
  attacks.ts         the recall corpus: one synthetic repository per attack technique (docs/RECALL.md)
  recall.test.ts     scans each one; known gaps are reported as todo
scripts/
  corpus.ts          clones pinned public skill repos (read-only) and compares with corpus.json
```

## Adding or changing a rule

1. Add the rule to `RULES` in `src/rules/catalog.ts` with a clear `why` and `fix`.
2. Add a detector (usually in `src/rules/text.ts`, pattern in `patterns.ts`). Use `contextual()` so severity is lowered for documentation, tests, fenced examples, quoted mentions and warnings.
3. Add a **positive** case: for a new attack technique, a synthetic repository in `test/attacks.ts` (it becomes a row in `docs/RECALL.md`); for a variant, a fixture in `test/helpers.ts` and an assertion in `test/detect.test.ts`.
   - Keep every quantifier bounded (`[^\n]{0,400}`, not `[^\n]*`): open-ended runs followed by a required literal backtrack quadratically, and a crafted file could stall the scan. The ReDoS test in `test/core.test.ts` has the shapes that caught this before.
   - If the pattern has an entry in `LITERALS` (`src/rules/patterns.ts`), the new alternative's literal must be added there too, or the pre-filter will skip it.
4. Add a **negative** case: the most plausible legitimate text that looks similar (e.g. a security skill that *warns* about the pattern).
5. Run the scanner on your own machine (`npm run dev`) and `npm run corpus`, and check the rule does not fire on legitimate skills. Precision regressions are bugs. If the corpus diff is intended (a new true positive), read every changed line, then `node scripts/corpus.ts --update`.
6. Regenerate `docs/RULES.md`.

Never commit real skills, configs or credentials as fixtures — write synthetic ones.

## Adding an agent

Add a block to `discoverMachine()` (and, if the agent has repo-level config, to `discoverPath()`), plus a fixture and a discovery assertion. Document the locations in both READMEs.
