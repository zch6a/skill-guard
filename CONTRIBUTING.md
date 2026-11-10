# Contributing

skill-guard is a scanner people will trust with security decisions, so two things matter more than features: **it must catch real attacks** and **it must not cry wolf**.

## Setup

```bash
npm install                 # dev dependencies only
npm run dev -- scan ./path  # run from source (Node runs .ts directly)
npm test
npm run check               # type-check + tests
node scripts/gen-rules.ts   # regenerate docs/RULES.md after changing rules
```

## Layout

```
src/
  discover.ts   where each agent keeps skills, plugins, hooks, MCP configs → Item[]
  parse.ts      frontmatter, JSONC and TOML (no dependencies)
  rules.ts      the rule catalog and detectors
  scan.ts       splits items into text units, runs rules, suppressions, de-duplication
  unicode.ts    invisible-character detection and decoding
  lock.ts       pinning and diff
  report.ts     terminal, JSON, SARIF, Markdown
test/
  helpers.ts    a fake home directory full of synthetic attacks
```

## Adding or changing a rule

1. Add the rule to `RULES` in `src/rules.ts` with a clear `why` and `fix`.
2. Add a detector. Use `contextual()` so severity is lowered for documentation, tests, fenced examples, quoted mentions and warnings.
3. Add a **positive** fixture to `test/helpers.ts` and an assertion in `test/detect.test.ts`.
4. Add a **negative** case: the most plausible legitimate text that looks similar (e.g. a security skill that *warns* about the pattern).
5. Run the scanner on your own machine (`npm run dev`) and check the rule does not fire on the skills and plugins you have installed. Precision regressions are bugs.
6. Regenerate `docs/RULES.md`.

Never commit real skills, configs or credentials as fixtures — write synthetic ones.

## Adding an agent

Add a block to `discoverMachine()` (and, if the agent has repo-level config, to `discoverPath()`), plus a fixture and a discovery assertion. Document the locations in both READMEs.
