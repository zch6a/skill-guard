# Polish log

Each round goes through the full checklist: features vs. README, code read-through, tests, first-run UX, docs, engineering, security & privacy.

## v0.1.0 — initial build (2026-11-11)

Research: 2026 work on malicious skills (CSA note on SKILL.md context poisoning, Skill-Inject, SkillSieve, Snyk ToxicSkills), MCP tool poisoning and rug pulls (CSA whitepaper, MCPTox), plugin hooks (PromptArmor marketplace hijack, HookPry, CVE-2025-59536). Surveyed the real layouts on this machine (152 SKILL.md files, 82 plugins incl. Codex `.codex-plugin`, 7 plugins with hooks, MCP servers in `~/.claude.json` and Codex TOML, DeepSeek Harness Cordis plugins as npm packages with a `dsh` field and install scripts).

Built: discovery for 8 hosts plus folder scans, zero-dependency frontmatter/JSONC/TOML parsers, 36 rules, context-aware severity, exfiltration-chain correlation, lock/diff, terminal/JSON/SARIF/Markdown output, suppressions.

**Precision work on real data** (344 items, all from official marketplaces — so every finding is a false-positive candidate): first run 181 findings with several "high"; final default view **4 medium, 0 high/critical**, all honest (two bundled binaries, two large embedded blobs in Codex plugins). Fixes that got there:

- Security tooling talks *about* attacks: quoted mentions, sentences phrased as warnings (before *and* after the match: "`X` does not mean…"), fenced examples, comments/docstrings in code, and test files are downgraded.
- Mode names vs. instructions: `bypassPermissions` listed among modes is not an instruction; flags and config assignments (`--dangerously-skip-permissions`, `defaultMode: bypassPermissions`) are.
- Mentions vs. access: `.npmrc` named in prose ≠ reading it; secret-file findings need a read/copy/send verb for full severity.
- `os.environ.items()` copying the env into a subprocess is not a dump; `env` is a variable name in Python/JS (bare `env` only counts in shell context).
- `core.hooksPath=/dev/null` disables hooks — defensive, not tampering.
- `<system>` used as a placeholder argument is not impersonation; a closed `<system>…</system>` block is.
- POSTing in code is routine unless the destination is a hard-coded external host; relative URLs are skipped.
- Known package names are never typosquats of each other (`server-github` vs `server-gitlab`).

**Recall**: 20 detection tests on synthetic attacks across every host — Unicode-Tag hidden instructions (decoded), override/concealment, trigger hijacking, hidden comments, download-and-run, credential theft + exfil chain, persistence, encoded execution, a malicious SessionStart hook and the script a hook runs, unpinned/typosquatted/plain-http/privileged/whole-disk MCP servers, secrets in configs (masked), Codex TOML, OpenCode JSONC, Claude Desktop, `~/.agents` remote instructions, and a DeepSeek Harness plugin with a phone-home install script that rewrites agent config.

Fresh install from `npm pack` (49 KB, 17 files) works. 38 tests passing.

## Round 1 — backlog

- [ ] Run against a corpus of *public* skills (e.g. clone a few popular skill repos into a temp dir, read-only) to measure precision beyond this machine.
- [ ] `list`: show capabilities per item (runs code, network, hooks, file writes) — "what can my agents do".
- [ ] Terminal output: group long hook names better; show the item's config file once.
- [ ] Windows: verify `~/.claude.json` per-project servers and `APPDATA` paths for Claude Desktop/VS Code on a real install.
- [ ] Think about remote MCP tool descriptions: an opt-in `--live` that connects to *already configured* servers and scans `tools/list` (never by default).
