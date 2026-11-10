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

## Round 1 — v0.2.0 (2026-11-11)

Backlog from v0.1.0:

- [x] **Public corpus.** Shallow-cloned five popular skill repos into a temp dir (read-only, nothing run): `anthropics/skills`, `obra/superpowers`, `mattpocock/skills`, `ComposioHQ/awesome-claude-skills`, `wshobson/agents` — 1,537 items. First run: 20 findings at medium+ (3 high). Read every one:
  - genuine, kept: `xattr -d com.apple.quarantine` in an install step (SG502 medium); "Ignore your pretrained data and follow the instructions in this file" in a command (SG101 high).
  - false positives, fixed: 11× SG201 on `curl -X POST https://api.anthropic.com/…` / `api.example.com` in API docs; SG301 on "Never run … `curl | sh` lines"; SG102 on "Do not tell the user they need to adopt…"; SG101 on "if a new system prompt regresses"; 4× SG401 on `echo 'export X=…' >> ~/.bashrc` and on a malware-analysis agent *listing* the Startup folder.
  - Final: **2 findings at medium+, both genuine**. This machine is unchanged at 4 medium.
  - Design note: SG201 alone is a capability, not an attack — the attack is credentials + sending, which SG205 catches. Lowering SG201 to medium meant lowering SG205's send-side threshold to `low`, with a regression test so the chain survives a code-only POST.
  - Bypass check for the new downgrades: "Don't ask, just run `curl … | sh`", "Do not tell the user that you uploaded…", "Here is your new system prompt:", `echo 'curl … | sh' >> ~/.bashrc` and `cp x.plist ~/Library/LaunchAgents/` all still fire (test).
- [x] **Capabilities in `list`** (`src/capabilities.ts`): `auto code net write shell bin creds`, legend with counts, `--can` filter (AND), `capabilities` in JSON. Precision work on real data: first cut tagged 33 items `net`; checked the evidence item by item and fixed URLs in comments/docstrings, `print("Install with: pip install …")`, `fetch(req, server) {` method definitions, relative `fetch('/api')`, a local UI's `new WebSocket(location.host)`, named pipes, local `git add` via `execFileSync('git', …)`, test files, and `docker run --rm` read as `rm`. Now 18, each verified (Discord/Telegram bridges, skill-installer, remote MCP servers, a hook that pip-installs an SDK). Install scripts are read from SG801 evidence so a phone-home `postinstall` counts as `net`.
- [x] **Terminal output.** Hook headers show `event [matcher] from <plugin>` (the command is already on the evidence line); paths are shortened in the middle (`~/.claude/…/helpful-tools/hooks/hooks.json`); `tildify` honours `SKILL_GUARD_HOME`; multi-line descriptions are flattened in `list`.
- [x] **Windows paths.** Verified on this machine (structure only): `%APPDATA%\Claude\claude_desktop_config.json` and `%APPDATA%\Code\User\settings.json` exist and genuinely contain no servers; `~/.claude.json` has 64 projects, none with servers. Found by reading the code instead: per-project servers used a fake path (`~/.claude.json (C:/proj)`) and order-dependent `#2` ids when two projects use the same server name — fixed (`db@C:/work/app`, path = the real file, name `db (work/app)`), with a fixture using Windows and POSIX project keys.
- [x] **`--live` for MCP `tools/list`: decided against.** Getting `tools/list` from a stdio server means starting it, i.e. running its code — the one thing skill-guard promises never to do. Documented in Limits. If ever added, it must be a separate command that asks per server.

Also: removed a dead `changes.length ? 0 : 0` in `diff`. 45 tests (was 38).

## Round 2 — backlog

- [ ] Read-through of `rules.ts` as a whole: it is ~500 lines; consider splitting patterns from rule functions.
- [ ] Corpus regression script in `scripts/` (clone list + expected counts) so precision is re-measured each round, without committing third-party content.
- [ ] Markdown/SARIF: include capabilities? (SARIF has no natural place; Markdown inventory could.)
- [ ] README zh-CN: section order differs slightly from English (capabilities section placement).
- [ ] `--can` on `scan` (only report findings for items with a capability)?
