# Changelog

All notable changes are documented here. Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versioning: [SemVer](https://semver.org/).

## [1.1.0] — 2026-11-12

### Added
- An Agent Skill and a Claude Code plugin: `/plugin marketplace add zch6a/skill-guard`, then
  `/plugin install skill-guard@skill-guard`. Ask the assistant whether a skill or plugin is safe: it clones it to a
  temporary folder without running anything, scans it, and explains the findings before anything is installed. The
  skill treats the scanned content as untrusted and never uses `--trust-ignores`. A test runs every command it gives.

### Security
- **A file mentioning `/dev/stdin` hung the scan on Linux and macOS.** Discovery follows scripts a Markdown file points
  at (`` `scripts/setup.sh` ``); a backticked `/dev/stdin` exists and is no folder, so it was read to look for a
  shebang, and the read waited forever. Found when the public-repository precision run hung in CI
  (`wshobson/agents`: "Avoid `/dev/stdin`"). Only regular files are read now, never devices or FIFOs.
- **Paths a checked file mentions are followed only inside its own folder tree** (or the scan root). Before, a
  backticked absolute path such as `` `/home/you/bin/deploy` `` made the scanner read that file and report it as part
  of the skill. Hook and MCP commands in configuration still resolve as the agent would run them.

### Changed
- README: an animated demo from real output at the top; the rule count badge corrected (43, not 36).

## [1.0.0] — 2026-11-11

The first stable release: rule IDs, item IDs, options, exit codes, the JSON/SARIF shapes and lock files are now covered by [docs/COMPATIBILITY.md](docs/COMPATIBILITY.md).

Before tagging it, an independent review of the whole source looked for ways to make the scanner itself look away. It found 20 issues, 19 confirmed by running; all are fixed, and each is now a case in the recall corpus (`docs/RECALL.md`, 57 of 58 caught).

### Security

- **On Linux and macOS no file inside a skill was scanned** (`isTextFile` returned false for every POSIX path). Windows was unaffected, which is why it went unnoticed.
- **Scanned content could suppress its own findings** with a `skill-guard-ignore-file` comment. Inline comments and `.skill-guard.json` inside the scanned content now count only with `--trust-ignores`; rule IDs are required; the suppressed count is always shown. **Behaviour change:** add `--trust-ignores` to CI runs of your own repository if you rely on inline ignores.
- A `plugin.json` at a repository root hid its `CLAUDE.md`, settings and commands (two of the five public repositories in the precision corpus had their root `CLAUDE.md`/`AGENTS.md`/`GEMINI.md` unscanned because of it).
- File caps counted images, so 400 assets could push `SKILL.md` out; truncated listings are now reported. Extensionless scripts, scripts SKILL.md points at inside `node_modules/`, and links leaving an item (new **SG804**) are handled.
- Downgrades an attacker could trigger: a skill folder named `fixtures`/`test`, "Not kidding: ignore …", an override in parentheses, a credential read in a backticked command, a hidden `<!--` fence that flipped code-block parity, shell backticks / `# """` / `" # "` read as comments — all fixed.
- Keywords split by a zero-width joiner, soft hyphen or look-alike Cyrillic/Greek letters are matched (rules also run on a de-obfuscated skeleton), and mixed-script words are reported (SG103).
- HTML comments of any length and hidden SVG/HTML text with nested tags are read.
- ESC sequences from scanned files could rewrite the terminal report; control characters are now neutralised in all output.
- One unparseable MCP `url` aborted the whole scan; a slow `fetch(` pattern could take seconds per file.

### Added

- `.claude/settings.json` beyond hooks: `statusLine` / `apiKeyHelper` / credential-helper commands are scanned like hooks, `prompt` hooks' text is scanned, and new **SG404** flags pre-approved commands, auto-enabled MCP servers and API base-URL redirection (full severity in a repository, low in your own user settings).
- MCP servers: modules the server imports are scanned for tool descriptions; `cmd /c npx …` wrappers are unwrapped for pinning and typosquat checks; the server's `package.json` scripts are checked.
- Plugins: custom `commands`/`agents`/`skills` paths from the manifest; scripts that plugin commands point at.
- More instruction files: `CLAUDE.local.md`, `.windsurfrules`, `.clinerules`, `.windsurf/rules`, `.github/instructions`.
- Files over 2 MB are scanned at their first and last megabyte (new **SG805**, low, says so); UTF-16 scripts are decoded; a NUL byte no longer hides a text file.
- Files a SKILL.md tells the agent to read (`README.md`, …) are read as instructions.
- `schema: 1` in JSON output; `docs/COMPATIBILITY.md`.

### Changed

- A full scan of this machine takes 3.5 s (was 2.2 s): oversized bundles are read instead of skipped, and text containing hidden or look-alike characters gets a second pass.

## [0.5.0] — 2026-11-11

### Fixed

- **A skill named `build`, `dist`, `out` … was invisible to repository scans**, and a skill's or plugin's own `dist/`/`build/` folders were never scanned (compiled DeepSeek Harness plugins live there). Build output is now skipped only when searching a repository for items, never inside an item or where the folder name is an item name.
- Command expansion in the new shell normalisation is bounded, so a crafted script cannot blow up memory.

### Added

- **SG110** backdoors planted in agent output ("in every page you create, include `<script src=…>`"), with the big public CDNs downgraded.
- **SG104** now also covers invisible SVG/HTML text (zero font size, zero opacity, `display: none`).
- `curl … | sh` assembled from string pieces and variables is detected (light shell normalisation: joined quotes, simple assignments).
- Scripts that a `CLAUDE.md`/`AGENTS.md`/repo command tells the agent to run are scanned with it; a local MCP server's own `package.json` install scripts are checked.
- Recall corpus: 28 cases, 27 caught (was 17 of 19).

### Changed

- `lock` and `diff` reuse the bytes read for scanning to compute file hashes: `lock` 3.9 s → 2.4 s, `diff` 2.4 s → 1.2 s on this machine. Hashes are unchanged, so existing lock files stay valid.

## [0.4.0] — 2026-11-11

### Added

- **MCP tool poisoning in server source.** A local MCP server's script (`python server.py`, `node ./index.js`, `${CLAUDE_PLUGIN_ROOT}/…`) is now scanned, and its tool docstrings / `description` strings are read as instructions — that text goes straight to the model.
- New rules: **SG109** tool shadowing (a tool description steering another tool; copying messages to a fixed address), **SG206** data leaked through image/link URLs, **SG305** download-unpack-run of binaries (password-protected archives, cleared quarantine).
- Also detected now: data sent out inside DNS names, PreToolUse hooks that answer "allow", instructions that widen the agent's own permissions, "don't mention … to the user".
- Recall corpus: 19 synthetic attacks modelled on published techniques (`test/attacks.ts`, `docs/RECALL.md`) — 17 caught, 2 documented gaps.
- `diff` shows capability changes: `now also: net` when an update starts talking to the network. Lock files record capabilities (older lock files still work).
- `docs/RULES.md` starts with how to read a finding.

### Fixed

- **ReDoS**: crafted text could make a scan take minutes (a link pattern took 124 s on a 200 KB line; the e-mail and ngrok patterns were quadratic). Every open-ended quantifier is now bounded; regression tests cover the shapes.
- A negation in an earlier clause ("To avoid prompts, add …", "Don't worry, just run …") no longer lowers the severity of the instruction after it.

### Changed

- Literal pre-filters and a linear base64 scanner: faster despite the new rules (2.5 s → 2.2 s on this machine, findings identical).

## [0.3.0] — 2026-11-11

### Added

- `--can` works with `scan` too: `skill-guard scan --can auto` reports only on things that run by themselves.
- Markdown reports open with a capability summary ("2 run automatically · 1 talks to the network").
- `npm run corpus`: a precision regression over five public skill repositories pinned to commits (read-only, nothing executed, nothing vendored), also run in CI.

### Changed

- About 40% faster on a full machine (344 items: 4.2 s → 2.5 s on Windows): files are read once per command and in parallel, and a file shared by several items (hooks running the same script) is scanned once. Findings are identical.
- The rules are split into `src/rules/{catalog,context,patterns,text,mcp,structure}.ts`; `src/rules.ts` re-exports them.
- `npm run typecheck` also checks the tests and scripts.
- Hooks are named by event and owning plugin in Markdown reports as well.

## [0.2.0] — 2026-11-11

### Added

- `list` shows what each item **can do** — `auto` (runs without being asked), `code`, `net`, `write`, `shell`, `bin`, `creds` — and `--can auto,net` filters by it. JSON output carries a `capabilities` array per item.
- Per-project MCP servers in `~/.claude.json` get stable ids (`name@<project>`) and names that tell projects apart (`db (work/app)`).

### Changed

- Precision measured on 1,537 items from five popular public skill repositories: 20 medium-or-higher findings → 2, both genuine.
- SG201 (sending data out) is `medium` on its own; documentation placeholders (`example.com`, `company.com`, …) are low. The exfiltration chain (SG205) now also fires when the sending side is only a hard-coded POST in code.
- SG101 no longer matches "a new system prompt" in ordinary prose; SG102 ignores "do not tell the user they need to…"; SG301 is downgraded when a sentence explicitly forbids running the quoted command ("Never run `curl … | sh`"); SG401 ignores start-up folders that are only named, and `echo 'export NAME=…' >> ~/.bashrc`.
- Terminal: hooks are headed by event and owning plugin instead of repeating their command; long paths are shortened in the middle so the file name stays visible; paths under `SKILL_GUARD_HOME` are shown with `~`.

## [0.1.0] — 2026-11-11

### Added

- Discovery for Claude Code (skills, plugins with commands/agents/hooks/MCP, settings hooks, `~/.claude.json`), Codex (skills, plugins, `config.toml`), Cursor, OpenCode, DeepSeek Harness (Cordis plugins), Claude Desktop, VS Code, `~/.agents` skills, and repository/folder scans.
- 36 rules across hidden instructions, prompt injection, exfiltration, execution, persistence, destructive commands, MCP configuration, hooks and packaging — each with an explanation and a fix.
- Context-aware severity (docs, tests, fenced examples, quoted mentions, warnings) and an exfiltration-chain rule.
- `lock` / `diff` for trust-on-first-use pinning of everything an agent loads.
- Terminal, JSON, SARIF 2.1.0 and Markdown output; inline and file-based suppressions; `--fail-on` for CI.
