# Changelog

All notable changes are documented here. Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versioning: [SemVer](https://semver.org/).

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
