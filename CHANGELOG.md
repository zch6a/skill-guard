# Changelog

All notable changes are documented here. Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versioning: [SemVer](https://semver.org/).

## [0.1.0] — 2026-11-11

### Added

- Discovery for Claude Code (skills, plugins with commands/agents/hooks/MCP, settings hooks, `~/.claude.json`), Codex (skills, plugins, `config.toml`), Cursor, OpenCode, DeepSeek Harness (Cordis plugins), Claude Desktop, VS Code, `~/.agents` skills, and repository/folder scans.
- 36 rules across hidden instructions, prompt injection, exfiltration, execution, persistence, destructive commands, MCP configuration, hooks and packaging — each with an explanation and a fix.
- Context-aware severity (docs, tests, fenced examples, quoted mentions, warnings) and an exfiltration-chain rule.
- `lock` / `diff` for trust-on-first-use pinning of everything an agent loads.
- Terminal, JSON, SARIF 2.1.0 and Markdown output; inline and file-based suppressions; `--fail-on` for CI.
