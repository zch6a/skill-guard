# Compatibility

From 1.0.0, skill-guard follows [Semantic Versioning](https://semver.org/). This page says what that covers — and what it deliberately does not, because a scanner that never changed its verdicts would never get better.

## Stable within 1.x

| What | Promise |
|---|---|
| **Rule IDs** (`SG101` …) | An ID always means the same thing. Retired rules keep their ID reserved; it is never reused. Suppressions and SARIF history keep working. |
| **Item IDs** (`claude-code:skill:pdf`, `repo:mcp-server:db@C:/work/app`) | The format `host:kind:name` (plus `plugin/` for items inside a plugin and `@project` for per-project servers) does not change. They appear in suppressions, lock files and JSON. |
| **Commands, options, exit codes** | Existing commands and options keep their meaning. Exit codes: `0` nothing at or above `--fail-on`, `1` findings at or above it, `2` usage error. |
| **JSON output** (`--json`) | `schema: 1`. Fields are only added, never renamed or removed. A finding is `{ rule, severity, title, message, item, file?, line?, column?, evidence? }`. A breaking change would bump `schema` and the major version. |
| **SARIF** (`--sarif`) | SARIF 2.1.0. `ruleId` is the rule ID; `partialFingerprints["skillGuard/v1"]` is stable so code-scanning alerts are matched across runs. |
| **Lock files** | `version: 1`, the same content hash (SHA-256 over file bytes, first 32 hex characters). New optional fields may be added; older lock files keep working — a lock written by 0.5 diffs cleanly against 1.x. |
| **Suppressions** | The `{ "ignore": [{ "rule", "item", "path", "reason" }] }` file format and the inline `skill-guard-ignore SG123` / `skill-guard-ignore-file SG123` comments (rule IDs required). Where they are honoured is a security decision and stays as it is in 1.0: `--config` and `~/.config/skill-guard/config.json` always; inline comments and `.skill-guard.json` in the scanned folder or cwd only with `--trust-ignores`. |
| **Node.js** | Every Node.js LTS line from 22.15 on, on Windows, macOS and Linux (CI tests 22 and 24 on all three). Dropping a Node version is a major change. |

## Not frozen (can change in a minor release)

- **What is found and how severe it is.** New rules, better patterns, fewer false positives, more recall. A minor update can turn up a finding that the previous version missed — that is the point. If your CI must be reproducible, pin the version (`npx skill-guard@1.2.3`) and update deliberately.
- **Default severities** of individual rules, and how context (docs, tests, warnings, quotes) lowers them.
- **Terminal and Markdown output.** They are for people; parse `--json` or SARIF instead.
- **Capabilities** (`auto`, `net`, …): the set may grow; the detection behind each tag improves.

## Deprecation

Anything in the stable list that has to change is first deprecated in a minor release (with a warning on stderr and a note in the CHANGELOG) and removed no earlier than the next major release.
