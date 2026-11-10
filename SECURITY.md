# Security

## What skill-guard does with your files

- Reads files only. It never executes scripts, starts MCP servers, or follows links.
- Makes no network requests and sends no telemetry.
- Masks anything that looks like a credential before it appears in terminal, JSON, SARIF or Markdown output.
- Writes only the lock file you ask for (`skill-guard lock`).

## Reporting a vulnerability

Please do not open a public issue for:

- a way to make skill-guard execute code or leak data,
- a realistic attack that skill-guard misses entirely (a bypass),
- input that makes a scan hang or take minutes (a crafted file that stalls the scanner is a bypass too; `test/core.test.ts` has the ReDoS regression cases).

Use GitHub's private vulnerability reporting ("Report a vulnerability" on the Security tab) with a minimal synthetic example. Bypasses are fixed by adding a rule or detector plus a regression fixture.

False positives and ordinary missed patterns are welcome as public issues.
