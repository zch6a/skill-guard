import type { RuleInfo } from '../types.ts';

/**
 * The rule catalog. Every rule explains *why* it matters and *what to do*, so a
 * finding is actionable without reading this source. IDs are stable: they are
 * used in suppressions, SARIF output and the docs.
 */
export const RULES: RuleInfo[] = [
  // --- instructions a model will follow
  { id: 'SG101', title: 'Instruction override', severity: 'high', why: 'Text that tells the model to ignore its previous instructions, rules or system prompt is the classic prompt-injection move. In a skill or tool description it runs every time the item is loaded.', fix: 'Remove the sentence. If the item legitimately needs different behaviour, say what to do, not what to ignore.' },
  { id: 'SG102', title: 'Hides actions from the user', severity: 'high', why: 'Legitimate tools have no reason to ask the model to keep something from you. "Silently", "without telling the user" and "do not mention" are how malicious skills keep their side effects out of the conversation.', fix: 'Remove the concealment, or remove the item.' },
  { id: 'SG103', title: 'Invisible characters', severity: 'high', why: 'Unicode Tag characters, bidirectional overrides and runs of zero-width characters are invisible in editors and on GitHub but are read by the model. They can carry whole hidden instructions.', fix: 'Delete the characters (`skill-guard` shows where they are and what hidden text they spell). Treat the item as hostile until you know why they are there.' },
  { id: 'SG104', title: 'Hidden comment with instructions', severity: 'medium', why: 'HTML comments do not render in Markdown previews, so instructions inside them are seen by the model but not by a human skimming the skill.', fix: 'Move the text out of the comment so reviewers can see it, or delete it.' },
  { id: 'SG105', title: 'Trigger hijacking', severity: 'medium', why: 'A description that claims the item must be used for every request makes the agent load it everywhere — maximising the reach of anything else it contains.', fix: 'Describe when the item is actually useful.' },
  { id: 'SG106', title: 'Loads instructions from the internet', severity: 'high', why: 'A skill that fetches its real instructions at run time can change behaviour after you reviewed it (a "rug pull"), and the reviewed text proves nothing.', fix: 'Vendor the instructions into the skill, or pin them to a content hash you have reviewed.' },
  { id: 'SG107', title: 'Pretends to be the system or an official source', severity: 'medium', why: 'Fake `<system>` blocks, "[SYSTEM]" markers or claims of being an official Anthropic/OpenAI/DeepSeek component try to borrow authority the text does not have.', fix: 'Remove the impersonation.' },
  { id: 'SG108', title: 'Turns off approvals or the sandbox', severity: 'high', why: 'Instructions or commands that disable permission prompts or the sandbox (`--dangerously-skip-permissions`, `bypassPermissions`, `danger-full-access`, YOLO mode) remove the last check between the model and your machine.', fix: 'Keep approvals on. Grant specific permissions instead of disabling them all.' },

  // --- data leaving the machine
  { id: 'SG201', title: 'Sends data to an external server', severity: 'medium', why: 'Uploading or POSTing data from your machine is how secrets and source code get exfiltrated. On its own it is often legitimate (calling an API); combined with credential or environment access in the same file it becomes SG205 (critical).', fix: 'Check exactly what is sent and to whom. Remove it if the item has no clear reason to upload anything.' },
  { id: 'SG202', title: 'Known exfiltration endpoint', severity: 'critical', why: 'Request bins, tunnels and chat webhooks (webhook.site, ngrok, Discord/Slack/Telegram webhooks, Burp Collaborator, interactsh…) are what attackers use to receive stolen data; legitimate tools almost never hard-code them.', fix: 'Treat the item as malicious unless you wrote it yourself.' },
  { id: 'SG203', title: 'Reads credentials or private keys', severity: 'high', why: 'SSH keys, cloud credentials, browser cookie stores, crypto wallets and agent auth files are the first thing an attacker looks for.', fix: 'Remove the access. If a tool genuinely needs a credential, pass it explicitly through a scoped environment variable.' },
  { id: 'SG204', title: 'Dumps environment variables', severity: 'medium', why: 'The environment holds API keys and tokens. Serialising all of it is rarely needed and is a common first step of exfiltration.', fix: 'Read the specific variables you need instead of the whole environment.' },
  { id: 'SG205', title: 'Reads secrets and sends data out (exfiltration chain)', severity: 'critical', why: 'The same file both touches credentials (or the whole environment) and sends data to a server. That is the complete shape of a credential-stealing payload.', fix: 'Treat as malicious. Do not run it; remove the item and rotate any credentials it could reach.' },

  // --- code execution
  { id: 'SG301', title: 'Downloads and executes code', severity: 'critical', why: '`curl … | sh`, `iwr … | iex` and friends run whatever a server returns at that moment, with your privileges. The content can change at any time.', fix: 'Download, verify (checksum or signature) and review before running — or install from a package manager with a pinned version.' },
  { id: 'SG302', title: 'Runs obfuscated or encoded code', severity: 'critical', why: 'Decoding base64 or hex and executing it (`powershell -enc`, `eval(atob(…))`, `exec(b64decode(…))`) exists to hide what runs from a reviewer.', fix: 'Replace with readable code, or remove the item.' },
  { id: 'SG303', title: 'Executes code fetched at run time', severity: 'critical', why: 'Passing network responses to `eval`, `exec` or `Function` lets a remote server run arbitrary code inside the tool.', fix: 'Ship the code with the item instead of fetching it.' },
  { id: 'SG304', title: 'Large encoded blob', severity: 'medium', why: 'Long base64 or hex strings in instructions or scripts can hide payloads from review.', fix: 'Check what the blob decodes to. Keep data in a separate, documented file.' },

  // --- persistence and tampering
  { id: 'SG401', title: 'Installs persistence', severity: 'high', why: 'Writing to shell start-up files, cron, scheduled tasks, launch agents, systemd units or the Windows Run key makes code run again long after the agent session ends.', fix: 'A skill should never need to survive a reboot. Remove it.' },
  { id: 'SG402', title: "Modifies agents' configuration", severity: 'high', why: "Writing to `.claude/settings.json`, `~/.claude.json`, `~/.codex/config.toml`, MCP configs, CLAUDE.md or AGENTS.md can add hooks or servers that run on every future session — a technique seen in real npm supply-chain attacks against coding agents.", fix: 'Agent configuration should be changed by you, not by a skill. Remove the write.' },
  { id: 'SG403', title: 'Tampers with git hooks', severity: 'medium', why: 'Writing `.git/hooks` or changing `core.hooksPath` runs code on every commit or checkout.', fix: 'Remove it unless it is a documented, opt-in feature.' },

  // --- destructive or weakening
  { id: 'SG501', title: 'Destructive command', severity: 'high', why: 'Recursive deletes of the home directory or disk, formatting, or force-pushing over history cannot be undone.', fix: 'Scope deletions to the project and ask before destructive operations.' },
  { id: 'SG502', title: 'Disables security protections', severity: 'high', why: 'Turning off antivirus, the firewall, SELinux or Gatekeeper opens the machine to everything else.', fix: 'Remove it.' },
  { id: 'SG503', title: 'Cryptocurrency miner', severity: 'critical', why: 'Miner binaries and stratum pool URLs have no place in an agent tool.', fix: 'Remove the item.' },

  // --- MCP servers
  { id: 'SG601', title: 'MCP server runs an unpinned package', severity: 'medium', why: '`npx -y some-server` (no version) runs whatever the latest release is every time the agent starts. A compromised or hijacked package version reaches you automatically — the npm-side version of a rug pull.', fix: 'Pin an exact version (`some-server@1.4.2`) and update deliberately.' },
  { id: 'SG602', title: 'MCP server over plain HTTP', severity: 'high', why: 'Tool calls, results and any auth headers travel unencrypted and can be read or altered on the network.', fix: 'Use https, or keep the server on localhost.' },
  { id: 'SG603', title: 'Secret stored in plain text', severity: 'medium', why: 'API keys written into agent config files end up in backups, dotfile repos and screenshots, and every server and skill that can read the file can read them.', fix: 'Reference an environment variable or the OS keychain instead of pasting the key.' },
  { id: 'SG604', title: 'MCP server is a shell command', severity: 'medium', why: 'A server started via `bash -c` / `cmd /c` / `powershell -Command` can run anything, and its real behaviour is in the command string rather than a reviewable package.', fix: 'Point the config at the actual server binary or package.' },
  { id: 'SG605', title: 'MCP server can reach the whole filesystem', severity: 'medium', why: 'A filesystem root of `/`, a drive root or your whole home directory gives every tool call access to keys, browser data and other projects.', fix: 'Limit the server to the project directories it needs.' },
  { id: 'SG606', title: 'MCP server runs a privileged container', severity: 'high', why: '`--privileged`, mounting `/` or the Docker socket, or host networking/PID make the container equivalent to root on the host.', fix: 'Drop the flag and mount only what the server needs.' },
  { id: 'SG607', title: 'Possible typosquat of a well-known package', severity: 'high', why: 'The package name is one or two characters away from a well-known MCP server. Typosquatted packages are a standard way to get malware installed.', fix: 'Check the exact name and publisher on the registry.' },
  { id: 'SG608', title: 'Remote MCP server', severity: 'low', why: 'The tools are defined and executed on someone else\u2019s server; their descriptions (which the model obeys) can change at any time without a new install.', fix: 'Use `skill-guard lock` to be told when your configuration changes, and only connect to providers you trust.' },

  // --- hooks
  { id: 'SG701', title: 'Hook runs automatically', severity: 'info', why: 'Hooks run shell commands with your privileges on agent events (session start, every prompt, every tool call) without asking. That is fine for hooks you wrote; worth knowing for hooks a plugin brought.', fix: 'Review the command. Use `skill-guard lock` so new or changed hooks are flagged.' },
  { id: 'SG702', title: 'Hook talks to the network', severity: 'medium', why: 'A hook that contacts a server runs on every matching event, so whatever it sends leaves your machine continuously.', fix: 'Check what is sent. Prefer hooks that only touch local files.' },

  // --- packaging
  { id: 'SG801', title: 'Install script', severity: 'medium', why: '`preinstall`/`install`/`postinstall`/`prepare` scripts run when the package is installed — before you ever use it.', fix: 'Check what the script does; prefer packages that need none.' },
  { id: 'SG802', title: 'Bundled executable', severity: 'medium', why: 'Compiled binaries inside a skill or plugin cannot be reviewed like scripts.', fix: 'Build from source you can read, or download from the vendor with a checksum.' },
  { id: 'SG803', title: 'Unrestricted tool access', severity: 'low', why: 'The skill asks for unrestricted shell access (`allowed-tools: Bash` or `*`), so anything its instructions say can be executed without per-command approval.', fix: 'Scope it, e.g. `Bash(git status:*)`.' },
];

export const RULE_BY_ID = new Map(RULES.map((r) => [r.id, r]));
