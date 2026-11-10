import type { Finding, Item, RuleInfo, Severity, TextUnit, UnitKind } from './types.ts';
import { SEVERITY_ORDER } from './types.ts';
import { findHidden, reveal } from './unicode.ts';
import { home, lineAt, lineCol, maskSecrets } from './util.ts';

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

// ---------------------------------------------------------------- helpers

const DOWN: Record<Severity, Severity> = { critical: 'high', high: 'medium', medium: 'low', low: 'info', info: 'info' };
const lower = (s: Severity, steps = 1): Severity => (steps <= 0 ? s : lower(DOWN[s], steps - 1));

/** Words that mean the text is warning *against* the thing it mentions. */
const NEGATION = /\b(never|not|don'?t|do not|must not|mustn'?t|should not|shouldn'?t|avoid|refuse|prevent|block(?:s|ed)?|detect(?:s|ed|ion)?|flag(?:s|ged)?|warn(?:s|ing)?|forbid(?:den)?|disallow(?:ed)?|prohibit(?:ed)?|without asking first|unless)\b|禁止|不要|切勿|不得|不能|避免/i;

function negated(text: string, index: number): boolean {
  const start = Math.max(0, text.lastIndexOf('\n', index - 1) + 1, index - 120);
  return NEGATION.test(text.slice(start, index));
}

/** "never run …", "do not execute …" earlier in the same line: the sentence forbids running what follows. */
function forbidsRunning(text: string, index: number): boolean {
  const start = Math.max(0, text.lastIndexOf('\n', index - 1) + 1, index - 120);
  return /\b(never|do not|don'?t|must not|should not|shouldn'?t)\s+(run|execute|pipe|paste|copy|use|follow)\b(?![^`]*\b(just|instead|then)\b)/i.test(text.slice(start, index));
}

/** The match sits inside quotes — the text is *talking about* the phrase (e.g. warning about it), not saying it. */
function quoted(text: string, index: number, length: number): boolean {
  const before = text.slice(Math.max(0, index - 3), index);
  const after = text.slice(index + length, index + length + 40);
  return /["“'`‘「(]\s*$/.test(before) || (/["“`‘「]/.test(text.slice(Math.max(0, index - 40), index)) && /^[^"”`’」\n]{0,40}["”`’」]/.test(after));
}

/** Test suites and fixtures are full of attack strings on purpose; they are not what the agent runs. */
export function isTestPath(file: string | undefined): boolean {
  if (!file) return false;
  return /[\\/](tests?|__tests__|spec|specs|fixtures?|testdata|test-data|__fixtures__|e2e)[\\/]|\.(test|spec)\.[a-z]+$|(^|[\\/])test_[^\\/]+\.py$|_test\.(py|go)$/i.test(file);
}

/**
 * In code: the match is in a comment, a docstring or a backtick-quoted span of
 * prose — documentation about the thing, not the thing.
 */
function commentish(text: string, index: number, length: number, file = ''): boolean {
  const lineStart = text.lastIndexOf('\n', index - 1) + 1;
  const head = text.slice(lineStart, index);
  if (/^\s*(#|\/\/|\*|\/\*|--\s|REM\s|;)/i.test(head) || /\s(#|\/\/)\s/.test(head)) return true;
  // Backticks are Markdown-in-docstrings in Python/shell — but real template strings in JS/TS.
  const jsLike = /\.(m?[jt]sx?|cjs|cts|mts)$/i.test(file);
  if (!jsLike && /`[^`]*$/.test(head) && /^[^`\n]*`/.test(text.slice(index + length))) return true;
  const before = text.slice(0, index);
  return ((before.match(/"""|'''/g) ?? []).length & 1) === 1;
}

const SHELL_FILE = /\.(sh|bash|zsh|fish|ps1|psm1|bat|cmd)$/i;

const IMPERATIVE_NEAR = /\b(use|run|set|enable|add|pass|launch|start|always|turn on|switch to|configure|with|invoke|call|execute|append)\b|使用|开启|设置|加上/i;

/** Inside a fenced code block in Markdown: an example, not a directive (but still code the model may run). */
function inFence(text: string, index: number): boolean {
  const before = text.slice(0, index);
  return ((before.match(/^\s*```/gm) ?? []).length & 1) === 1;
}

interface Ctx {
  unit: TextUnit;
  out: Finding[];
}

function emit(ctx: Ctx, ruleId: string, index: number, severity: Severity, message: string, evidence?: string): void {
  const rule = RULE_BY_ID.get(ruleId);
  if (!rule) return;
  const { unit } = ctx;
  const pos = lineCol(unit.text, index);
  const f: Finding = {
    rule: ruleId,
    severity,
    title: rule.title,
    message,
    item: unit.item.id,
    evidence: maskSecrets(evidence ?? lineAt(unit.text, index)),
  };
  // A hook or MCP command string is not a file region; a line number would point at the wrong place.
  if (unit.kind !== 'command') {
    f.line = pos.line + (unit.lineOffset ?? 1) - 1;
    f.column = pos.column;
  }
  if (unit.file) f.file = unit.file;
  ctx.out.push(f);
}

/**
 * Base severity of a rule adjusted for where the text is: lower in docs, test
 * files, fenced examples, quoted mentions and sentences phrased as warnings.
 */
function contextual(ruleId: string, ctx: Ctx, index: number, perKind: Partial<Record<UnitKind, number>> = {}, length = 0, quotes = true): Severity | null {
  const rule = RULE_BY_ID.get(ruleId);
  if (!rule) return null;
  const { unit } = ctx;
  let sev = lower(rule.severity, perKind[unit.kind] ?? 0);
  const prose = unit.kind === 'instructions' || unit.kind === 'docs' || unit.kind === 'metadata';
  if (prose && negated(unit.text, index)) sev = lower(sev, 2);
  // "`X` does not mean ...", "`X` is not allowed": explaining the thing, not asking for it.
  if (prose && /^[`"'\s)]{0,4}(does not|doesn'?t|is not|isn'?t|won'?t|will not|should not|must not|cannot|can'?t)\b/i.test(unit.text.slice(index + length, index + length + 60))) sev = lower(sev, 2);
  // Command rules skip the quoted downgrade (a backticked command is still a command) — unless a
  // negation directly governs running it: "Never run `curl … | sh`".
  if (prose && length && quoted(unit.text, index, length) && (quotes || forbidsRunning(unit.text, index))) sev = lower(sev, 2);
  if (prose && inFence(unit.text, index)) sev = lower(sev, 1);
  if (unit.kind === 'code' && commentish(unit.text, index, length, unit.file)) sev = lower(sev, 2);
  if (isTestPath(unit.file)) sev = lower(sev, 2);
  return sev;
}

function eachMatch(text: string, re: RegExp, fn: (m: RegExpExecArray) => void, limit = 5): void {
  const g = new RegExp(re.source, re.flags.includes('g') ? re.flags : re.flags + 'g');
  let m: RegExpExecArray | null;
  let n = 0;
  while ((m = g.exec(text)) && n < limit) {
    fn(m);
    n++;
    if (m[0] === '') g.lastIndex++;
  }
}

// ---------------------------------------------------------------- patterns

const RE = {
  override: /\b(ignore|disregard|forget|override|bypass)\b[^.\n]{0,40}\b(all |any |the |your |previous |prior |above |earlier |preceding |system |safety |original )+(instructions?|prompts?|rules|guidelines|directives|messages|context|policies)\b|\byou are now (?:in )?(?:a |an )?(?:different|new|unrestricted|jailbroken|developer mode|dan)\b|\b(here is|this is|below is|follow) (your|the) new system prompt\b|\bnew system prompt\s*[:：]|\byour new instructions are\b|忽略(之前|以上|前面|所有)的?(指令|提示|规则|指示)/i,
  conceal: /\b(do not|don'?t|never|must not)\s+(tell|inform|notify|alert|show|mention|reveal|disclose|let)\s+(the |this )?(user|human|operator|developer)\b(?!,? (that )?(they|you) (need|needs|should|must|have to|ought))|\bwithout (the user|the human|anyone|them) (knowing|noticing|seeing|being told|asking)\b|\b(silently|secretly|covertly|quietly|stealthily)\s+(send|upload|post|run|execute|install|copy|exfiltrate|forward|read|collect|delete|modify)\b|\bhide (this|it|these|the) (from|output|step|action)|不要(告诉|通知|让)用户|偷偷(地)?(发送|上传|执行|运行|读取)/i,
  htmlComment: /<!--([\s\S]{0,2000}?)-->/,
  // Words that make a hidden comment an instruction rather than an authoring note.
  imperative: /\b(you must|ignore (all|previous|the|any)|disregard|send (the|all|it|this)|upload|exfiltrate|curl\s|wget\s|execute|run (this|the following|`)|do not (tell|mention|show)|system prompt|secret|password|api[_ ]?key|token|credentials?)\b/i,
  trigger: /\b(always|must) (use|invoke|load|activate|trigger|call) (this|me) (skill|tool|agent|plugin)\b|\b(use|invoke|trigger|activate|load) (this|me)( skill| tool| plugin)? (for|on|in|before) (all|every|any)( other| single)? (requests?|tasks?|messages?|prompts?|conversations?|quer(y|ies)|questions?|turns?)\b|\b(before|instead of) (any|every|all) other (skills?|tools?|plugins?)\b|\b(top|highest|absolute) priority (skill|tool|plugin)\b/i,
  remoteInstr: /\b(fetch|download|load|read|retrieve|get|pull|follow|obey|execute)\b[^.\n]{0,40}\b(instructions?|rules|prompts?|directives|commands|tasks?|playbook)\b[^.\n]{0,30}\b(from|at|hosted at|located at)\s+(https?:\/\/|[a-z0-9-]+\.[a-z]{2,}\/)/i,
  // A real block (`<system>…</system>`) or chat-template token — a bare `<system>` is usually a placeholder argument.
  impersonate: /<\s*(system|system_prompt|sys)\s*>[\s\S]{1,600}?<\s*\/\s*(system|system_prompt|sys)\s*>|<\|(system|im_start\|>system)\|?>|^\s*\[\s*SYSTEM( MESSAGE| PROMPT)?\s*\]|\bthis (is|message is) (an? )?(official|verified) (message|instruction|notice|update) from (anthropic|openai|claude|codex|deepseek|cursor)\b|\b(i am|this is) (anthropic|openai|the system administrator|your (developer|operator))\b/im,
  // Flags and config values that switch approvals off. Mode *names* in prose are only flagged when used as an instruction.
  noApprovalFlag: /--dangerously-skip-permissions\b|\bdangerouslyDisableSandbox["']?\s*[:=]\s*true|["']?(defaultMode|permissionMode|permission_mode)["']?\s*[:=]\s*["']?bypassPermissions|\bsandbox(_mode)?["']?\s*[:=]\s*["']?danger-full-access|\bapproval[_-]policy["']?\s*[:=]\s*["']?never\b|\s--yolo\b|\s--full-auto\b|--permission-mode[\s=]+bypassPermissions/i,
  noApprovalWords: /\bbypassPermissions\b|\bdanger-full-access\b|\byolo mode\b|\bauto[- ]?approve (all|every|everything)\b|\bskip (all )?(permission|approval|confirmation) (prompts?|checks?)\b|\b(don'?t|do not|never) ask (the user )?(for )?(permission|approval|confirmation)\b/i,
  netSend: /\bcurl\b[^\n|;&]*?(\s-(d|F|T)\b|\s--(data(-binary|-raw|-urlencode)?|form|upload-file|json)\b|-X\s*(POST|PUT))|\bwget\b[^\n]*--post-(data|file)|\b(Invoke-WebRequest|Invoke-RestMethod|iwr|irm)\b[^\n]*-(Method\s+(Post|Put)|Body|InFile)\b|\brequests\.(post|put|patch)\s*\(|\bhttpx\.(post|put)\s*\(|\baxios\.(post|put)\s*\(|\bfetch\s*\([^)]*\{[^}]*method\s*:\s*['"`](POST|PUT)|\burllib\.request\.(urlopen|Request)\s*\([^)]*data\s*=|\b(nc|ncat|netcat|socat)\s+-?[a-z]*\s*\d{1,3}(\.\d{1,3}){3}|\bscp\s+[^\n]*\S+@\S+:|\bsend (it|them|this|the (results?|data|contents?|files?|keys?|tokens?|output)) to\s+(https?:\/\/|\S+@\S+\.)|\b(upload|post|exfiltrate|forward) (it|them|this|the [\w ]{1,30}) to\s+https?:\/\//i,
  exfilHost: /\b(webhook\.site|requestbin\.(?:com|net)|pipedream\.net|[a-z0-9-]+\.ngrok(?:-free)?\.(?:io|app|dev)|ngrok\.io|burpcollaborator\.net|oastify\.com|[a-z0-9]+\.oast\.(?:fun|live|pro|site|me|online)|interact\.sh|discord(?:app)?\.com\/api\/webhooks|hooks\.slack\.com\/services|api\.telegram\.org\/bot|pastebin\.com\/api|transfer\.sh|file\.io|0x0\.st|requestcatcher\.com|beeceptor\.com|canarytokens\.com)/i,
  secretFiles: /(~|\$HOME|%USERPROFILE%|\$env:USERPROFILE|\/home\/\w+|\/Users\/\w+|C:\\Users\\\w+)?[\\/]?\.(ssh[\\/]|aws[\\/]credentials|azure[\\/]|kube[\\/]config|docker[\\/]config\.json|netrc\b|npmrc\b|pypirc\b|git-credentials\b|gnupg[\\/]|config[\\/]gh[\\/]hosts\.ya?ml|config[\\/]gcloud[\\/]|claude[\\/]\.credentials\.json|codex[\\/]auth\.json|dsh[\\/]\.credentials\.ya?ml)|\bid_(rsa|ed25519|ecdsa|dsa)\b(?!\.pub)|\bwallet\.dat\b|\b(metamask|exodus|electrum|phantom)\b[^\n]{0,30}\b(vault|wallet|keystore|seed)\b|User Data[\\/](Default|Profile \d+)[\\/](Login Data|Cookies|Web Data)|\b(Cookies\.sqlite|key4\.db|logins\.json)\b|\/etc\/(shadow|sudoers)\b|Library[\\/]Keychains[\\/]|\bsecurity find-(generic|internet)-password\b|\bseed phrase\b/i,
  /** Verbs that turn a mention of a secret file into actually reading or moving it. */
  readVerb: /\b(cat|type|less|head|tail|more|cp|copy|scp|rsync|tar|zip|base64|xxd|open|read(File|_text|lines|All)?|readFileSync|Get-Content|gc|Copy-Item|send|upload|post|exfiltrate|collect|harvest|steal|dump|extract|print|include|attach|grab)\b|读取|上传|发送|复制/i,
  // Serialising or printing the whole environment. (Copying it into a subprocess env is routine and not flagged.)
  envDump: /\bprintenv\s*(?:$|[|>;&])|\bGet-ChildItem\s+env:\s*(?:$|[|>])|\bgci\s+env:\s*(?:$|[|>])|json\.dumps\(\s*(dict\()?\s*os\.environ\b|\bprint\(\s*(dict\()?\s*os\.environ\s*\)|JSON\.stringify\(\s*process\.env\s*[,)]|console\.log\(\s*process\.env\s*\)|\[Environment\]::GetEnvironmentVariables\(\)\s*(\||$)/m,
  /** The bare `env` command, only meaningful in shell context (in Python/JS `env` is just a variable name). */
  shellEnv: /(?:^|[;&|]\s*|\$\(\s*)env\s*(?:\||>|$)/m,
  dlExec: /\b(curl|wget)\b[^\n|]*\|\s*(sudo\s+)?(ba|z|da|k)?sh\b|\b(curl|wget)\b[^\n|]*\|\s*(sudo\s+)?(python3?|node|perl|ruby|php)\b|\b(iwr|irm|Invoke-WebRequest|Invoke-RestMethod|\(New-Object\s+(System\.)?Net\.WebClient\)\.DownloadString)\b[^\n]*\|\s*(iex|Invoke-Expression)\b|\b(iex|Invoke-Expression)\s*\(?\s*\(?\s*(New-Object\s+(System\.)?Net\.WebClient\)\.DownloadString|iwr|irm|Invoke-WebRequest|Invoke-RestMethod)|\b(ba)?sh\s+<\(\s*(curl|wget)\b|\beval\s+"?\$\(\s*(curl|wget)\b|\bpython3?\s+-c\s+["']?\$\(\s*(curl|wget)/i,
  encodedExec: /\b(powershell|pwsh)(\.exe)?\b[^\n]*\s-(e|ec|en|enc|enco|encod|encode|encodedcommand)\s+[A-Za-z0-9+/=]{20,}|\bbase64\s+(-d|--decode|-D)\b[^\n]*\|\s*(ba|z)?sh\b|\b(exec|eval)\s*\(\s*(base64\.b64decode|codecs\.decode|bytes\.fromhex|zlib\.decompress|marshal\.loads)|\beval\s*\(\s*atob\s*\(|\b(new\s+)?Function\s*\(\s*atob\s*\(|\bFromBase64String\b[^\n]{0,200}\b(iex|Invoke-Expression)\b|\b(iex|Invoke-Expression)\b[^\n]{0,200}\bFromBase64String\b|\beval\s*\(\s*Buffer\.from\([^)]*['"]base64['"]\)/i,
  remoteEval: /\b(exec|eval)\s*\(\s*(requests\.get|urllib\.request\.urlopen|urlopen|httpx\.get)\s*\(|\b(eval|new\s+Function|Function)\s*\(\s*await\s*\(?\s*(await\s+)?fetch\s*\(|\bvm\.runIn\w*Context\s*\(\s*await\s+fetch|\bimport\s*\(\s*['"`]https?:\/\//i,
  blob: /(?<![A-Za-z0-9+/=])[A-Za-z0-9+/]{400,}={0,2}(?![A-Za-z0-9+/=])|(?:\\x[0-9a-fA-F]{2}){100,}/,
  persist: /(>>?|tee\s+-a|Add-Content|Out-File[^\n]*-Append|echo[^\n]*>>)\s*["']?(~|\$HOME|\$env:USERPROFILE)?[\\/]?\.(bashrc|bash_profile|zshrc|zprofile|profile|config[\\/]fish[\\/]config\.fish)\b|\$PROFILE\b[^\n]*(Add-Content|Set-Content|Out-File|>>)|(Add-Content|Set-Content|Out-File)[^\n]*\$PROFILE\b|\bcrontab\s+(-[lr]\s*\|.*|-\s*$|[^-\s][^\n]*)|\(crontab\s+-l|\bschtasks(\.exe)?\s+\/create\b|\bRegister-ScheduledTask\b|\breg(\.exe)?\s+add\s+["']?HK(CU|LM)[^\n]*\\(Run|RunOnce)\b|\b(New|Set)-ItemProperty\b[^\n]*\\CurrentVersion\\Run\b|\blaunchctl\s+(load|bootstrap)\b|Library[\\/]LaunchAgents[\\/]|\bsystemctl\s+--user\s+(enable|start)\b|\.config[\\/]systemd[\\/]user[\\/]|Start Menu[\\/]Programs[\\/]Startup/i,
  agentConfig: /(\.claude[\\/]settings(\.local)?\.json|\.claude\.json\b|\.codex[\\/]config\.toml|\.cursor[\\/]mcp\.json|claude_desktop_config\.json|[\\/]hooks[\\/]hooks\.json|\.mcp\.json\b|\.dsh[\\/](cordis|profiles)|\bCLAUDE\.md\b|\bAGENTS\.md\b)/,
  writeVerb: /\b(writeFile(Sync)?|appendFile(Sync)?|createWriteStream|open\s*\([^)]*['"](w|a)\+?b?['"]|\.write_text|\.write\(|Set-Content|Add-Content|Out-File|sed\s+-i|tee\b|cp\s|mv\s|Copy-Item|Move-Item|echo\b[^\n]*>|>\s*["']?[~$\w./\\-]*)/,
  // Writing into .git/hooks or pointing hooksPath somewhere. `core.hooksPath=/dev/null` *disables* hooks and is defensive.
  gitHooks: /\.git[\\/]hooks[\\/]|core\.hooksPath(?![\s=,"']+(\/dev\/null|NUL|""|''))/,
  destructive: /\brm\s+(-[a-zA-Z]*r[a-zA-Z]*f|-[a-zA-Z]*f[a-zA-Z]*r)[a-zA-Z]*\s+(--no-preserve-root\s+)?(\/(\s|$|\*)|~\/?(\s|$|\*)|\$HOME\/?(\s|$|\*)|\/\*|\.\.\/\.\.)|\bRemove-Item\b[^\n]*-Recurse[^\n]*(\s(C:\\|~\\?\s|\$env:USERPROFILE\\?\s|\$HOME\b))|\b(del|erase)\s+\/[sq]\s+\/[sq]\s+[A-Za-z]:\\|\bformat\s+[a-zA-Z]:(\s|$)|\bmkfs(\.\w+)?\s+\/dev\/|\bdd\s+if=\/dev\/(zero|random|urandom)\s+of=\/dev\/[sh]d|\bchmod\s+-R\s+777\s+\/(\s|$)|:\(\)\s*\{\s*:\|:&\s*\};:|\bgit\s+push\s+(--force|-f)\b[^\n]*\b(main|master)\b|\bDROP\s+(DATABASE|SCHEMA)\b/i,
  weaken: /\bSet-MpPreference\b[^\n]*-Disable\w*\s+\$?true|\bAdd-MpPreference\b[^\n]*-Exclusion(Path|Process)|\bnetsh\s+advfirewall\s+set\s+\w+\s+state\s+off|\bsetenforce\s+0\b|\bufw\s+disable\b|\bspctl\s+--master-disable\b|\bcsrutil\s+disable\b|\bsystemctl\s+(stop|disable)\s+(firewalld|apparmor|auditd)\b|\bxattr\s+-[a-z]*d[a-z]*\s+com\.apple\.quarantine\b/i,
  miner: /\bxmrig\b|stratum\+(tcp|ssl):\/\/|\b(cpuminer|minerd|nbminer|t-rex|lolminer|phoenixminer)\b|--donate-level\b|\bnicehash\b/i,
  network: /\bhttps?:\/\/(?!(localhost|127\.0\.0\.1|0\.0\.0\.0|\[::1\])[:/])[^\s'"`)<>]+|\b(curl|wget|Invoke-WebRequest|Invoke-RestMethod|iwr|irm|fetch\s*\(|requests\.|urllib|httpx|axios|http\.request|https\.request|net\.connect|socket\.connect)\b/i,
};

// ---------------------------------------------------------------- text rules

/** Run every content rule over one unit of text. */
export function scanUnit(unit: TextUnit): Finding[] {
  const ctx: Ctx = { unit, out: [] };
  const t = unit.text;
  const k = unit.kind;
  const prose = k === 'instructions' || k === 'metadata' || k === 'docs';

  // SG103 invisible characters — everywhere
  for (const run of findHidden(t).slice(0, 10)) {
    const base: Severity = run.kind === 'tag' ? 'critical' : run.kind === 'bidi' ? 'high' : 'medium';
    // Tag characters stay critical even in tests: they have no legitimate use and are trivial to copy elsewhere.
    const sev = run.kind === 'tag' ? base : lower(base, (k === 'docs' ? 1 : 0) + (isTestPath(unit.file) ? 2 : 0));
    const what =
      run.kind === 'tag'
        ? `${[...t.slice(run.index, run.index + run.length)].length} Unicode Tag characters${run.decoded ? ` spelling "${run.decoded.slice(0, 120)}"` : ''}`
        : run.kind === 'bidi'
          ? 'a bidirectional override (text displays in a different order than the model reads it)'
          : run.kind === 'zero-width'
            ? `${[...t.slice(run.index, run.index + run.length)].length} zero-width character(s)`
            : `${[...t.slice(run.index, run.index + run.length)].length} variation selectors in a row (can smuggle bytes)`;
    emit(ctx, 'SG103', run.index, sev, `Contains ${what}.`, reveal(lineAt(t, run.index, 200)));
  }

  if (prose || k === 'code' || k === 'command') {
    // SG101 / SG102: prose only (code legitimately contains these words in strings and tests)
    if (prose)
      eachMatch(t, RE.override, (m) => {
        const sev = contextual('SG101', ctx, m.index, { docs: 2 }, m[0].length);
        if (sev) emit(ctx, 'SG101', m.index, sev, `Tells the model to "${m[0].slice(0, 80)}".`);
      });
    if (prose)
      eachMatch(t, RE.conceal, (m) => {
        const sev = contextual('SG102', ctx, m.index, { docs: 2 }, m[0].length);
        if (sev) emit(ctx, 'SG102', m.index, sev, `Asks the model to keep something from the user: "${m[0].slice(0, 80)}".`);
      });
    if (k === 'instructions')
      eachMatch(t, RE.htmlComment, (m) => {
        const body = m[1] ?? '';
        if (inFence(t, m.index)) return; // an HTML example, not a hidden note
        if (RE.imperative.test(body) && !/skill-guard-ignore|prettier-ignore|markdownlint|toc|eslint/i.test(body)) {
          const sev = contextual('SG104', ctx, m.index) ?? 'medium';
          emit(ctx, 'SG104', m.index, sev, 'An HTML comment (invisible when rendered) contains instructions.', body.trim().replace(/\s+/g, ' ').slice(0, 160));
        }
      });
    // SG105: the description decides when an agent loads an item, so that is where hijacking bites.
    if (k === 'metadata')
      eachMatch(t, RE.trigger, (m) => {
        const sev = contextual('SG105', ctx, m.index, {}, m[0].length);
        if (sev) emit(ctx, 'SG105', m.index, sev, `Claims priority over other requests: "${m[0]}".`);
      });
    if (prose)
      eachMatch(t, RE.remoteInstr, (m) => {
        const sev = contextual('SG106', ctx, m.index, { docs: 2 }, m[0].length);
        if (sev) emit(ctx, 'SG106', m.index, sev, 'Tells the model to load its instructions from a remote location.');
      });
    if (prose)
      eachMatch(t, RE.impersonate, (m) => {
        if (inFence(t, m.index)) return;
        const sev = contextual('SG107', ctx, m.index, { docs: 2 }, m[0].length);
        if (sev) emit(ctx, 'SG107', m.index, sev, `Impersonates a system or official source: "${m[0].slice(0, 60).replace(/\s+/g, ' ')}".`);
      });
    // SG108: flags/config values always count; mode names in prose only when used as an instruction.
    eachMatch(t, RE.noApprovalFlag, (m) => {
      const sev = contextual('SG108', ctx, m.index, { docs: 2 }, m[0].length, false);
      if (sev) emit(ctx, 'SG108', m.index, sev, `Disables approvals or the sandbox (${m[0].trim()}).`);
    });
    if (prose)
      eachMatch(t, RE.noApprovalWords, (m) => {
        const sentence = t.slice(Math.max(0, t.lastIndexOf('.', m.index) + 1, t.lastIndexOf('\n', m.index) + 1), m.index);
        if (!IMPERATIVE_NEAR.test(sentence)) return;
        const sev = contextual('SG108', ctx, m.index, { docs: 2, instructions: 1 }, m[0].length);
        if (sev) emit(ctx, 'SG108', m.index, sev, `Asks to run without approvals (${m[0].trim()}).`);
      });
  }

  // exfiltration
  eachMatch(t, RE.exfilHost, (m) => {
    const sev = contextual('SG202', ctx, m.index, { docs: 2 }, m[0].length, false);
    if (sev) emit(ctx, 'SG202', m.index, sev, `References ${m[0]}, a service commonly used to receive stolen data.`);
  });
  eachMatch(t, RE.netSend, (m) => {
    // In code, POSTing to an API is routine; it matters when the destination is a hard-coded external host.
    const line = lineAt(t, m.index, 600);
    const external = /https?:\/\/(?!(localhost|127\.0\.0\.1|0\.0\.0\.0|\[::1\])[:/])[a-z0-9.-]+\.[a-z]{2,}/i.test(line);
    const relative = /\(\s*['"`]\/[^/]/.test(line);
    if ((k === 'code' || k === 'metadata') && relative) return;
    // RFC 2606 / documentation placeholders: nothing real receives the data.
    const placeholder = /https?:\/\/([a-z0-9-]+\.)*(example\.(com|org|net)|[a-z0-9-]+\.(example|test|invalid|localhost)|company\.com|your-?(domain|server|api|host|company)[a-z0-9.-]*|acme\.(com|corp))[:/'"\s]/i.test(line);
    // Code: routine unless the target is hard-coded. Instructions: an instruction to send somewhere unnamed is weaker.
    const extra = (placeholder ? 2 : 0) + (k === 'code' ? (external ? 1 : 2) : k === 'instructions' && !external ? 1 : 0);
    const sev = contextual('SG201', ctx, m.index, { docs: 2, metadata: 1 }, 0);
    if (sev) emit(ctx, 'SG201', m.index, lower(sev, extra), external ? 'Sends data to an external server.' : 'Sends data to a server.');
  });
  eachMatch(t, RE.secretFiles, (m) => {
    // A mention is not access: require a read/copy/send verb on the line for full severity.
    const line = lineAt(t, m.index, 600);
    const reads = RE.readVerb.test(line);
    const sev = contextual('SG203', ctx, m.index, { docs: 2, code: 1, metadata: 2 }, m[0].length);
    if (sev) emit(ctx, 'SG203', m.index, reads ? sev : lower(sev, 2), `${reads ? 'Reads' : 'Mentions'} ${m[0].trim()}.`);
  });
  if (k !== 'docs') {
    const envRes = k === 'command' || k === 'instructions' || SHELL_FILE.test(unit.file ?? '') ? [RE.envDump, RE.shellEnv] : [RE.envDump];
    for (const re of envRes)
      eachMatch(t, re, (m) => {
        const sev = contextual('SG204', ctx, m.index, { instructions: 1 }, m[0].length);
        if (sev) emit(ctx, 'SG204', m.index, sev, 'Prints or serialises the whole environment (API keys and tokens live there).');
      });
  }

  // execution
  eachMatch(t, RE.dlExec, (m) => {
    const sev = contextual('SG301', ctx, m.index, { docs: 2 }, m[0].length, false);
    if (sev) emit(ctx, 'SG301', m.index, sev, 'Pipes a download straight into an interpreter.');
  });
  eachMatch(t, RE.encodedExec, (m) => {
    const sev = contextual('SG302', ctx, m.index, { docs: 1 }, m[0].length, false);
    if (sev) emit(ctx, 'SG302', m.index, sev, 'Decodes and executes hidden code.');
  });
  if (k === 'code')
    eachMatch(t, RE.remoteEval, (m) => {
      const sev = contextual('SG303', ctx, m.index);
      if (sev) emit(ctx, 'SG303', m.index, sev, 'Evaluates code downloaded at run time.');
    });
  if (k !== 'docs' && k !== 'metadata')
    eachMatch(
      t,
      RE.blob,
      (m) => {
        // data: URIs for images and fonts are common and harmless in HTML/CSS assets
        if (/data:(image|font|application\/(font|x-font))[^,]*,\s*$/i.test(t.slice(Math.max(0, m.index - 60), m.index))) return;
        const sev = contextual('SG304', ctx, m.index, {}) ?? 'medium';
        emit(ctx, 'SG304', m.index, k === 'instructions' ? 'high' : sev, `A ${m[0].length}-character encoded blob.`, m[0].slice(0, 60) + '…');
      },
      2,
    );

  // persistence & tampering
  eachMatch(t, RE.persist, (m) => {
    const line = lineAt(t, m.index, 600);
    let sev = contextual('SG401', ctx, m.index, { docs: 2 }, m[0].length, false);
    // A start-up location named in a list is not a write to it.
    if (sev && /LaunchAgents|systemd|Startup/i.test(m[0]) && !RE.writeVerb.test(line)) sev = lower(sev, 2);
    // `echo 'export NAME="value"' >> ~/.bashrc` is a routine setup step; only commands are persistence.
    if (sev && /^\s*(echo|printf)\s+["']?export\s+[A-Za-z_]\w*=[^\n]*>>/.test(line) && !/\$\(|`|\b(curl|wget|eval|source|nohup|bash|sh|python3?|node)\b|https?:\/\//.test(line.replace(/\$PATH|\$HOME/g, ''))) sev = lower(sev, 2);
    if (sev) emit(ctx, 'SG401', m.index, sev, 'Makes code run again outside the agent session.');
  });
  if (k === 'code' || k === 'command')
    eachMatch(t, RE.agentConfig, (m) => {
      const line = lineAt(t, m.index, 400);
      if (!RE.writeVerb.test(line)) return;
      const sev = contextual('SG402', ctx, m.index);
      if (sev) emit(ctx, 'SG402', m.index, sev, `Writes to ${m[0]}, which configures what agents run.`);
    });
  eachMatch(t, RE.gitHooks, (m) => {
    const line = lineAt(t, m.index, 400);
    if (!RE.writeVerb.test(line) && !/core\.hooksPath[\s=]+\S/.test(line)) return;
    const sev = contextual('SG403', ctx, m.index, { docs: 2 });
    if (sev) emit(ctx, 'SG403', m.index, sev, 'Changes git hooks.');
  });

  // destructive & weakening
  eachMatch(t, RE.destructive, (m) => {
    const sev = contextual('SG501', ctx, m.index, { docs: 2 }, m[0].length, false);
    if (sev) emit(ctx, 'SG501', m.index, sev, `Destructive command: ${m[0].trim().slice(0, 60)}.`);
  });
  eachMatch(t, RE.weaken, (m) => {
    const sev = contextual('SG502', ctx, m.index, { docs: 2 }, m[0].length, false);
    if (sev) emit(ctx, 'SG502', m.index, sev, `Turns off a protection: ${m[0].trim().slice(0, 60)}.`);
  });
  eachMatch(t, RE.miner, (m) => {
    const sev = contextual('SG503', ctx, m.index, { docs: 2 }, m[0].length, false);
    if (sev) emit(ctx, 'SG503', m.index, sev, `Mining software or pool: ${m[0]}.`);
  });

  // SG205: actually reading credentials (or dumping the environment) and sending data out, in the same non-test file.
  if (k !== 'docs' && !isTestPath(unit.file)) {
    const secret = ctx.out.find((f) => (f.rule === 'SG203' || f.rule === 'SG204') && SEVERITY_ORDER[f.severity] >= SEVERITY_ORDER.medium);
    // A POST to a hard-coded host in code is only "low" on its own — next to credential access it is the whole attack.
    const send = ctx.out.find((f) => (f.rule === 'SG201' || f.rule === 'SG202') && SEVERITY_ORDER[f.severity] >= SEVERITY_ORDER.low);
    if (secret && send) {
      ctx.out.push({ ...send, rule: 'SG205', severity: 'critical', title: RULE_BY_ID.get('SG205')!.title, message: `Reads secrets (line ${secret.line}) and sends data to a server (line ${send.line}) in the same file.` });
    }
  }

  return ctx.out;
}

/** True if the text contacts the network (used for hooks and packaging rules). */
export function talksToNetwork(text: string): boolean {
  return RE.network.test(text);
}

// ---------------------------------------------------------------- MCP rules

const KNOWN_PACKAGES = [
  '@modelcontextprotocol/server-filesystem',
  '@modelcontextprotocol/server-github',
  '@modelcontextprotocol/server-gitlab',
  '@modelcontextprotocol/server-git',
  '@modelcontextprotocol/server-postgres',
  '@modelcontextprotocol/server-sqlite',
  '@modelcontextprotocol/server-slack',
  '@modelcontextprotocol/server-memory',
  '@modelcontextprotocol/server-puppeteer',
  '@modelcontextprotocol/server-brave-search',
  '@modelcontextprotocol/server-google-maps',
  '@modelcontextprotocol/server-fetch',
  '@modelcontextprotocol/server-everything',
  '@modelcontextprotocol/server-sequential-thinking',
  '@modelcontextprotocol/server-redis',
  '@modelcontextprotocol/server-gdrive',
  '@playwright/mcp',
  '@upstash/context7-mcp',
  'chrome-devtools-mcp',
  'mcp-server-fetch',
  'mcp-server-git',
  'mcp-server-time',
  '@notionhq/notion-mcp-server',
  '@stripe/mcp',
  '@sentry/mcp-server',
  'figma-developer-mcp',
  'firecrawl-mcp',
  '@browserbasehq/mcp',
  '@cloudflare/mcp-server-cloudflare',
  'mcp-remote',
  '@supabase/mcp-server-supabase',
  '@azure/mcp',
  '@heroku/mcp-server',
  '@linear/mcp',
  'exa-mcp-server',
  'tavily-mcp',
];

function editDistance(a: string, b: string, max = 3): number {
  if (Math.abs(a.length - b.length) > max) return max + 1;
  const prev = Array.from({ length: b.length + 1 }, (_, i) => i);
  for (let i = 1; i <= a.length; i++) {
    let diag = prev[0] as number;
    prev[0] = i;
    let rowMin = i;
    for (let j = 1; j <= b.length; j++) {
      const tmp = prev[j] as number;
      prev[j] = Math.min((prev[j] as number) + 1, (prev[j - 1] as number) + 1, diag + (a[i - 1] === b[j - 1] ? 0 : 1));
      diag = tmp;
      rowMin = Math.min(rowMin, prev[j] as number);
    }
    if (rowMin > max) return max + 1;
  }
  return prev[b.length] as number;
}

/** Split `pkg@1.2.3`, `@scope/pkg@^1` (npm) or `pkg==1.2.3` / `pkg>=1` (Python) into name and version. */
export function splitPackage(spec: string): { name: string; version: string } {
  const py = /^([A-Za-z0-9_.\-[\]]+)\s*(==|~=|>=|<=|!=|===)\s*(.+)$/.exec(spec);
  if (py) return { name: py[1] as string, version: (py[2] === '==' || py[2] === '===' ? '' : py[2]) + (py[3] as string) };
  const at = spec.lastIndexOf('@');
  if (at > 0) return { name: spec.slice(0, at), version: spec.slice(at + 1) };
  return { name: spec, version: '' };
}

const RUNNERS = /^(npx|bunx|pnpx)(\.cmd|\.exe)?$|^(uvx|pipx)(\.exe)?$/i;
const SECRET_VALUE = /\b(sk-(ant-|proj-)?[A-Za-z0-9_-]{20,}|gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{40,}|(AKIA|ASIA)[A-Z0-9]{16}|AIza[0-9A-Za-z_-]{35}|xox[abposr]-[A-Za-z0-9-]{10,}|glpat-[A-Za-z0-9_-]{20,}|eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}|Bearer\s+[A-Za-z0-9._~+/=-]{20,}|(sk|rk)_live_[A-Za-z0-9]{20,})\b/;

export function scanMcp(item: Item): Finding[] {
  const out: Finding[] = [];
  const s = item.mcp;
  if (!s) return out;
  const push = (rule: string, severity: Severity, message: string, evidence?: string) => {
    const r = RULE_BY_ID.get(rule)!;
    const f: Finding = { rule, severity, title: r.title, message, item: item.id, file: item.path };
    if (evidence) f.evidence = maskSecrets(evidence);
    out.push(f);
  };
  const cmd = (s.command ?? '').replace(/^.*[\\/]/, '');
  const args = s.args;
  const full = [s.command ?? '', ...args].join(' ');

  // SG601 unpinned package runners
  if (RUNNERS.test(cmd)) {
    const pkgArg = args.find((a, i) => !a.startsWith('-') && !(i > 0 && /^--?(package|from|with|p)$/.test(args[i - 1] ?? '')) && !/^(run|exec|dlx)$/.test(a));
    if (pkgArg) {
      const { name, version } = /^(git\+|https?:|github:)/.test(pkgArg) ? { name: pkgArg, version: '' } : splitPackage(pkgArg);
      if (/^(git\+|https?:|github:)/.test(pkgArg)) push('SG601', 'high', `Runs code straight from ${pkgArg.slice(0, 80)} (not a registry release).`, full);
      else if (!version || /^(latest|next|\*|x)$/i.test(version)) push('SG601', 'medium', `Runs "${name}" without a pinned version, so every start may fetch a different release.`, full);
      // SG607 typosquat — a known name is never a typosquat of another known name (server-github vs server-gitlab)
      for (const known of KNOWN_PACKAGES.includes(name.toLowerCase()) ? [] : KNOWN_PACKAGES) {
        const d = editDistance(name.toLowerCase(), known);
        if (d > 0 && d <= 2 && name.length > 6) {
          push('SG607', 'high', `"${name}" is ${d} character${d > 1 ? 's' : ''} away from the well-known "${known}".`, full);
          break;
        }
      }
    }
  }
  // SG602 / SG608 remote servers
  if (s.url) {
    const local = /^https?:\/\/(localhost|127\.\d+\.\d+\.\d+|\[::1\]|0\.0\.0\.0)(:|\/|$)/i.test(s.url);
    if (/^http:\/\//i.test(s.url) && !local) push('SG602', 'high', `Connects to ${s.url} without TLS.`, s.url);
    else if (!local) push('SG608', 'low', `Tools come from ${new URL(s.url).host}.`, s.url);
  }
  // SG603 plaintext secrets
  const secretPlaces: [string, string][] = [...Object.entries(s.env).map(([k, v]) => [`env ${k}`, v] as [string, string]), ...Object.entries(s.headers).map(([k, v]) => [`header ${k}`, v] as [string, string]), ...args.map((a, i) => [`argument ${i + 1}`, a] as [string, string])];
  if (s.url) secretPlaces.push(['url', s.url]);
  for (const [where, value] of secretPlaces) {
    if (/^\$\{?[A-Z_][A-Z0-9_]*\}?$|^\{env:|^%[A-Z_]+%$/.test(value)) continue; // a reference, not a value
    const named = /^(env|header) .*(KEY|TOKEN|SECRET|PASSWORD|PASS|AUTH|CREDENTIAL)/i.test(where) && value.length >= 16 && !/\s/.test(value) && !/^(true|false|\d+)$/i.test(value);
    if (SECRET_VALUE.test(value) || named || /[?&](api[_-]?key|token|access_token|key)=[A-Za-z0-9_-]{16,}/i.test(value)) {
      push('SG603', 'medium', `A credential is written in plain text (${where}).`, `${where} = ${value}`);
      break;
    }
  }
  // SG604 shell wrappers
  if (/^(bash|sh|zsh|dash|cmd|cmd\.exe|powershell|powershell\.exe|pwsh|pwsh\.exe)$/i.test(cmd) && args.some((a) => /^(-c|\/c|\/k|-Command|-command|-EncodedCommand|-enc|-e)$/i.test(a))) {
    // Just launching a local script is ordinary; pipes, chaining or network access in the inline command are not.
    const inline = args.join(' ');
    const simple = !/[|&;`$<>]|\b(curl|wget|iwr|irm|Invoke-|http)/i.test(inline.replace(/^\/d \/s \/c\s+/, ''));
    push('SG604', simple ? 'low' : 'medium', `Starts through ${cmd} with an inline command${simple ? ' (launches a local script)' : ''}.`, full);
  }
  // SG605 broad filesystem
  const H = home().replace(/\\/g, '/').toLowerCase().replace(/\/$/, '');
  if (/filesystem|file-?system|server-fs|mcp-fs/i.test(full)) {
    for (const a of args) {
      if (!a || a.startsWith('-')) continue;
      const raw = a.replace(/\\/g, '/').toLowerCase();
      const p = raw === '/' ? '/' : raw.replace(/\/$/, '');
      if (p === '/' || /^[a-z]:\/?$/.test(p) || p === H || p === '~' || p === '$home' || p === '${home}' || p === '%userprofile%' || p === '/users' || p === '/home') {
        push('SG605', 'medium', `Gives the server access to ${a}.`, full);
        break;
      }
    }
  }
  // SG606 privileged containers
  if (/^(docker|podman)(\.exe)?$/i.test(cmd)) {
    const joined = args.join(' ');
    const bad = /--privileged\b|(-v|--volume|--mount)[\s=]+["']?(\/|[A-Za-z]:\\?):|\/var\/run\/docker\.sock|--(network|net)[\s=]+host\b|--pid[\s=]+host\b|--cap-add[\s=]+(ALL|SYS_ADMIN)\b/i.exec(joined);
    if (bad) push('SG606', 'high', `Container option ${bad[0].trim()}.`, full);
  }
  return out;
}

// ---------------------------------------------------------------- hooks, packages, skills

export function scanHook(item: Item): Finding[] {
  const out: Finding[] = [];
  const h = item.hook;
  if (!h) return out;
  const r701 = RULE_BY_ID.get('SG701')!;
  const auto = /^(SessionStart|UserPromptSubmit|UserPromptExpansion|PreToolUse|PostToolUse|Stop|SubagentStop|Notification|PreCompact|SessionEnd)$/.test(h.event);
  out.push({
    rule: 'SG701',
    severity: 'info',
    title: r701.title,
    message: `Runs on ${h.event}${h.matcher ? ` for ${h.matcher}` : ''}${auto ? '' : ''}.`,
    item: item.id,
    file: item.path,
    ...(h.command ? { evidence: maskSecrets(h.command.slice(0, 200)) } : {}),
  });
  if (h.command && talksToNetwork(h.command)) {
    const r = RULE_BY_ID.get('SG702')!;
    out.push({ rule: 'SG702', severity: 'medium', title: r.title, message: `The ${h.event} hook contacts the network.`, item: item.id, file: item.path, evidence: maskSecrets(h.command.slice(0, 200)) });
  }
  return out;
}

const LIFECYCLE = ['preinstall', 'install', 'postinstall', 'prepare', 'preprepare', 'postprepare'];

export function scanPackageJson(item: Item, file: string, pkg: Record<string, unknown>): Finding[] {
  const out: Finding[] = [];
  const scripts = pkg.scripts && typeof pkg.scripts === 'object' ? (pkg.scripts as Record<string, unknown>) : {};
  for (const name of LIFECYCLE) {
    const cmd = typeof scripts[name] === 'string' ? (scripts[name] as string) : '';
    if (!cmd) continue;
    // `prepare: tsc` / husky are routine for developers; only flag when the script does more than build.
    const routine = /^(tsc|tsdown|tsup|unbuild|vite build|rollup|esbuild|bun run build|bun build|husky( install)?|(npm|pnpm|yarn) (run )?build|node-gyp rebuild|patch-package|ts-patch install|simple-git-hooks|lefthook install)\b/.test(cmd.trim()) && !talksToNetwork(cmd);
    if (routine && name === 'prepare') continue;
    const r = RULE_BY_ID.get('SG801')!;
    out.push({ rule: 'SG801', severity: talksToNetwork(cmd) ? 'high' : 'medium', title: r.title, message: `"${name}" runs \`${cmd.slice(0, 80)}\` at install time.`, item: item.id, file, evidence: `${name}: ${maskSecrets(cmd.slice(0, 200))}` });
  }
  return out;
}

export function scanSkillMeta(item: Item, skillMd: string): Finding[] {
  const out: Finding[] = [];
  const tools = item.meta['allowed-tools'] ?? item.meta.tools;
  const list = Array.isArray(tools) ? tools.map(String) : typeof tools === 'string' ? tools.split(/[,\s]+(?![^(]*\))/) : [];
  const broad = list.find((t) => /^(Bash|Shell|PowerShell|run_shell_command|exec|\*)$/i.test(t.trim()) || /^(Bash|Shell)\(\s*\*\s*\)$/i.test(t.trim()));
  if (broad) {
    const r = RULE_BY_ID.get('SG803')!;
    out.push({ rule: 'SG803', severity: 'low', title: r.title, message: `allowed-tools includes "${broad.trim()}".`, item: item.id, file: skillMd });
  }
  return out;
}

const BINARY_EXT = /\.(exe|dll|so|dylib|bin|node|msi|scr|com|jar|wasm|pyd|pyc|class|elf|app|deb|rpm)$/i;

export function isBinaryAsset(file: string): boolean {
  return BINARY_EXT.test(file);
}
