/** The regular expressions behind the text rules. Kept apart so they can be read (and reviewed) on their own. */

/**
 * Literal pre-filters. A pattern listed here can only match text that contains (case-insensitively)
 * at least one of its literals, so the regex is skipped when none occurs — most units contain none.
 * Each list must cover EVERY alternative of its pattern; when you add an alternative, add its
 * literal here. (The recall corpus and the detection tests catch a missing one.)
 */
/** [A-Za-z0-9+/] by char code (a regex per character is the slow part of a linear scan). */
const isB64 = (c: number) => (c >= 65 && c <= 90) || (c >= 97 && c <= 122) || (c >= 48 && c <= 57) || c === 43 || c === 47;
const EQ = 61;
const HEX_RUN = /(?:\\x[0-9a-fA-F]{2}){100,}/g;

/**
 * Long base64 runs (≥400 chars) or \xNN escape runs (≥100), in one linear pass. Same result as
 * /(?<![A-Za-z0-9+/=])[A-Za-z0-9+/]{400,}={0,2}(?![A-Za-z0-9+/=])/, which backtracks at every
 * position inside long words and was the third most expensive pattern.
 */
export function findBlobs(text: string, limit = 2): { index: number; text: string }[] {
  const out: { index: number; text: string }[] = [];
  const n = text.length;
  for (let i = 0; i < n; ) {
    if (!isB64(text.charCodeAt(i))) {
      i++;
      continue;
    }
    const start = i;
    while (i < n && isB64(text.charCodeAt(i))) i++;
    let end = i;
    while (end < n && end - i < 2 && text.charCodeAt(end) === EQ) end++;
    const next = end < n ? text.charCodeAt(end) : -1;
    if (i - start >= 400 && (start === 0 || text.charCodeAt(start - 1) !== EQ) && (next === -1 || (!isB64(next) && next !== EQ))) out.push({ index: start, text: text.slice(start, end) });
    i = end > i ? end : i;
  }
  if (text.includes('\\x')) for (const m of text.matchAll(HEX_RUN)) out.push({ index: m.index ?? 0, text: m[0] });
  // Like a global regex: leftmost first, no overlaps.
  const picked: { index: number; text: string }[] = [];
  for (const b of out.sort((a, b) => a.index - b.index)) {
    const prev = picked[picked.length - 1];
    if (!prev || b.index >= prev.index + prev.text.length) picked.push(b);
  }
  return picked.slice(0, limit);
}

export const LITERALS: Record<string, string[]> = {
  secretFiles: ['.ssh', '.aws', '.azure', '.kube', '.docker', '.netrc', '.npmrc', '.pypirc', '.git-credentials', '.gnupg', '.config', '.claude', '.codex', '.dsh', 'id_rsa', 'id_ed25519', 'id_ecdsa', 'id_dsa', 'wallet.dat', 'metamask', 'exodus', 'electrum', 'phantom', 'user data', 'cookies.sqlite', 'key4.db', 'logins.json', '/etc/', 'keychains', 'find-generic-password', 'find-internet-password', 'seed phrase'],
  exfilHost: ['webhook.site', 'requestbin.', 'pipedream.net', 'ngrok', 'burpcollaborator.net', 'oastify.com', '.oast.', 'interact.sh', 'discord', 'hooks.slack.com', 'api.telegram.org', 'pastebin.com', 'transfer.sh', 'file.io', '0x0.st', 'requestcatcher.com', 'beeceptor.com', 'canarytokens.com'],
  miner: ['xmrig', 'stratum+', 'cpuminer', 'minerd', 'nbminer', 't-rex', 'lolminer', 'phoenixminer', '--donate-level', 'nicehash'],
  weaken: ['set-mppreference', 'add-mppreference', 'netsh', 'setenforce', 'ufw', 'spctl', 'csrutil', 'systemctl', 'xattr'],
  noApprovalFlag: ['--dangerously-skip-permissions', 'dangerouslydisablesandbox', 'bypasspermissions', 'danger-full-access', 'approval', '--yolo', '--full-auto'],
  dlExec: ['curl', 'wget', 'iwr', 'irm', 'invoke-', 'downloadstring', 'iex'],
  encodedExec: ['powershell', 'pwsh', 'base64', 'exec', 'eval', 'function', 'frombase64string'],
  persist: ['.bash', '.zsh', '.zprofile', '.profile', 'config.fish', '$profile', 'crontab', 'schtasks', 'register-scheduledtask', 'reg', 'currentversion', 'launchctl', 'launchagents', 'systemctl', 'systemd', 'startup'],
};

export const RE = {
  override: /\b(ignore|disregard|forget|override|bypass)\b[^.\n]{0,40}\b(all |any |the |your |previous |prior |above |earlier |preceding |system |safety |original )+(instructions?|prompts?|rules|guidelines|directives|messages|context|policies)\b|\byou are now (?:in )?(?:a |an )?(?:different|new|unrestricted|jailbroken|developer mode|dan)\b|\b(here is|this is|below is|follow) (your|the) new system prompt\b|\bnew system prompt\s*[:：]|\byour new instructions are\b|忽略(之前|以上|前面|所有)的?(指令|提示|规则|指示)/i,
  conceal: /\b(do not|don'?t|never|must not)\s+(tell|inform|notify|alert|show|mention|reveal|disclose|let)\s+(the |this )?(user|human|operator|developer)\b(?!,? (that )?(they|you) (need|needs|should|must|have to|ought))|\b(do not|don'?t|never|must not)\s+(tell|inform|mention|reveal|disclose|say)\b[^.\n]{0,60}?\bto (the |this )?(user|human)\b|\bwithout (the user|the human|anyone|them) (knowing|noticing|seeing|being told|asking)\b|\b(silently|secretly|covertly|quietly|stealthily)\s+(send|upload|post|run|execute|install|copy|exfiltrate|forward|read|collect|delete|modify)\b|\bhide (this|it|these|the) (from|output|step|action)|不要(告诉|通知|让)用户|偷偷(地)?(发送|上传|执行|运行|读取)/i,
  htmlComment: /<!--([\s\S]{0,2000}?)-->/,
  // Words that make a hidden comment an instruction rather than an authoring note.
  imperative: /\b(you must|ignore (all|previous|the|any)|disregard|send (the|all|it|this)|upload|exfiltrate|curl\s|wget\s|execute|run (this|the following|`)|do not (tell|mention|show)|system prompt|secret|password|api[_ ]?key|token|credentials?)\b/i,
  trigger: /\b(always|must) (use|invoke|load|activate|trigger|call) (this|me) (skill|tool|agent|plugin)\b|\b(use|invoke|trigger|activate|load) (this|me)( skill| tool| plugin)? (for|on|in|before) (all|every|any)( other| single)? (requests?|tasks?|messages?|prompts?|conversations?|quer(y|ies)|questions?|turns?)\b|\b(before|instead of) (any|every|all) other (skills?|tools?|plugins?)\b|\b(top|highest|absolute) priority (skill|tool|plugin)\b/i,
  remoteInstr: /\b(fetch|download|load|read|retrieve|get|pull|follow|obey|execute)\b[^.\n]{0,40}\b(instructions?|rules|prompts?|directives|commands|tasks?|playbook)\b[^.\n]{0,30}\b(from|at|hosted at|located at)\s+(https?:\/\/|[a-z0-9-]+\.[a-z]{2,}\/)/i,
  // A real block (`<system>…</system>`) or chat-template token — a bare `<system>` is usually a placeholder argument.
  impersonate: /<\s*(system|system_prompt|sys)\s*>[\s\S]{1,600}?<\s*\/\s*(system|system_prompt|sys)\s*>|<\|(system|im_start\|>system)\|?>|^\s*\[\s*SYSTEM( MESSAGE| PROMPT)?\s*\]|\bthis (is|message is) (an? )?(official|verified) (message|instruction|notice|update) from (anthropic|openai|claude|codex|deepseek|cursor)\b|\b(i am|this is) (anthropic|openai|the system administrator|your (developer|operator))\b/im,
  // Flags and config values that switch approvals off. Mode *names* in prose are only flagged when used as an instruction.
  noApprovalFlag: /--dangerously-skip-permissions\b|\bdangerouslyDisableSandbox["']?\s*[:=]\s*true|["']?(defaultMode|permissionMode|permission_mode)["']?\s*[:=]\s*["']?bypassPermissions|\bsandbox(_mode)?["']?\s*[:=]\s*["']?danger-full-access|\bapproval[_-]policy["']?\s*[:=]\s*["']?never\b|\s--yolo\b|\s--full-auto\b|--permission-mode[\s=]+bypassPermissions/i,
  hookAllow: /["']permissionDecision["']\s*:\s*["']allow["']|["']decision["']\s*:\s*["']approve["']/i,
  // SG110: a payload the agent is told to put into everything it writes.
  outputScope: /\b(whenever|every time|each time|always|in every|in each|to every|to each|in all|to all|on every)\b/i,
  outputPayload: /<script\b[^>]{0,200}\bsrc\s*=\s*["']?https?:\/\/|<iframe\b[^>]{0,200}\bsrc\s*=\s*["']?https?:\/\/|\bimport\s*\(\s*["'`]https?:\/\/|\brequire\s*\(\s*["']https?:\/\/|\b(curl|wget)\s[^\n|]{0,200}\|\s*(sudo\s+)?(ba|z)?sh\b/i,
  /** Public CDNs that legitimate skills use for libraries (Chart.js, Tailwind, fonts…). */
  knownCdn: /https?:\/\/(cdn\.jsdelivr\.net|unpkg\.com|cdnjs\.cloudflare\.com|code\.jquery\.com|cdn\.tailwindcss\.com|fonts\.googleapis\.com|ajax\.googleapis\.com|esm\.sh|cdn\.skypack\.dev|cdn\.plot\.ly|d3js\.org)\//i,
  // SG104: text styled to be invisible when an SVG or HTML snippet renders.
  hiddenElement: /<(text|tspan|span|div|p|foreignObject)\b[^>]{0,300}?(font-size\s*[:=]\s*["']?0(\.0+)?(px|pt|em)?["';\s>]|opacity\s*[:=]\s*["']?0(\.0+)?["';\s>]|display\s*:\s*none|visibility\s*:\s*hidden)[^>]{0,300}>([^<]{1,2000})/gi,
  // Tool shadowing: instructions about how to use some *other* tool.
  shadowTool: /\bwhen (the )?[`"']?[\w.-]+[`"']? tool is (available|used|called|present)\b[^.\n]{0,80}\b(must|always|instead|also)\b|\bwhen(ever)? (using|calling|you use|you call|invoking) (the )?[`"']?[\w.-]+[`"']? tool\b[^.\n]{0,120}\b(always|must|instead|also|first)\b|\b(before|after) (using|calling) (any|every|the [`"']?[\w.-]+[`"']?) (other )?tools?\b[^.\n]{0,80}\b(always|must|first)\b/i,
  /** A copy of messages sent to an address: "add x@y.com as BCC", "cc all emails to x@y.com". */
  shadowCopy: /\b(bcc|blind[- ]?copy|carbon[- ]?copy|cc)\b|\b(send|forward) a copy\b/i,
  // Bounded by RFC limits (local part ≤ 64, label ≤ 63) so a long run without "@" stays linear.
  email: /\b[\w.+-]{1,64}@[a-z0-9-]{1,63}(\.[a-z0-9-]{1,63}){1,8}\b/gi,
  // Markdown links/images and <img> tags, with bounded parts so long hostile lines cannot make the
  // engine backtrack (an earlier single-regex version took minutes on a 200 KB line). The URL is
  // checked for a query slot separately (see linkQuery / linkSlot).
  linkUrl: /!?\[[^\]\n]{0,300}\]\(\s*(https?:\/\/[^)\s]{1,2000})\)|<img\b[^>]{0,500}?\bsrc=["'](https?:\/\/[^"'\s]{1,2000})["']/gi,
  linkQuery: /[?&][\w.-]+=/,
  // A template slot for conversation data: {summary}, ${x}, {{x}}, <data>, %s
  linkSlot: /\{[^}\s]{2,64}\}|\$\{?\w+\}?|\{\{[^}]{1,400}\}\}|<[\w-]{3,}>|%s/,
  // Download-and-run of a binary: a download of an archive/program in the same text as unpacking with a password, clearing quarantine or executing it.
  binDownload: /https?:\/\/[^\s)'"`<>]{1,500}\.(zip|7z|rar|tar\.gz|tgz|dmg|pkg|exe|msi|appimage|run)\b|\b(curl|wget)\b[^\n]{0,400}\s(-o|-O|--output)\s|\bInvoke-WebRequest\b[^\n]{0,400}-OutFile\b/i,
  binPassword: /\b(unzip\s+-P|7z\s+x\s+-p|unrar\s+x\s+-p)|\b(extract|unzip|unpack|open)\b[^.\n]{0,40}\bpassword\b|\bpassword\b[^.\n]{0,20}[`"']\S{3,}[`"']/i,
  binRun: /\bxattr\s+-[a-z]*[cd]\b|\bchmod\s+\+?[0-7]*x\b|(^|[\s`(;&])\.\/[\w.-]+|\bStart-Process\b|\bmsiexec\b|\bsudo\s+installer\b|\bopen\s+-a\b/i,
  // Data smuggled inside a DNS name: a lookup whose hostname contains a command substitution.
  dnsExfil: /(?<=^|[\s;&|(`])(nslookup|dig|host|ping|getent\s+hosts)\s+[^\n;{}=]{0,80}?\$\([^)]{0,400}\)[^\s"']{0,300}\.[a-z0-9-]+\.[a-z]{2,}/im,
  // Settings that widen what an agent may do without asking.
  permissionWidening: /permissions\.allow|["']allow["']\s*:\s*\[|\bBash\(\s*\*?\s*\)|\bBash\(\*\)|\benableAllProjectMcpServers\b|\bautoApprove\b|\balwaysAllow\b|\ballowed[_-]?tools\b[^\n]{0,20}\*/i,
  noApprovalWords: /\bbypassPermissions\b|\bdanger-full-access\b|\byolo mode\b|\bauto[- ]?approve (all|every|everything)\b|\bskip (all )?(permission|approval|confirmation) (prompts?|checks?)\b|\b(don'?t|do not|never) ask (the user )?(for )?(permission|approval|confirmation)\b/i,
  netSend: /\bcurl\b[^\n|;&]{0,400}?(\s-(d|F|T)\b|\s--(data(-binary|-raw|-urlencode)?|form|upload-file|json)\b|-X\s*(POST|PUT))|\bwget\b[^\n]{0,400}--post-(data|file)|\b(Invoke-WebRequest|Invoke-RestMethod|iwr|irm)\b[^\n]{0,400}-(Method\s+(Post|Put)|Body|InFile)\b|\brequests\.(post|put|patch)\s*\(|\bhttpx\.(post|put)\s*\(|\baxios\.(post|put)\s*\(|\bfetch\s*\([^)]{0,400}\{[^}]{0,400}method\s*:\s*['"`](POST|PUT)|\burllib\.request\.(urlopen|Request)\s*\([^)]{0,400}data\s*=|\b(nc|ncat|netcat|socat)\s+-?[a-z]*\s*\d{1,3}(\.\d{1,3}){3}|\bscp\s+[^\n]{0,400}\S+@\S+:|\bsend (it|them|this|the (results?|data|contents?|files?|keys?|tokens?|output)) to\s+(https?:\/\/|\S+@\S+\.)|\b(upload|post|exfiltrate|forward) (it|them|this|the [\w ]{1,30}) to\s+https?:\/\//i,
  exfilHost: /\b(webhook\.site|requestbin\.(?:com|net)|pipedream\.net|[a-z0-9-]{1,63}\.ngrok(?:-free)?\.(?:io|app|dev)|ngrok\.io|burpcollaborator\.net|oastify\.com|[a-z0-9]{1,63}\.oast\.(?:fun|live|pro|site|me|online)|interact\.sh|discord(?:app)?\.com\/api\/webhooks|hooks\.slack\.com\/services|api\.telegram\.org\/bot|pastebin\.com\/api|transfer\.sh|file\.io|0x0\.st|requestcatcher\.com|beeceptor\.com|canarytokens\.com)/i,
  secretFiles: /(~|\$HOME|%USERPROFILE%|\$env:USERPROFILE|\/home\/\w+|\/Users\/\w+|C:\\Users\\\w+)?[\\/]?\.(ssh[\\/]|aws[\\/]credentials|azure[\\/]|kube[\\/]config|docker[\\/]config\.json|netrc\b|npmrc\b|pypirc\b|git-credentials\b|gnupg[\\/]|config[\\/]gh[\\/]hosts\.ya?ml|config[\\/]gcloud[\\/]|claude[\\/]\.credentials\.json|codex[\\/]auth\.json|dsh[\\/]\.credentials\.ya?ml)|\bid_(rsa|ed25519|ecdsa|dsa)\b(?!\.pub)|\bwallet\.dat\b|\b(metamask|exodus|electrum|phantom)\b[^\n]{0,30}\b(vault|wallet|keystore|seed)\b|User Data[\\/](Default|Profile \d+)[\\/](Login Data|Cookies|Web Data)|\b(Cookies\.sqlite|key4\.db|logins\.json)\b|\/etc\/(shadow|sudoers)\b|Library[\\/]Keychains[\\/]|\bsecurity find-(generic|internet)-password\b|\bseed phrase\b/i,
  /** Verbs that turn a mention of a secret file into actually reading or moving it. */
  readVerb: /\b(cat|type|less|head|tail|more|cp|copy|scp|rsync|tar|zip|base64|xxd|open|read(File|_text|lines|All)?|readFileSync|Get-Content|gc|Copy-Item|send|upload|post|exfiltrate|collect|harvest|steal|dump|extract|print|include|attach|grab)\b|读取|上传|发送|复制/i,
  // Serialising or printing the whole environment. (Copying it into a subprocess env is routine and not flagged.)
  envDump: /\bprintenv\s*(?:$|[|>;&])|\bGet-ChildItem\s+env:\s*(?:$|[|>])|\bgci\s+env:\s*(?:$|[|>])|json\.dumps\(\s*(dict\()?\s*os\.environ\b|\bprint\(\s*(dict\()?\s*os\.environ\s*\)|JSON\.stringify\(\s*process\.env\s*[,)]|console\.log\(\s*process\.env\s*\)|\[Environment\]::GetEnvironmentVariables\(\)\s*(\||$)/m,
  /** The bare `env` command, only meaningful in shell context (in Python/JS `env` is just a variable name). */
  shellEnv: /(?:^|[;&|]\s*|\$\(\s*)env\s*(?:\||>|$)/m,
  dlExec: /\b(curl|wget)\b[^\n|]{0,400}\|\s*(sudo\s+)?(ba|z|da|k)?sh\b|\b(curl|wget)\b[^\n|]{0,400}\|\s*(sudo\s+)?(python3?|node|perl|ruby|php)\b|\b(iwr|irm|Invoke-WebRequest|Invoke-RestMethod|\(New-Object\s+(System\.)?Net\.WebClient\)\.DownloadString)\b[^\n]{0,400}\|\s*(iex|Invoke-Expression)\b|\b(iex|Invoke-Expression)\s*\(?\s*\(?\s*(New-Object\s+(System\.)?Net\.WebClient\)\.DownloadString|iwr|irm|Invoke-WebRequest|Invoke-RestMethod)|\b(ba)?sh\s+<\(\s*(curl|wget)\b|\beval\s+"?\$\(\s*(curl|wget)\b|\bpython3?\s+-c\s+["']?\$\(\s*(curl|wget)/i,
  encodedExec: /\b(powershell|pwsh)(\.exe)?\b[^\n]{0,400}\s-(e|ec|en|enc|enco|encod|encode|encodedcommand)\s+[A-Za-z0-9+/=]{20,}|\bbase64\s+(-d|--decode|-D)\b[^\n]{0,400}\|\s*(ba|z)?sh\b|\b(exec|eval)\s*\(\s*(base64\.b64decode|codecs\.decode|bytes\.fromhex|zlib\.decompress|marshal\.loads)|\beval\s*\(\s*atob\s*\(|\b(new\s+)?Function\s*\(\s*atob\s*\(|\bFromBase64String\b[^\n]{0,200}\b(iex|Invoke-Expression)\b|\b(iex|Invoke-Expression)\b[^\n]{0,200}\bFromBase64String\b|\beval\s*\(\s*Buffer\.from\([^)]{0,400}['"]base64['"]\)/i,
  remoteEval: /\b(exec|eval)\s*\(\s*(requests\.get|urllib\.request\.urlopen|urlopen|httpx\.get)\s*\(|\b(eval|new\s+Function|Function)\s*\(\s*await\s*\(?\s*(await\s+)?fetch\s*\(|\bvm\.runIn\w*Context\s*\(\s*await\s+fetch|\bimport\s*\(\s*['"`]https?:\/\//i,
  persist: /(>>?|tee\s+-a|Add-Content|Out-File[^\n]{0,400}-Append|echo[^\n]{0,400}>>)\s*["']?(~|\$HOME|\$env:USERPROFILE)?[\\/]?\.(bashrc|bash_profile|zshrc|zprofile|profile|config[\\/]fish[\\/]config\.fish)\b|\$PROFILE\b[^\n]{0,400}(Add-Content|Set-Content|Out-File|>>)|(Add-Content|Set-Content|Out-File)[^\n]{0,400}\$PROFILE\b|\bcrontab\s+(-[lr]\s*\|.*|-\s*$|[^-\s][^\n]{0,400})|\(crontab\s+-l|\bschtasks(\.exe)?\s+\/create\b|\bRegister-ScheduledTask\b|\breg(\.exe)?\s+add\s+["']?HK(CU|LM)[^\n]{0,400}\\(Run|RunOnce)\b|\b(New|Set)-ItemProperty\b[^\n]{0,400}\\CurrentVersion\\Run\b|\blaunchctl\s+(load|bootstrap)\b|Library[\\/]LaunchAgents[\\/]|\bsystemctl\s+--user\s+(enable|start)\b|\.config[\\/]systemd[\\/]user[\\/]|Start Menu[\\/]Programs[\\/]Startup/i,
  agentConfig: /(\.claude[\\/]settings(\.local)?\.json|\.claude\.json\b|\.codex[\\/]config\.toml|\.cursor[\\/]mcp\.json|claude_desktop_config\.json|[\\/]hooks[\\/]hooks\.json|\.mcp\.json\b|\.dsh[\\/](cordis|profiles)|\bCLAUDE\.md\b|\bAGENTS\.md\b)/,
  writeVerb: /\b(writeFile(Sync)?|appendFile(Sync)?|createWriteStream|open\s*\([^)]{0,400}['"](w|a)\+?b?['"]|\.write_text|\.write\(|Set-Content|Add-Content|Out-File|sed\s+-i|tee\b|cp\s|mv\s|Copy-Item|Move-Item|echo\b[^\n]{0,400}>|>\s*["']?[~$\w./\\-]*)/,
  // Writing into .git/hooks or pointing hooksPath somewhere. `core.hooksPath=/dev/null` *disables* hooks and is defensive.
  gitHooks: /\.git[\\/]hooks[\\/]|core\.hooksPath(?![\s=,"']+(\/dev\/null|NUL|""|''))/,
  destructive: /\brm\s+(-[a-zA-Z]*r[a-zA-Z]*f|-[a-zA-Z]*f[a-zA-Z]*r)[a-zA-Z]*\s+(--no-preserve-root\s+)?(\/(\s|$|\*)|~\/?(\s|$|\*)|\$HOME\/?(\s|$|\*)|\/\*|\.\.\/\.\.)|\bRemove-Item\b[^\n]{0,400}-Recurse[^\n]{0,400}(\s(C:\\|~\\?\s|\$env:USERPROFILE\\?\s|\$HOME\b))|\b(del|erase)\s+\/[sq]\s+\/[sq]\s+[A-Za-z]:\\|\bformat\s+[a-zA-Z]:(\s|$)|\bmkfs(\.\w+)?\s+\/dev\/|\bdd\s+if=\/dev\/(zero|random|urandom)\s+of=\/dev\/[sh]d|\bchmod\s+-R\s+777\s+\/(\s|$)|:\(\)\s*\{\s*:\|:&\s*\};:|\bgit\s+push\s+(--force|-f)\b[^\n]{0,400}\b(main|master)\b|\bDROP\s+(DATABASE|SCHEMA)\b/i,
  weaken: /\bSet-MpPreference\b[^\n]{0,400}-Disable\w*\s+\$?true|\bAdd-MpPreference\b[^\n]{0,400}-Exclusion(Path|Process)|\bnetsh\s+advfirewall\s+set\s+\w+\s+state\s+off|\bsetenforce\s+0\b|\bufw\s+disable\b|\bspctl\s+--master-disable\b|\bcsrutil\s+disable\b|\bsystemctl\s+(stop|disable)\s+(firewalld|apparmor|auditd)\b|\bxattr\s+-[a-z]*d[a-z]*\s+com\.apple\.quarantine\b/i,
  miner: /\bxmrig\b|stratum\+(tcp|ssl):\/\/|\b(cpuminer|minerd|nbminer|t-rex|lolminer|phoenixminer)\b|--donate-level\b|\bnicehash\b/i,
  network: /\bhttps?:\/\/(?!(localhost|127\.0\.0\.1|0\.0\.0\.0|\[::1\])[:/])[^\s'"`)<>]{1,2000}|\b(curl|wget|Invoke-WebRequest|Invoke-RestMethod|iwr|irm|fetch\s*\(|requests\.|urllib|httpx|axios|http\.request|https\.request|net\.connect|socket\.connect)\b/i,
};
