/** Where an item is installed: which agent (or a plain repository) loads it. */
export type Host = 'claude-code' | 'codex' | 'cursor' | 'opencode' | 'deepseek-harness' | 'claude-desktop' | 'vscode' | 'agents' | 'repo';

export const HOST_LABELS: Record<Host, string> = {
  'claude-code': 'Claude Code',
  codex: 'Codex',
  cursor: 'Cursor',
  opencode: 'OpenCode',
  'deepseek-harness': 'DeepSeek Harness',
  'claude-desktop': 'Claude Desktop',
  vscode: 'VS Code',
  agents: 'Agent Skills (~/.agents)',
  repo: 'Repository',
};

/**
 * What an item is.
 * - `skill`: a folder with SKILL.md (Agent Skills format), plus any scripts it bundles
 * - `plugin`: a Claude Code / Codex plugin (plugin.json) — may contain skills, hooks, commands, agents, MCP servers
 * - `command` / `subagent`: markdown prompt files a plugin or user installs
 * - `hook`: a shell command an agent runs automatically on an event
 * - `mcp-server`: an MCP server definition in some agent's config
 * - `context`: instruction files loaded into every conversation (CLAUDE.md, AGENTS.md, .cursorrules)
 * - `dsh-plugin`: a DeepSeek Harness (Cordis) plugin package
 * - `settings`: an agent settings file's permission rules and environment (Claude Code settings.json)
 */
export type ItemKind = 'skill' | 'plugin' | 'command' | 'subagent' | 'hook' | 'mcp-server' | 'context' | 'dsh-plugin' | 'settings';

export interface McpServer {
  transport: 'stdio' | 'http' | 'sse' | 'unknown';
  command?: string;
  args: string[];
  env: Record<string, string>;
  url?: string;
  headers: Record<string, string>;
  disabled?: boolean;
}

export interface Hook {
  event: string;
  matcher?: string;
  type: string;
  command?: string;
  /** `type: "prompt"` hooks: text given to a model on the event. */
  prompt?: string;
}

export interface Item {
  /** Stable identifier used in reports and the lock file, e.g. `claude-code:skill:pdf`. */
  id: string;
  kind: ItemKind;
  host: Host;
  name: string;
  /** Folder (skills, plugins) or config file (MCP servers, hooks) the item comes from. */
  path: string;
  /** Files that belong to the item and get scanned. */
  files: string[];
  description?: string;
  /** For items inside a plugin: the plugin's id. */
  parent?: string;
  mcp?: McpServer;
  hook?: Hook;
  /** Parsed manifest / frontmatter, for rules that look at metadata. */
  meta: Record<string, unknown>;
  /** For repository scans: the scanned folder (test-path detection starts there, not at the drive root). */
  scanRoot?: string;
  /** Symbolic links inside the item that point outside it (not followed). */
  outsideLinks?: string[];
}

export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';

export const SEVERITY_ORDER: Record<Severity, number> = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };

export function atLeast(s: Severity, min: Severity): boolean {
  return SEVERITY_ORDER[s] >= SEVERITY_ORDER[min];
}

export interface Finding {
  rule: string;
  severity: Severity;
  title: string;
  /** One sentence: what was found and why it matters, specific to this occurrence. */
  message: string;
  item: string;
  file?: string;
  line?: number;
  column?: number;
  /** The offending text, trimmed and with secrets masked. */
  evidence?: string;
}

/**
 * What a piece of text is, which decides how a rule reads it. Natural-language
 * instructions are what a model obeys; code is what runs; docs are for humans.
 */
export type UnitKind = 'instructions' | 'code' | 'command' | 'docs' | 'metadata';

export interface TextUnit {
  item: Item;
  file?: string;
  kind: UnitKind;
  text: string;
  /** Line number of `text`'s first line within `file` (1-based). */
  lineOffset?: number;
  /** Set for MCP tool descriptions extracted from server source (see tooldesc.ts). */
  origin?: 'tool-description';
}

export interface RuleInfo {
  id: string;
  title: string;
  severity: Severity;
  /** Why this matters, in two or three sentences. */
  why: string;
  /** What to do about it. */
  fix: string;
}

/** What an item can do (not a verdict): see capabilities.ts. */
export type Capability = 'runs-code' | 'auto-runs' | 'network' | 'writes-files' | 'shell' | 'binaries' | 'credentials';

export interface ScanResult {
  items: Item[];
  findings: Finding[];
  /** Capabilities per item id (items that can do nothing beyond prompting are absent). */
  capabilities?: Record<string, Capability[]>;
  /** Files that could not be read (too big, binary, permission denied). */
  skipped: { file: string; reason: string }[];
}
