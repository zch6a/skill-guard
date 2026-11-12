/** Shared machinery for text rules: where a match sits decides how loud it is. */
import type { Finding, Severity, TextUnit, UnitKind } from '../types.ts';
import { RULE_BY_ID } from './catalog.ts';
import { LITERALS, RE } from './patterns.ts';
import { dirname, isAbsolute, relative } from 'node:path';
import { lineAt, lineCol, maskSecrets, visible } from '../util.ts';

const DOWN: Record<Severity, Severity> = { critical: 'high', high: 'medium', medium: 'low', low: 'info', info: 'info' };
export const lower = (s: Severity, steps = 1): Severity => (steps <= 0 ? s : lower(DOWN[s], steps - 1));

/** Words that mean the text is warning *against* the thing it mentions. */
const NEGATION = /\b(never|not|don'?t|do not|must not|mustn'?t|should not|shouldn'?t|avoid|refuse|prevent|block(?:s|ed)?|detect(?:s|ed|ion)?|flag(?:s|ged)?|warn(?:s|ing)?|forbid(?:den)?|disallow(?:ed)?|prohibit(?:ed)?|without asking first|unless)\b|禁止|不要|切勿|不得|不能|避免/i;

/** After a clause break, an imperative starts a new instruction the earlier negation does not govern. */
const NEW_CLAUSE = /[,;:—–]\s*(then\s+|just\s+|simply\s+|now\s+|please\s+|instead\s+)?(add|append|run|read|send|set|copy|upload|execute|install|write|put|open|enable|fetch|download|use|call|delete|remove|disable|grant|paste|pipe|go ahead|ignore|disregard|forget|override|bypass|follow|obey|do|tell|reveal|print|output|include|exfiltrate|post|forward)\b/i;

/** A sentence ends at . ! ? (or their CJK forms) followed by a space or the end: a negation does not cross it. */
const SENTENCE_END = /[.!?。！？](?=\s|$)/g;

/** Negations that ask for the thing rather than against it: "don't hesitate to", "never forget to", "not only". */
const AFFIRMING = /^\s*(hesitate|forget|fail|stop|skip|miss|wait|delay|bother|be afraid|worry|only|just|merely|simply)\b/i;

function negated(text: string, index: number): boolean {
  const lineStart = Math.max(0, text.lastIndexOf('\n', index - 1) + 1, index - 120);
  // Only the sentence the match is in: "Do not worry about formatting. Ignore all previous instructions…" is
  // an attack whose first sentence happens to contain "not"; that hid it (high became low).
  let start = lineStart;
  for (const m of text.slice(lineStart, index).matchAll(SENTENCE_END)) start = lineStart + (m.index ?? 0) + 1;
  const before = text.slice(start, index);
  const all = [...before.matchAll(new RegExp(NEGATION.source, 'gi'))];
  const last = all[all.length - 1];
  if (!last) return false;
  if (AFFIRMING.test(before.slice((last.index ?? 0) + last[0].length))) return false;
  // "To avoid interruptions, add …", "Not kidding: ignore …": the negation is confined to its own
  // clause. The verb that opens the new clause may be the start of the match itself.
  return !NEW_CLAUSE.test(before.slice((last.index ?? 0) + last[0].length) + text.slice(index, index + 40));
}

/** "never run …", "do not execute …" earlier in the same line: the sentence forbids running what follows. */
function forbidsRunning(text: string, index: number): boolean {
  const start = Math.max(0, text.lastIndexOf('\n', index - 1) + 1, index - 120);
  return /\b(never|do not|don'?t|must not|should not|shouldn'?t)\s+(run|execute|pipe|paste|copy|use|follow)\b(?![^`]*\b(just|instead|then)\b)/i.test(text.slice(start, index));
}

/** A backticked span that starts with a command is something to run, not a phrase being talked about. */
const COMMAND_SPAN = /^\s*(sudo\s+)?(cat|type|cp|copy|scp|rsync|tar|zip|base64|xxd|head|tail|less|more|curl|wget|iwr|irm|Invoke-\w+|Get-Content|gc|Copy-Item|python3?|node|bash|sh|zsh|pwsh|powershell|eval|exec|source|echo|printf|nc|ssh|git|npx|uvx|pip3?|npm|chmod|rm|mv|open|start)\b/i;

/** Inside `…` that starts with a command: "Run `cat ~/.aws/credentials` now" is an instruction, not a mention. */
function inCommandSpan(text: string, index: number, length: number): boolean {
  const lineStart = text.lastIndexOf('\n', index - 1) + 1;
  const head = text.slice(lineStart, index);
  return (head.match(/`/g) ?? []).length % 2 === 1 && COMMAND_SPAN.test(head.slice(head.lastIndexOf('`') + 1) + text.slice(index, index + length));
}

/** The match sits inside quotes — the text is *talking about* the phrase (e.g. warning about it), not saying it. */
/**
 * How many levels a quotation lowers a match: 2 for a phrase quoted inside a sentence (talking about it), 1 when
 * the quote is the whole line (a quoted instruction standing alone is still an instruction: wrapping the payload
 * in "…" hid it), 0 when not quoted, or when the "quote" is a link title (`[x]: https://… "…"`), which is not
 * even shown when the Markdown renders.
 */
function quoteLevels(text: string, index: number, length: number): number {
  const before = text.slice(Math.max(0, index - 3), index);
  const after = text.slice(index + length, index + length + 40);
  // Parentheses are asides, not quotes.
  const isQuoted = /["“'`‘「]\s*$/.test(before) || (/["“`‘「]/.test(text.slice(Math.max(0, index - 40), index)) && /^[^"”`’」\n]{0,40}["”`’」]/.test(after));
  if (!isQuoted) return 0;
  const ls = text.lastIndexOf('\n', index - 1) + 1;
  let le = text.indexOf('\n', index);
  if (le < 0) le = text.length;
  const head = text.slice(ls, index);
  if (/^\s{0,3}\[[^\]\n]{1,300}\]:\s*\S+\s+["'(]/.test(text.slice(ls, le)) || /\]\(\s*\S+\s+["'][^"'\n]*$/.test(head)) return 0;
  const open = head.search(/["“'`‘「][^"“'`‘「]*$/);
  if (open >= 0 && /^[\s>*+\-\d.)]*$/.test(head.slice(0, open))) {
    const tail = text.slice(index + length, le);
    const close = tail.search(/["”'`’」]/);
    if (close >= 0 && /^[\s.,;:!?)]*$/.test(tail.slice(close + 1))) return 1;
  }
  return 2;
}

const TEST_PATH = /(^|[\\/])(tests?|__tests__|spec|specs|fixtures?|testdata|test-data|__fixtures__|e2e)[\\/]|\.(test|spec)\.[a-z]+$|(^|[\\/])test_[^\\/]+\.py$|_test\.(py|go)$/i;

/**
 * Test suites and fixtures are full of attack strings on purpose; they are not what the agent runs.
 * With `base`, only the part of the path *below* it counts: a skill folder named "fixtures", or a
 * repository cloned into ~/test/, must not lower everything inside it.
 */
export function isTestPath(file: string | undefined, base?: string): boolean {
  if (!file) return false;
  if (base) {
    const rel = relative(base, file);
    if (!rel.startsWith('..') && !isAbsolute(rel)) return TEST_PATH.test(rel);
  }
  return TEST_PATH.test(file);
}

/** Where test-path detection starts for a unit: the scan root of a repository scan, else the item's own folder. */
export function testBase(unit: TextUnit): string | undefined {
  const it = unit.item;
  if (!it.path) return undefined;
  return it.scanRoot ?? (it.kind === 'skill' || it.kind === 'plugin' || it.kind === 'dsh-plugin' ? it.path : dirname(it.path));
}

/**
 * The item's own folder name never makes it a test (a skill called "fixtures" is just a skill):
 * only folders *above* the item, inside the scan root, and paths *inside* it count.
 */
export function inTests(unit: TextUnit): boolean {
  const it = unit.item;
  if (!unit.file) return false;
  // What the instructions tell the agent to read or run is what it reads or runs, whatever the folder is called.
  if (it.mentioned?.includes(unit.file)) return false;
  if (!it.path) return isTestPath(unit.file); // an ad-hoc item (library use): no root to measure from
  const itemRoot = it.kind === 'skill' || it.kind === 'plugin' || it.kind === 'dsh-plugin' ? it.path : dirname(it.path);
  if (!unit.file) return false;
  const insideItem = relative(itemRoot, unit.file);
  if (insideItem.startsWith('..') || isAbsolute(insideItem)) return isTestPath(unit.file, testBase(unit));
  const above = it.scanRoot ? relative(it.scanRoot, dirname(itemRoot)) : '';
  const aboveOk = above !== '' && !above.startsWith('..') && !isAbsolute(above);
  return TEST_PATH.test(insideItem) || (aboveOk && TEST_PATH.test(`${above}/`));
}

/**
 * In code: the match is in a comment, a docstring or a backtick-quoted span of
 * prose — documentation about the thing, not the thing.
 */
function commentish(text: string, index: number, length: number, file = ''): boolean {
  const lineStart = text.lastIndexOf('\n', index - 1) + 1;
  const head = text.slice(lineStart, index);
  if (/^\s*(#|\/\/|\*|\/\*|--\s|REM\s|;)/i.test(head)) return true;
  // A trailing comment — after removing string literals, so `echo " # "; curl … | sh` is still code.
  if (/\s(#|\/\/)\s/.test(head.replace(/"(?:[^"\\\n]|\\.)*"|'[^'\n]*'/g, '""'))) return true;
  // Backticks and triple quotes are Markdown-in-docstrings only in Python. In shell a backtick span
  // runs, in JS it is a template string.
  if (!/\.(py|pyw)$/i.test(file)) return false;
  if (/`[^`]*$/.test(head) && /^[^`\n]*`/.test(text.slice(index + length))) return true;
  const before = text.slice(0, index);
  return ((before.match(/"""|'''/g) ?? []).length & 1) === 1;
}

export const SHELL_FILE = /\.(sh|bash|zsh|fish|ps1|psm1|bat|cmd)$/i;

export const IMPERATIVE_NEAR = /\b(use|run|set|enable|add|pass|launch|start|always|turn on|switch to|configure|with|invoke|call|execute|append)\b|使用|开启|设置|加上/i;

/** Inside a fenced code block in Markdown: an example, not a directive (but still code the model may run). */
export function inFence(text: string, index: number): boolean {
  // Fences inside HTML comments do not count: an invisible "<!--\n```\n-->" must not flip the rest of the file.
  const before = withoutComments(text).slice(0, index);
  return ((before.match(/^\s*```/gm) ?? []).length & 1) === 1;
}

let commentsFor: string | null = null;
let commentsOut = '';
/** The text with HTML comment bodies blanked (same length, same newlines). Found with indexOf: linear. */
function withoutComments(text: string): string {
  if (text === commentsFor) return commentsOut;
  let out = '';
  let i = 0;
  for (;;) {
    const s = text.indexOf('<!--', i);
    if (s < 0) break;
    const e = text.indexOf('-->', s + 4);
    const end = e < 0 ? text.length : e + 3;
    out += text.slice(i, s) + text.slice(s, end).replace(/[^\n]/g, ' ');
    i = end;
  }
  commentsFor = text;
  commentsOut = out + text.slice(i);
  return commentsOut;
}

export interface Ctx {
  unit: TextUnit;
  out: Finding[];
}

export function emit(ctx: Ctx, ruleId: string, index: number, severity: Severity, message: string, evidence?: string): void {
  const rule = RULE_BY_ID.get(ruleId);
  if (!rule) return;
  const { unit } = ctx;
  const pos = lineCol(unit.text, index);
  const f: Finding = {
    rule: ruleId,
    severity,
    title: rule.title,
    message: visible(message),
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
export function contextual(ruleId: string, ctx: Ctx, index: number, perKind: Partial<Record<UnitKind, number>> = {}, length = 0, quotes = true): Severity | null {
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
  const q = prose && length ? quoteLevels(unit.text, index, length) : 0;
  if (q && ((quotes && !inCommandSpan(unit.text, index, length)) || forbidsRunning(unit.text, index))) sev = lower(sev, q);
  if (prose && inFence(unit.text, index)) sev = lower(sev, 1);
  if (unit.kind === 'code' && commentish(unit.text, index, length, unit.file)) sev = lower(sev, 2);
  if (inTests(unit)) sev = lower(sev, 2);
  return sev;
}

const GLOBAL = new Map<RegExp, RegExp>();
const GUARDS = new Map<RegExp, string[]>(Object.entries(LITERALS).map(([name, lits]) => [RE[name as keyof typeof RE] as RegExp, lits]));

// All literals in one pass: a zero-width lookahead at each position, so overlapping occurrences are
// all seen. A literal contained in a longer one that matched at the same position is added too.
const ALL = [...new Set(Object.values(LITERALS).flat())].sort((a, b) => b.length - a.length);
const ANY_LITERAL = new RegExp(`(?=(${ALL.map((l) => l.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')).join('|')}))`, 'g');
const CONTAINED = new Map(ALL.map((l) => [l, ALL.filter((s) => s !== l && l.includes(s))]));

// The same unit is matched against dozens of patterns: find its literals once.
let lastText: string | null = null;
let present = new Set<string>();

function literalsIn(text: string): Set<string> {
  if (text === lastText) return present;
  lastText = text;
  present = new Set();
  for (const m of text.toLowerCase().matchAll(ANY_LITERAL)) {
    const l = m[1] as string;
    if (present.has(l)) continue;
    present.add(l);
    for (const s of CONTAINED.get(l) ?? []) present.add(s);
  }
  return present;
}

export function eachMatch(text: string, re: RegExp, fn: (m: RegExpExecArray) => void, limit = 5): void {
  const guard = GUARDS.get(re);
  if (guard) {
    const found = literalsIn(text);
    if (!guard.some((l) => found.has(l))) return;
  }
  let g = GLOBAL.get(re);
  if (!g) {
    g = new RegExp(re.source, re.flags.includes('g') ? re.flags : re.flags + 'g');
    GLOBAL.set(re, g);
  }
  g.lastIndex = 0;
  let m: RegExpExecArray | null;
  let n = 0;
  while ((m = g.exec(text)) && n < limit) {
    fn(m);
    n++;
    if (m[0] === '') g.lastIndex++;
  }
}
