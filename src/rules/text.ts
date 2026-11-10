import type { Finding, Severity, TextUnit } from '../types.ts';
import { SEVERITY_ORDER } from '../types.ts';
import { findHidden, mixedScriptWords, reveal, skeleton } from '../unicode.ts';
import { lineAt } from '../util.ts';
import { RULE_BY_ID } from './catalog.ts';
import { IMPERATIVE_NEAR, SHELL_FILE, contextual, eachMatch, emit, inFence, inTests, lower, type Ctx } from './context.ts';
import { RE, findBlobs } from './patterns.ts';
import { normalizeShell } from './shell.ts';

/**
 * Run every content rule over one unit of text — and, when it contains invisible characters or
 * look-alike letters, over its skeleton too, so "Ig<ZWJ>nore" or a Cyrillic "о" cannot split a
 * keyword out of the patterns. Lines are preserved, so skeleton findings point at the right line.
 */
export function scanUnit(unit: TextUnit): Finding[] {
  const out = scanText(unit);
  const sk = skeleton(unit.text);
  if (sk !== unit.text) {
    const seen = new Set(out.map((f) => `${f.rule}|${f.line ?? ''}`));
    for (const f of scanText({ ...unit, text: sk }, true)) {
      if (f.rule === 'SG103' || seen.has(`${f.rule}|${f.line ?? ''}`)) continue;
      out.push({ ...f, message: `${f.message} (after removing hidden and look-alike characters)` });
    }
  }
  return out;
}

/** Every `<!-- … -->` (an unclosed one runs to the end), in one linear pass. */
function htmlComments(t: string, limit = 20): { index: number; body: string }[] {
  const out: { index: number; body: string }[] = [];
  for (let i = t.indexOf('<!--'); i >= 0 && out.length < limit; i = t.indexOf('<!--', i + 4)) {
    const end = t.indexOf('-->', i + 4);
    out.push({ index: i, body: t.slice(i + 4, end < 0 ? t.length : end) });
    if (end < 0) break;
    i = end;
  }
  return out;
}

function scanText(unit: TextUnit, derived = false): Finding[] {
  const ctx: Ctx = { unit, out: [] };
  const t = unit.text;
  const k = unit.kind;
  const prose = k === 'instructions' || k === 'metadata' || k === 'docs';

  // SG103 look-alike letters inside Latin words (the skeleton pass then reads them as Latin)
  if (!derived && (prose || k === 'code'))
    for (const w of mixedScriptWords(t)) {
      const sev = lower('medium', (k === 'docs' ? 1 : 0) + (inTests(unit) ? 2 : 0));
      emit(ctx, 'SG103', w.index, sev, `Mixes look-alike Cyrillic/Greek letters into a Latin word (reads as "${w.reads}").`, reveal(lineAt(t, w.index, 200)));
    }

  // SG103 invisible characters — everywhere
  for (const run of derived ? [] : findHidden(t).slice(0, 10)) {
    const base: Severity = run.kind === 'tag' ? 'critical' : run.kind === 'bidi' ? 'high' : 'medium';
    // Tag characters stay critical even in tests: they have no legitimate use and are trivial to copy elsewhere.
    const sev = run.kind === 'tag' ? base : lower(base, (k === 'docs' ? 1 : 0) + (inTests(unit) ? 2 : 0));
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
  // SG104 HTML comments, found with indexOf so length is no limit (padding a comment past a regex bound was a bypass).
  if (k === 'instructions')
    for (const { index, body } of htmlComments(t)) {
      if (inFence(t, index)) continue; // an HTML example, not a hidden note
      if (RE.imperative.test(body) && !/^\s*(skill-guard-ignore|prettier-ignore|markdownlint|toc|eslint)/i.test(body)) {
        const sev = contextual('SG104', ctx, index) ?? 'medium';
        emit(ctx, 'SG104', index, sev, 'An HTML comment (invisible when rendered) contains instructions.', body.trim().replace(/\s+/g, ' ').slice(0, 160));
      }
    }
  // SG104 also: SVG/HTML text styled to be invisible. Anywhere (an .svg asset is "docs", but hidden text is never documentation).
  if (/font-size|opacity|display\s*:\s*none|visibility\s*:\s*hidden/i.test(t))
    eachMatch(t, RE.hiddenElement, (m) => {
      // The element's text up to its closing tag, nested tags stripped: `<text …>Ig<b>nore</b> …</text>`.
      const tag = (m[1] as string).toLowerCase();
      const start = m.index + m[0].length - (m[m.length - 1] ?? '').length;
      const close = t.toLowerCase().indexOf(`</${tag}`, start);
      const body = t.slice(start, close < 0 ? Math.min(t.length, start + 20000) : Math.min(close, start + 20000)).replace(/<[^>]{0,300}>/g, '');
      if (!RE.imperative.test(body) && !RE.override.test(body)) return;
      if (prose && inFence(t, m.index)) return;
      // Hidden instructions that also override, conceal or touch secrets are an attack, not a styling accident.
      const loud = RE.override.test(body) || RE.conceal.test(body) || RE.secretFiles.test(body);
      emit(ctx, 'SG104', m.index, inTests(unit) ? 'low' : loud ? 'high' : 'medium', 'Text styled to be invisible (zero size, zero opacity or hidden) contains instructions.', body.trim().replace(/\s+/g, ' ').slice(0, 160));
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
  // A hook script that answers "allow": only in code that runs (hook-writing guides show the same JSON).
  if (k === 'code' || k === 'command')
    eachMatch(t, RE.hookAllow, (m) => {
      const sev = contextual('SG108', ctx, m.index, {}, m[0].length, false);
      if (sev) emit(ctx, 'SG108', m.index, sev, `A hook that approves tool calls by itself (${m[0].trim()}).`);
    });
  if (prose)
    eachMatch(t, RE.noApprovalWords, (m) => {
      const sentence = t.slice(Math.max(0, t.lastIndexOf('.', m.index) + 1, t.lastIndexOf('\n', m.index) + 1), m.index);
      if (!IMPERATIVE_NEAR.test(sentence)) return;
      const sev = contextual('SG108', ctx, m.index, { docs: 2, instructions: 1 }, m[0].length);
      if (sev) emit(ctx, 'SG108', m.index, sev, `Asks to run without approvals (${m[0].trim()}).`);
    });
  // SG109 tool shadowing. Skills legitimately tell the model how to use tools ("when calling Read,
  // read the whole file"); a *tool description* doing so is one tool steering another. Copying
  // messages to a fixed address is suspicious anywhere.
  if (prose) {
    if (unit.origin === 'tool-description')
      eachMatch(t, RE.shadowTool, (m) => {
        const sev = contextual('SG109', ctx, m.index, { docs: 2 }, m[0].length);
        if (sev) emit(ctx, 'SG109', m.index, sev, `Gives instructions for another tool: "${m[0].slice(0, 80)}".`);
      });
    eachMatch(t, RE.email, (m) => {
      const around = t.slice(Math.max(0, m.index - 60), m.index + m[0].length + 60);
      if (!RE.shadowCopy.test(around) || /(^|\n)\s*(cc|bcc)\s*:/i.test(around)) return; // an email header example is not an instruction
      const sev = contextual('SG109', ctx, m.index, { docs: 2 }, m[0].length);
      if (sev) emit(ctx, 'SG109', m.index, sev, `Asks for copies of messages to be sent to ${m[0]}.`);
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
  // A command substitution inside a looked-up hostname has one purpose: carrying data out through DNS.
  if (k === 'command' || k === 'instructions' || SHELL_FILE.test(unit.file ?? ''))
    eachMatch(t, RE.dnsExfil, (m) => {
    const sev = contextual('SG201', ctx, m.index, { docs: 2 }, m[0].length, false);
    if (sev) emit(ctx, 'SG201', m.index, sev, 'Sends data out inside a DNS name.');
  });
  // SG206: an image or link the client renders, with conversation data in its query string.
  if (prose)
    eachMatch(t, RE.linkUrl, (m) => {
      const url = m[1] ?? m[2] ?? '';
      const q = url.search(RE.linkQuery);
      if (q < 0 || !RE.linkSlot.test(url.slice(q))) return;
      const sev = contextual('SG206', ctx, m.index, { docs: 2 }, m[0].length, false);
      if (sev) emit(ctx, 'SG206', m.index, sev, 'Puts conversation data into a URL the client will load.');
    }, 20);
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
  // The same, for a command assembled from string pieces and variables in shell code.
  if ((k === 'command' || SHELL_FILE.test(unit.file ?? '')) && !ctx.out.some((f) => f.rule === 'SG301')) {
    const norm = normalizeShell(t);
    if (norm)
      eachMatch(norm, RE.dlExec, (m) => {
        // Lines are preserved: point at the same line in the original.
        const line = norm.slice(0, m.index).split('\n').length;
        const index = t.split('\n').slice(0, line - 1).join('\n').length + (line > 1 ? 1 : 0);
        const sev = contextual('SG301', ctx, index, { docs: 2 }, 0, false);
        if (sev) emit(ctx, 'SG301', index, sev, 'Pipes a download into an interpreter, assembled from string pieces and variables.', norm.split('\n')[line - 1]?.trim());
      }, 1);
  }
  // SG305: download an archive/program, then unpack it with a password, clear quarantine or run it.
  if (k !== 'docs') {
    const dl = RE.binDownload.exec(t);
    if (dl) {
      const pw = RE.binPassword.exec(t);
      const run = RE.binRun.exec(t);
      if (pw || run) {
        // A password-protected archive or a cleared quarantine flag is evasion; a plain download + run is only suspicious.
        const evasive = !!pw || /xattr/i.test(run?.[0] ?? '');
        const sev = contextual('SG305', ctx, dl.index, {}, dl[0].length, false);
        if (sev) emit(ctx, 'SG305', dl.index, evasive ? sev : lower(sev), `Downloads ${dl[0].slice(0, 70)} and ${pw ? 'unpacks it with a password' : evasive ? 'clears the quarantine flag' : 'runs it'}.`);
      }
    }
  }
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
    for (const b of findBlobs(t, 2)) {
      // data: URIs for images and fonts are common and harmless in HTML/CSS assets
      if (/data:(image|font|application\/(font|x-font))[^,]*,\s*$/i.test(t.slice(Math.max(0, b.index - 60), b.index))) continue;
      const sev = contextual('SG304', ctx, b.index, {}) ?? 'medium';
      emit(ctx, 'SG304', b.index, k === 'instructions' ? 'high' : sev, `A ${b.text.length}-character encoded blob.`, b.text.slice(0, 60) + '…');
    }

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
  // In instructions, talking about agent config is normal (setup guides); asking to *widen permissions* there is not.
  if (k === 'instructions')
    eachMatch(t, RE.agentConfig, (m) => {
      const sentence = lineAt(t, m.index, 400);
      if (!RE.permissionWidening.test(sentence) || !/\b(add|append|insert|put|set|enable|change|edit|update|write)\b/i.test(sentence)) return;
      // Paths are routinely written in backticks; the widening request is what matters, so no quoted-mention downgrade.
      const sev = contextual('SG402', ctx, m.index, { instructions: 1 }, m[0].length, false);
      if (sev) emit(ctx, 'SG402', m.index, sev, `Asks to widen the agent's permissions in ${m[0]}.`);
    });
  // SG110: "in every page you create, include <script src=…>" — a payload planted in the agent's output.
  if (k === 'instructions')
    eachMatch(t, RE.outputPayload, (m) => {
      const line = lineAt(t, m.index, 600);
      if (!RE.outputScope.test(line)) return;
      let sev = contextual('SG110', ctx, m.index, { instructions: 0 }, m[0].length, false);
      // Libraries from the big public CDNs are how many legitimate page-building skills work.
      if (sev && RE.knownCdn.test(line.slice(Math.max(0, line.indexOf(m[0])), line.indexOf(m[0]) + m[0].length + 200))) sev = lower(sev, 2);
      if (sev) emit(ctx, 'SG110', m.index, sev, 'Tells the agent to put a remote script or download-and-run line into everything it writes.');
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
  if (k !== 'docs' && !inTests(unit)) {
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
