import type { Finding, Severity, TextUnit } from '../types.ts';
import { SEVERITY_ORDER } from '../types.ts';
import { findHidden, reveal } from '../unicode.ts';
import { lineAt } from '../util.ts';
import { RULE_BY_ID } from './catalog.ts';
import { IMPERATIVE_NEAR, SHELL_FILE, contextual, eachMatch, emit, inFence, isTestPath, lower, type Ctx } from './context.ts';
import { RE } from './patterns.ts';

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
