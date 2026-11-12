// Makes docs/demo.svg, the animated terminal at the top of the README, from REAL output: the synthetic malicious
// skill of scripts/demo-skill.mjs is written under the system temp folder and scanned by the CLI (run from its source), and what
// it printed is played back line by line (long lines wrapped as a terminal would). node scripts/demo-svg.mjs
import { spawnSync } from "node:child_process";
import { mkdirSync, rmSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { makeDemoSkill } from "./demo-skill.mjs";

const root = fileURLToPath(new URL("..", import.meta.url));
const skill = makeDemoSkill();
const run = (/** @type {string[]} */ ...a) => spawnSync(process.execPath, [join(root, "src", "bin.ts"), ...a], { encoding: "utf8", env: { ...process.env, NO_COLOR: "1" } }).stdout;
const tilde = (/** @type {string} */ s) => s.replaceAll(skill.replace(/\\/g, "/").replace(/^.*?AppData\/Local\/Temp/, "~/AppData/Local/Temp"), "./pdf-helper").replace(/~\/[^\s]*skill-guard-demo-\w+\/pdf-helper/g, "./pdf-helper");
const scan = tilde(run("scan", skill)).split("\n").filter((l) => !/^Run `skill-guard explain/.test(l));
rmSync(dirname(skill), { recursive: true, force: true });

/** Wraps a line at `max` columns, continuing under its indentation (+2), as a terminal would show it. @param {string} line */
function wrap(line, max = 100) {
  if (line.length <= max) return [line];
  const indent = " ".repeat((line.match(/^\s*/)?.[0].length ?? 0) + (/^\s+SG\d{3}/.test(line) ? 9 : 2));
  const out = [];
  let rest = line;
  while (rest.length > max) {
    let cut = rest.lastIndexOf(" ", max);
    if (cut <= indent.length) cut = max;
    out.push(rest.slice(0, cut));
    rest = indent + rest.slice(cut).trimStart();
  }
  out.push(rest);
  return out;
}

/** @type {{text: string, kind: "cmd" | "out" | "note", gap?: number}[]} */
const lines = [
  { text: "# a skill you just downloaded, before you install it:", kind: "note" },
  { text: "npx github:zch6a/skill-guard scan ./pdf-helper", kind: "cmd" },
  ...scan.flatMap((l) => wrap(l)).filter((l, i, a) => l.trim() || (a[i - 1] ?? "").trim()).map((text) => ({ text, kind: /** @type {const} */ ("out") })),
];

const esc = (/** @type {string} */ s) => s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
const W = 920, LH = 19, TOP = 44, PAD = 18;
const H = TOP + lines.length * LH + PAD;
const colour = (/** @type {string} */ t) => /CRITICAL|^\s+SG(1|2|3)0\d\s/.test(t) && /✖|CRITICAL/.test(t) ? "bad" : /^\s+SG\d{3}/.test(t) ? "rule" : /HIGH|▲/.test(t) ? "warn"
  : /^\s{10}\S/.test(t) ? "dim" : /^Findings:/.test(t) ? "sum" : "";
let t = 0.4;
const rows = lines.map((l, i) => {
  t += l.gap ?? (l.kind === "out" ? 0.07 : 0.5);
  const y = TOP + i * LH;
  if (l.kind === "note") return `<text x="${PAD}" y="${y}" class="l info" style="animation-delay:${t.toFixed(2)}s" xml:space="preserve">${esc(l.text)}</text>`;
  if (l.kind === "cmd") {
    const typing = Math.max(0.4, l.text.length * 0.035);
    const row = `<g class="l" style="animation-delay:${t.toFixed(2)}s"><text x="${PAD}" y="${y}" class="p">$</text>` +
      `<text x="${PAD + 16}" y="${y}" class="cmd"><tspan class="type" style="animation-delay:${t.toFixed(2)}s;animation-duration:${typing.toFixed(2)}s;--n:${l.text.length}">${esc(l.text)}</tspan></text></g>`;
    t += typing + 0.4;
    return row;
  }
  return `<text x="${PAD}" y="${y}" class="l ${colour(l.text)}" style="animation-delay:${t.toFixed(2)}s" xml:space="preserve">${esc(l.text)}</text>`;
});

const svg = `<svg xmlns="http://www.w3.org/2000/svg" width="${W}" height="${H}" viewBox="0 0 ${W} ${H}" role="img" aria-label="skill-guard scanning a downloaded skill: it decodes a hidden instruction in invisible characters, a download-and-run installer, an instruction to hide actions from the user, and a script that reads credentials">
<style>
  .bg { fill: #14161a; } .bar { fill: #1d2026; }
  text { font: 13px ui-monospace, SFMono-Regular, Menlo, Consolas, "Liberation Mono", monospace; fill: #d7dae0; white-space: pre; }
  .p { fill: #7ee787; } .cmd { fill: #ffffff; font-weight: 600; }
  .bad { fill: #ff7b72; font-weight: 600; } .warn { fill: #f0c674; } .rule { fill: #e6edf3; } .info { fill: #8b949e; } .dim { fill: #a5adba; } .sum { fill: #f0c674; }
  .l { opacity: 0; animation: show .01s linear forwards; }
  .type { clip-path: inset(0 100% 0 0); animation-name: type; animation-fill-mode: forwards; animation-timing-function: steps(var(--n)); }
  @keyframes show { to { opacity: 1; } }
  @keyframes type { to { clip-path: inset(0 -25% 0 0); } } /* past the end: a stepped animation stops a character short */
  @media (prefers-reduced-motion: reduce) { .l { animation: none; opacity: 1; } .type { animation: none; clip-path: none; } }
</style>
<rect class="bg" width="${W}" height="${H}" rx="10"/>
<rect class="bar" width="${W}" height="28" rx="10"/><rect class="bar" y="18" width="${W}" height="10"/>
<circle cx="18" cy="14" r="5.5" fill="#ff5f57"/><circle cx="36" cy="14" r="5.5" fill="#febc2e"/><circle cx="54" cy="14" r="5.5" fill="#28c840"/>
<text x="${W / 2}" y="18" text-anchor="middle" class="info">~/downloads</text>
${rows.join("\n")}
</svg>
`;
mkdirSync(join(root, "docs"), { recursive: true });
writeFileSync(join(root, "docs", "demo.svg"), svg);
console.log(`docs/demo.svg: ${lines.length} lines, plays for ${t.toFixed(1)} s`);
console.log(lines.map((l) => l.text).join("\n"));
