let colorOn = !process.env.NO_COLOR && (process.env.FORCE_COLOR ? process.env.FORCE_COLOR !== '0' : !!process.stdout.isTTY);

export function setColor(on: boolean): void {
  colorOn = on;
}

const wrap = (open: number, close: number) => (s: string) => (colorOn ? `\x1b[${open}m${s}\x1b[${close}m` : s);

export const c = {
  bold: wrap(1, 22),
  dim: wrap(2, 22),
  red: wrap(31, 39),
  green: wrap(32, 39),
  yellow: wrap(33, 39),
  blue: wrap(34, 39),
  magenta: wrap(35, 39),
  cyan: wrap(36, 39),
  gray: wrap(90, 39),
  bgRed: (s: string) => (colorOn ? `\x1b[41m\x1b[97m${s}\x1b[39m\x1b[49m` : s),
};

// eslint-disable-next-line no-control-regex
const ANSI = /\x1b\[[0-9;]*m/g;

function isWide(cp: number): boolean {
  return (cp >= 0x1100 && cp <= 0x115f) || (cp >= 0x2e80 && cp <= 0xa4cf && cp !== 0x303f) || (cp >= 0xac00 && cp <= 0xd7a3) || (cp >= 0xf900 && cp <= 0xfaff) || (cp >= 0xfe30 && cp <= 0xfe4f) || (cp >= 0xff00 && cp <= 0xff60) || (cp >= 0xffe0 && cp <= 0xffe6) || (cp >= 0x1f300 && cp <= 0x1f64f) || (cp >= 0x1f900 && cp <= 0x1f9ff) || (cp >= 0x20000 && cp <= 0x3fffd);
}

export function width(s: string): number {
  let w = 0;
  for (const ch of s.replace(ANSI, '')) {
    const cp = ch.codePointAt(0) ?? 0;
    if (cp < 32) continue;
    w += isWide(cp) ? 2 : 1;
  }
  return w;
}

export function fit(s: string, max: number): string {
  if (width(s) <= max) return s;
  let out = '';
  let w = 0;
  for (const ch of s) {
    const cw = isWide(ch.codePointAt(0) ?? 0) ? 2 : 1;
    if (w + cw > max - 1) break;
    out += ch;
    w += cw;
  }
  return out + '…';
}

export function pad(s: string, w: number): string {
  return s + ' '.repeat(Math.max(0, w - width(s)));
}

export function plural(n: number, word: string, many = word + 's'): string {
  return `${n.toLocaleString('en-US')} ${n === 1 ? word : many}`;
}
