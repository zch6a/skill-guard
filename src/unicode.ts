/**
 * Invisible text. A model reads every code point; a human reviewing the file
 * in an editor or on GitHub sees nothing. These are the characters attackers
 * use to hide instructions in plain sight.
 *
 * Code points are built from numbers so this source file itself stays plain ASCII.
 */

export interface HiddenRun {
  index: number;
  length: number;
  kind: 'tag' | 'zero-width' | 'bidi' | 'variation-selector';
  /** For Unicode Tag characters: the ASCII text they encode. */
  decoded?: string;
}

const isTag = (cp: number) => cp >= 0xe0000 && cp <= 0xe007f;
const isZeroWidth = (cp: number) => cp === 0x200b || cp === 0x200c || cp === 0x200d || cp === 0x2060 || cp === 0x2061 || cp === 0x2062 || cp === 0x2063 || cp === 0x2064 || cp === 0xfeff || cp === 0x180e;
const isBidi = (cp: number) => (cp >= 0x202a && cp <= 0x202e) || (cp >= 0x2066 && cp <= 0x2069) || cp === 0x200e || cp === 0x200f || cp === 0x061c;
/** Variation selectors carry no visible glyph; long runs of them can encode bytes ("emoji smuggling"). */
const isVariationSelector = (cp: number) => (cp >= 0xfe00 && cp <= 0xfe0f) || (cp >= 0xe0100 && cp <= 0xe01ef);

function kindOf(cp: number): HiddenRun['kind'] | null {
  if (isTag(cp)) return 'tag';
  if (isZeroWidth(cp)) return 'zero-width';
  if (isBidi(cp)) return 'bidi';
  if (isVariationSelector(cp)) return 'variation-selector';
  return null;
}

/** Find runs of invisible characters. Single joiners inside emoji sequences are ignored. */
export function findHidden(text: string): HiddenRun[] {
  const runs: HiddenRun[] = [];
  let cur: HiddenRun | null = null;
  let tagText = '';
  let i = 0;
  for (const ch of text) {
    const cp = ch.codePointAt(0) ?? 0;
    const kind = kindOf(cp);
    if (kind && (!cur || cur.kind === kind)) {
      if (!cur) {
        cur = { index: i, length: 0, kind };
        tagText = '';
      }
      cur.length += ch.length;
      if (kind === 'tag' && cp >= 0xe0020 && cp <= 0xe007e) tagText += String.fromCharCode(cp - 0xe0000);
    } else {
      if (cur) flush(cur);
      cur = null;
      if (kind) {
        cur = { index: i, length: ch.length, kind };
        tagText = kind === 'tag' && cp >= 0xe0020 && cp <= 0xe007e ? String.fromCharCode(cp - 0xe0000) : '';
      }
    }
    i += ch.length;
  }
  if (cur) flush(cur);
  return runs;

  /**
   * Which runs count:
   * - tag characters and bidi controls: always (no legitimate use in instructions or code)
   * - zero-width: two or more in a row, or a lone one other than ZWJ/ZWNJ (which emoji and some scripts need)
   * - variation selectors: three or more in a row (a single VS16 is ordinary emoji presentation)
   */
  function flush(run: HiddenRun) {
    const chars = [...text.slice(run.index, run.index + run.length)];
    const count = chars.length;
    let keep = false;
    if (run.kind === 'tag' || run.kind === 'bidi') keep = true;
    else if (run.kind === 'zero-width') keep = count >= 2 || !(chars[0] === String.fromCharCode(0x200c) || chars[0] === String.fromCharCode(0x200d));
    else keep = count >= 3;
    if (!keep) return;
    if (run.kind === 'tag' && tagText) run.decoded = tagText;
    runs.push(run);
  }
}

/** Make hidden characters visible for a report: `<U+200B>`, and decoded tag text as `[hidden: …]`. */
export function reveal(text: string): string {
  let out = '';
  let tag = '';
  for (const ch of text) {
    const cp = ch.codePointAt(0) ?? 0;
    if (isTag(cp)) {
      if (cp >= 0xe0020 && cp <= 0xe007e) tag += String.fromCharCode(cp - 0xe0000);
      continue;
    }
    if (tag) {
      out += `[hidden: ${tag}]`;
      tag = '';
    }
    const kind = kindOf(cp);
    out += kind ? `<U+${cp.toString(16).toUpperCase().padStart(4, '0')}>` : ch;
  }
  if (tag) out += `[hidden: ${tag}]`;
  return out;
}

/** Remove every invisible character (for `skill-guard clean`-style suggestions and tests). */
export function stripHidden(text: string): string {
  let out = '';
  for (const ch of text) if (!kindOf(ch.codePointAt(0) ?? 0)) out += ch;
  return out;
}
