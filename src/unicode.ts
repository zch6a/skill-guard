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
  kind: 'tag' | 'zero-width' | 'bidi' | 'variation-selector' | 'confusable';
  /** For Unicode Tag characters: the ASCII text they encode. */
  decoded?: string;
}

const isTag = (cp: number) => cp >= 0xe0000 && cp <= 0xe007f;
// Zero-width and other glyphless characters: ZW space/joiners, word joiner and invisible operators,
// BOM, Mongolian vowel separator, soft hyphen, combining grapheme joiner, Hangul fillers.
// Also: Khmer inherent vowels and Mongolian free variation selectors (render as nothing outside their script),
// interlinear annotation marks, and the invisible musical formatting controls.
const isZeroWidth = (cp: number) =>
  cp === 0x200b || cp === 0x200c || cp === 0x200d || cp === 0x2060 || cp === 0x2061 || cp === 0x2062 || cp === 0x2063 || cp === 0x2064 || cp === 0xfeff || cp === 0x180e || cp === 0x00ad || cp === 0x034f || cp === 0x115f || cp === 0x1160 || cp === 0x3164 || cp === 0xffa0 ||
  cp === 0x17b4 || cp === 0x17b5 || (cp >= 0x180b && cp <= 0x180d) || cp === 0x180f || (cp >= 0xfff9 && cp <= 0xfffb) || (cp >= 0x1d173 && cp <= 0x1d17a);
const isAsciiLetter = (ch: string | undefined) => !!ch && /^[A-Za-z]$/.test(ch);
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
    else if (run.kind === 'zero-width') {
      // ZWJ/ZWNJ and the soft hyphen have real uses (emoji, some scripts, hyphenation hints) - but never
      // splitting an ASCII word: "Ig<ZWJ>nore" exists only to dodge pattern matching.
      const lenient = chars[0] === String.fromCharCode(0x200c) || chars[0] === String.fromCharCode(0x200d) || chars[0] === String.fromCharCode(0x00ad);
      const splitsWord = isAsciiLetter(text[run.index - 1]) && isAsciiLetter(text[run.index + run.length]);
      keep = count >= 2 || !lenient || splitsWord;
    } else {
      // Variation selectors: a run of three can encode bytes; a single one inside an ASCII word ("Ig<VS1>nore")
      // exists only to split a keyword (emoji take one after the emoji, not between letters).
      const splitsWord = isAsciiLetter(text[run.index - 1]) && isAsciiLetter(text[run.index + run.length]);
      keep = count >= 3 || splitsWord;
    }
    if (!keep) return;
    if (run.kind === 'tag' && tagText) run.decoded = tagText;
    runs.push(run);
  }
}

// ---------------------------------------------------------------- look-alike letters

/** Cyrillic and Greek letters that look like Latin ones, as [code point, Latin letter]. */
const CONFUSABLE_PAIRS: [number, string][] = [
  // Cyrillic lower: a e o p c y x s i j d h k m t b l n
  [0x0430, 'a'], [0x0435, 'e'], [0x043e, 'o'], [0x0440, 'p'], [0x0441, 'c'], [0x0443, 'y'], [0x0445, 'x'], [0x0455, 's'], [0x0456, 'i'], [0x0458, 'j'], [0x0501, 'd'], [0x04bb, 'h'], [0x043a, 'k'], [0x043c, 'm'], [0x0442, 't'], [0x044c, 'b'], [0x04cf, 'l'], [0x043f, 'n'],
  // Cyrillic upper
  [0x0410, 'A'], [0x0412, 'B'], [0x0415, 'E'], [0x041a, 'K'], [0x041c, 'M'], [0x041d, 'H'], [0x041e, 'O'], [0x0420, 'P'], [0x0421, 'C'], [0x0422, 'T'], [0x0425, 'X'], [0x0406, 'I'], [0x0408, 'J'], [0x0405, 'S'], [0x04c0, 'I'],
  // Greek
  [0x03bf, 'o'], [0x03b1, 'a'], [0x03b5, 'e'], [0x03c1, 'p'], [0x03bd, 'v'], [0x03c4, 't'], [0x03ba, 'k'], [0x03b9, 'i'], [0x03c5, 'u'], [0x03c7, 'x'],
  [0x0391, 'A'], [0x0392, 'B'], [0x0395, 'E'], [0x0396, 'Z'], [0x0397, 'H'], [0x0399, 'I'], [0x039a, 'K'], [0x039c, 'M'], [0x039d, 'N'], [0x039f, 'O'], [0x03a1, 'P'], [0x03a4, 'T'], [0x03a5, 'Y'], [0x03a7, 'X'],
];
const CONFUSABLE = new Map(CONFUSABLE_PAIRS.map(([cp, l]) => [String.fromCharCode(cp), l]));
/** Fullwidth ASCII (U+FF01-FF5E) and the mathematical letters and digits (U+1D400-1D7FF, "𝗜𝗴𝗻𝗼𝗿𝗲") fold to ASCII. */
const fold = (ch: string) => {
  const cp = ch.codePointAt(0) ?? 0;
  if (cp >= 0xff01 && cp <= 0xff5e) return String.fromCharCode(cp - 0xfee0);
  if (cp >= 0x1d400 && cp <= 0x1d7ff) {
    const n = ch.normalize('NFKC');
    if (/^[A-Za-z0-9]$/.test(n)) return n;
  }
  return CONFUSABLE.get(ch) ?? ch;
};
/** Combining marks: "I\u0301gnore" reads as "Ignore" to a model; the skeleton drops them. */
const isCombining = (cp: number) => cp >= 0x0300 && cp <= 0x036f;
const isLatin = (ch: string) => /^[A-Za-z]$/.test(ch);

/**
 * The text as a pattern should see it: invisible characters removed, look-alike letters folded to
 * Latin. Newlines are untouched, so line N of the skeleton is line N of the text. Returns the text
 * itself when there is nothing to fold (the usual case).
 */
export function skeleton(text: string): string {
  return skeletonMap(text).text;
}

/** Anything the skeleton changes. Variation selectors and the supplementary ones (U+E0100-E01EF) included. */
const NEEDS_SKELETON = /[\u00ad\u0300-\u036f\u034f\u115f\u1160\u17b4\u17b5\u180b-\u180f\u200b-\u200f\u202a-\u202e\u2060-\u2069\u3164\ufe00-\ufe0f\ufeff\ufff9-\ufffb\uffa0\u0370-\u03ff\u0400-\u052f\uff01-\uff5e]|\udb40[\udc00-\uddef]|\ud835[\udc00-\udfff]|\ud834[\udd73-\udd7a]/;

/**
 * The skeleton, and for each of its UTF-16 positions the position in `text` it came from (one more entry for the
 * end), so a finding in the skeleton can be reported at its real column.
 */
export function skeletonMap(text: string): { text: string; map: number[] | null } {
  if (!NEEDS_SKELETON.test(text)) return { text, map: null };
  let out = '';
  const map: number[] = [];
  let i = 0;
  for (const ch of text) {
    const cp = ch.codePointAt(0) ?? 0;
    if (!kindOf(cp) && !isCombining(cp)) {
      const f = fold(ch);
      out += f;
      for (let k = 0; k < f.length; k++) map.push(i);
    }
    i += ch.length;
  }
  map.push(text.length);
  return { text: out, map };
}

/** Words that mix Latin letters with look-alike Cyrillic/Greek ones ("Ign\u043ere" with a Cyrillic \u043e). */
export function mixedScriptWords(text: string): { index: number; length: number; reads: string }[] {
  const out: { index: number; length: number; reads: string }[] = [];
  // Almost no text contains a Cyrillic or Greek letter at all: one test skips the word-by-word pass.
  if (!/[\u0370-\u03ff\u0400-\u052f]/.test(text)) return out;
  for (const m of text.matchAll(/[\p{L}\u00ad\u200b-\u200d]{3,64}/gu)) {
    const w = m[0];
    let latin = false;
    let fake = false;
    for (const ch of w) {
      if (isLatin(ch)) latin = true;
      else if (CONFUSABLE.has(ch)) fake = true;
    }
    if (latin && fake) out.push({ index: m.index ?? 0, length: w.length, reads: [...w].map(fold).join('') });
    if (out.length >= 10) break;
  }
  return out;
}

/** Make hidden characters visible for a report: `<U+200B>`, and decoded tag text as `[hidden: \u2026]`. */
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
