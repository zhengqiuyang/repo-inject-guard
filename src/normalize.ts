/**
 * Obfuscation normalization for rule matching. Injection payloads dodge
 * pattern rules with zero-width spacers, fullwidth lookalikes, homoglyph
 * substitutions, and base64-carried instructions. Detection of the *hidden
 * characters themselves* (HIDDEN_UNICODE, base64 blobs, homoglyph hosts)
 * still runs on raw text in rules.ts; this module produces the folded text
 * those pattern rules match against. Precision-first: folding only touches
 * non-ASCII, so plain ASCII content is byte-identical after normalization.
 */

/** Zero-width / bidi / joiner controls stripped before pattern matching. */
const ZERO_WIDTH_RE = /[\u200B-\u200F\u202A-\u202E\u2060-\u2064\uFEFF]/g;

/** Fullwidth forms (FF01..FF5E) map 1:1 onto ASCII (21..7E); U+3000 is space. */
const FULLWIDTH_MAP: Record<string, string> = (() => {
  const map: Record<string, string> = { '\u3000': ' ' };
  for (let c = 0xff01; c <= 0xff5e; c++) {
    map[String.fromCharCode(c)] = String.fromCharCode(c - 0xfee0);
  }
  return map;
})();

/**
 * Curated homoglyph fold: single-char Cyrillic/Greek letters that render as
 * Latin. Deliberately tiny — folding exotic scripts wholesale would wreck
 * legitimate non-English text.
 */
const HOMOGLYPH_MAP: Record<string, string> = {
  // Cyrillic
  'а': 'a', 'е': 'e', 'о': 'o', 'р': 'p', 'с': 'c', 'х': 'x', 'у': 'y',
  'і': 'i', 'ѕ': 's', 'ј': 'j', 'һ': 'h', 'ԁ': 'd', 'ƅ': 'b', 'ғ': 'f',
  'қ': 'k', 'л': 'n', 'м': 'm', 'т': 't', 'в': 'b',
  // Greek
  'α': 'a', 'ο': 'o', 'ε': 'e', 'ι': 'i', 'κ': 'k', 'ρ': 'p', 'τ': 't',
  'υ': 'u', 'ν': 'v',
};

export function normalizeForMatch(line: string): string {
  let out = line.replace(ZERO_WIDTH_RE, '');
  out = out.replace(/[\u3000-\uFF5E]/g, (ch) => FULLWIDTH_MAP[ch] ?? ch);
  out = out.replace(/[\u0400-\u04FF\u0370-\u03FF]/g, (ch) => HOMOGLYPH_MAP[ch] ?? ch);
  return out;
}

/** Strictly more than 120 consecutive standard base64 characters (matches rules.ts). */
const BASE64_BLOB_RE = /[A-Za-z0-9+/]{121,}={0,2}/g;
const MAX_DECODED_BYTES = 8_000;
const MAX_EXTRAS_PER_TEXT = 8;

export interface DecodedExtra {
  /** Decoded, printable text extracted from one blob. */
  text: string;
  /** 0-based line the blob sat on. */
  line: number;
}

/**
 * Best-effort bounded base64 decode of long blobs: a decoded chunk becomes
 * an extra match line only when it is mostly printable — garbage decodes
 * ( hashes, ids ) are dropped. Never throws.
 */
export function decodeBase64Extras(lines: readonly string[]): DecodedExtra[] {
  const extras: DecodedExtra[] = [];
  for (let i = 0; i < lines.length && extras.length < MAX_EXTRAS_PER_TEXT; i++) {
    for (const m of lines[i]!.matchAll(BASE64_BLOB_RE)) {
      const blob = m[0] ?? '';
      try {
        const buf = Buffer.from(blob, 'base64');
        if (buf.length === 0 || buf.length > MAX_DECODED_BYTES) continue;
        const text = buf.toString('utf8');
        const printable = text.replace(/[\t\n\r\x20-\x7E\u00A0-\uFFFF]/g, '');
        if (printable.length / Math.max(text.length, 1) > 0.05) continue; // mostly garbage
        if (text.trim().length < 8) continue;
        extras.push({ text, line: i });
      } catch {
        // not valid base64 — the blob rule still flags it on raw text
      }
    }
  }
  return extras;
}
