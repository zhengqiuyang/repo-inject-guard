/**
 * Small shared helpers: CRLF-tolerant line splitting, glob matching,
 * evidence excerpts and hidden-Unicode codepoint tables.
 */

export function toPosix(p: string): string {
  return p.split('\\').join('/');
}

/** Normalize a repo-relative path for matching: posix separators, no leading "./". */
export function normalizeRel(p: string): string {
  const posix = toPosix(p).replace(/^\.\//, '');
  return posix;
}

export function escapeRegex(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

export function basename(p: string): string {
  const i = p.lastIndexOf('/');
  return i === -1 ? p : p.slice(i + 1);
}

/**
 * Convert a glob pattern to an anchored RegExp.
 * Supported: a `**` segment (any characters including the path separator),
 * a `**` segment followed by a separator (zero or more directories),
 * `*` (any characters except the separator) and `?` (one such character).
 * Matching is case-insensitive: agent manifests are matched leniently because
 * case tricks ("agents.md" vs "AGENTS.md") are a cheap obfuscation and
 * default filesystems on Windows/macOS resolve case-insensitively anyway.
 */
export function globToRegex(pattern: string): RegExp {
  let re = '';
  let i = 0;
  while (i < pattern.length) {
    const c = pattern[i];
    if (c === '*') {
      if (pattern[i + 1] === '*') {
        let j = i + 2;
        while (pattern[j] === '*') j++;
        const nextIsSlash = pattern[j] === '/';
        if (nextIsSlash) {
          // `**/` directory wildcard (`skills/**/SKILL.md`): zero or more segments
          re += '(?:[^/]+/)*';
          i = j + 1;
        } else {
          // trailing `**` (`.claude/**`) or bare `**`: crosses separators
          re += '[\\s\\S]*';
          i = j;
        }
      } else {
        re += '[^/]*';
        i += 1;
      }
    } else if (c === '?') {
      re += '[^/]';
      i += 1;
    } else {
      re += escapeRegex(c);
      i += 1;
    }
  }
  return new RegExp('^' + re + '$', 'i');
}

/**
 * Match a repo-relative posix path against a glob.
 * - Patterns containing `/` are anchored globs against the full path.
 * - Bare filenames (e.g. `AGENTS.md`) match by basename at any depth,
 *   because agents discover nested copies of these files too.
 */
export function pathMatchesGlob(relPosix: string, pattern: string): boolean {
  const p = normalizeRel(pattern);
  const path = normalizeRel(relPosix);
  if (!p.includes('/')) {
    return basename(path).toLowerCase() === p.toLowerCase();
  }
  return globToRegex(p).test(path);
}

/**
 * Split text into lines. Tolerates CRLF, LF and lone CR so that fixtures and
 * real-world files behave identically on Windows checkouts.
 */
export function splitLines(text: string): string[] {
  return text.split(/\r\n|\r|\n/);
}

/**
 * Evidence excerpt: invisible/control characters are shown as \uXXXX escapes,
 * whitespace is collapsed and the result is capped (default 120 chars).
 */
export function excerpt(raw: string, max = 120): string {
  let s = raw.replace(
    // eslint-disable-next-line no-control-regex
    /[\u0000-\u0008\u000B-\u001F\u007F-\u009F\u200B-\u200F\u2028-\u202E\u2060-\u206F\uFEFF]/g,
    (ch) => '\\u' + (ch.codePointAt(0) as number).toString(16).padStart(4, '0')
  );
  s = s.trim().replace(/\s+/g, ' ');
  if (s.length > max) s = s.slice(0, max - 3) + '...';
  return s;
}

/** Hidden / bidi Unicode codepoints we always report. */
export const HIDDEN_CODEPOINT_NAMES: Record<string, string> = {
  '\u200B': 'U+200B ZERO WIDTH SPACE',
  '\u200C': 'U+200C ZERO WIDTH NON-JOINER',
  '\u200D': 'U+200D ZERO WIDTH JOINER',
  '\u2060': 'U+2060 WORD JOINER',
  '\uFEFF': 'U+FEFF ZERO WIDTH NO-BREAK SPACE (BOM)',
  '\u202A': 'U+202A LEFT-TO-RIGHT EMBEDDING',
  '\u202B': 'U+202B RIGHT-TO-LEFT EMBEDDING',
  '\u202C': 'U+202C POP DIRECTIONAL FORMATTING',
  '\u202D': 'U+202D LEFT-TO-RIGHT OVERRIDE',
  '\u202E': 'U+202E RIGHT-TO-LEFT OVERRIDE',
  '\u2066': 'U+2066 LEFT-TO-RIGHT ISOLATE',
  '\u2067': 'U+2067 RIGHT-TO-LEFT ISOLATE',
  '\u2068': 'U+2068 FIRST STRONG ISOLATE',
  '\u2069': 'U+2069 POP DIRECTIONAL ISOLATE',
};

/**
 * Names of hidden codepoints present in `text`, in order of first appearance,
 * de-duplicated.
 */
export function findHiddenCodepointNames(text: string): string[] {
  const seen: string[] = [];
  for (const ch of text) {
    const name = HIDDEN_CODEPOINT_NAMES[ch];
    if (name && !seen.includes(name)) seen.push(name);
  }
  return seen;
}

export function errMsg(e: unknown): string {
  if (e instanceof Error) return e.message;
  return String(e);
}
