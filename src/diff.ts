/**
 * Minimal unified-diff parser for `gate --diff <file.patch>`: extracts the
 * files touched and the ADDED lines (with their new-file line numbers) so
 * rules can be applied to exactly what a PR introduces. CRLF-tolerant.
 */
import { splitLines, toPosix } from './util.js';

export interface PatchAddedLine {
  line: number;
  text: string;
}

export interface PatchFile {
  path: string;
  status: 'added' | 'modified';
  addedLines: PatchAddedLine[];
}

function cleanPath(raw: string): string {
  let s = raw.trim();
  if (s.startsWith('"') && s.endsWith('"')) s = s.slice(1, -1);
  s = toPosix(s);
  while (s.startsWith('b/') || s.startsWith('a/')) s = s.slice(2);
  return s;
}

export function parseUnifiedDiff(text: string): PatchFile[] {
  const out: PatchFile[] = [];
  const lines = splitLines(text);
  let path = '';
  let oldPath = '';
  let pendingOld: string | null = null; // '--- a/x' arrives before '+++ b/x'
  let added: PatchAddedLine[] = [];
  let cur = 0;
  let started = false;

  const flush = (): void => {
    if (!started) return;
    if (path === '' || path === '/dev/null') return; // deleted file: nothing new to inspect
    const status: 'added' | 'modified' = oldPath === '/dev/null' ? 'added' : 'modified';
    out.push({ path, status, addedLines: added });
  };

  for (const raw of lines) {
    let m: RegExpMatchArray | null;
    if ((m = raw.match(/^\+\+\+ (?:b\/)?(.+)$/))) {
      flush();
      const target = cleanPath(m[1] as string);
      path = target === 'dev/null' ? '/dev/null' : target;
      oldPath = pendingOld ?? '';
      pendingOld = null;
      added = [];
      cur = 0;
      started = true;
      continue;
    }
    if ((m = raw.match(/^--- (?:a\/)?(.+)$/))) {
      const src = cleanPath(m[1] as string);
      pendingOld = src === 'dev/null' ? '/dev/null' : src;
      continue;
    }
    if ((m = raw.match(/^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@/))) {
      cur = parseInt(m[1] as string, 10);
      continue;
    }
    if (!started) continue;
    if (raw.startsWith('+')) {
      added.push({ line: cur, text: raw.slice(1) });
      cur += 1;
      continue;
    }
    if (raw.startsWith('-')) {
      continue; // removed line: does not carry new content
    }
    if (raw.startsWith(' ') || raw === '') {
      cur += 1;
      continue;
    }
    // anything else (e.g. "\ No newline at end of file") is metadata
  }
  flush();
  return out;
}
