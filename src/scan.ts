/**
 * File-system scanning engine: walk a repository, keep only files that sit on
 * an agent auto-read surface, apply the rules line by line.
 */
import { readdir, readFile, stat } from 'node:fs/promises';
import { join, resolve } from 'node:path';
import type { Dirent } from 'node:fs';
import { Finding, applyRules } from './rules.js';
import { SurfaceSet, isMarkdownLikePath, whichProfilesMatch } from './surfaces.js';
import { normalizeRel, pathMatchesGlob, splitLines, toPosix } from './util.js';

/** Minimal .gitignore respect: these directories are never interesting. */
export const SKIP_DIR_NAMES = new Set(['node_modules', '.git']);
export const MAX_FILE_BYTES = 1_000_000;
export const MAX_FILES = 20_000;

export interface ScannedFile {
  path: string;
  lines: number;
  matchedProfiles: string[];
  findings: Finding[];
}

export interface SkippedFile {
  path: string;
  reason: string;
}

export interface FileScanResult {
  root: string;
  scanned: ScannedFile[];
  skipped: SkippedFile[];
  /** every regular file seen during the walk */
  allFiles: string[];
  findings: Finding[];
}

function isIgnored(relPosix: string, ignoreGlobs: string[]): boolean {
  return ignoreGlobs.some((g) => pathMatchesGlob(relPosix, g));
}

export async function listFiles(
  root: string,
  ignoreGlobs: string[] = [],
  skipDirs: Set<string> = SKIP_DIR_NAMES
): Promise<{ files: string[]; skipped: SkippedFile[] }> {
  const absRoot = resolve(root);
  const files: string[] = [];
  const skipped: SkippedFile[] = [];

  async function walk(dir: string): Promise<void> {
    if (files.length >= MAX_FILES) return;
    let entries: Dirent[];
    try {
      entries = await readdir(dir, { withFileTypes: true });
    } catch {
      skipped.push({ path: normalizeRel(toPosix(dir.slice(absRoot.length + 1))), reason: 'unreadable directory' });
      return;
    }
    for (const entry of entries) {
      if (files.length >= MAX_FILES) return;
      const full = join(dir, entry.name);
      const rel = normalizeRel(toPosix(full.slice(absRoot.length + 1)));
      if (entry.isDirectory()) {
        if (skipDirs.has(entry.name.toLowerCase())) continue;
        if (isIgnored(rel, ignoreGlobs)) continue;
        await walk(full);
      } else if (entry.isFile()) {
        if (isIgnored(rel, ignoreGlobs)) continue;
        files.push(rel);
      }
      // symlinks and other types are skipped deliberately (cycle safety)
    }
  }

  await walk(absRoot);
  files.sort();
  return { files, skipped };
}

export async function scanFiles(
  root: string,
  surface: SurfaceSet,
  ignoreGlobs: string[] = []
): Promise<FileScanResult> {
  const absRoot = resolve(root);
  const { files, skipped } = await listFiles(absRoot, ignoreGlobs);
  const scanned: ScannedFile[] = [];
  const findings: Finding[] = [];

  for (const rel of files) {
    const matched = whichProfilesMatch(rel, surface);
    if (matched.length === 0) continue;

    const full = join(absRoot, rel);
    let size: number;
    try {
      const st = await stat(full);
      size = st.size;
    } catch {
      skipped.push({ path: rel, reason: 'stat failed' });
      continue;
    }
    if (size > MAX_FILE_BYTES) {
      skipped.push({ path: rel, reason: `too large (${size} bytes > ${MAX_FILE_BYTES})` });
      continue;
    }
    let buf: Buffer;
    try {
      buf = await readFile(full);
    } catch {
      skipped.push({ path: rel, reason: 'unreadable' });
      continue;
    }
    if (buf.includes(0)) {
      skipped.push({ path: rel, reason: 'binary' });
      continue;
    }

    const text = buf.toString('utf8');
    const markdownLike = isMarkdownLikePath(rel);
    const fileFindings = applyRules(text, {
      kind: 'file',
      location: { kind: 'file', path: rel, line: 1 },
      markdownLike,
      instructionFile: markdownLike,
      trust: 'neutral',
    });
    scanned.push({
      path: rel,
      lines: splitLines(text).length,
      matchedProfiles: matched,
      findings: fileFindings,
    });
    findings.push(...fileFindings);
  }

  return { root: absRoot, scanned, skipped, allFiles: files, findings };
}
