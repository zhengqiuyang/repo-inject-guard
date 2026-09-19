#!/usr/bin/env node
/**
 * repo-inject-guard CLI
 *
 * Commands:
 *   scan [path]     full scan of a local repository's agent auto-read surfaces
 *   gate            CI mode: changed files in the PR + tracker events
 *   certify [path]  pre-fork verdict (SAFE / CAUTION / DO NOT) + what was and
 *                   was NOT inspected
 *   surfaces        list what each agent profile auto-reads
 *
 * Exit codes: 0 pass (or --warn-only), 1 FAIL verdict, 2 harness/config error.
 */
import { readFile, stat } from 'node:fs/promises';
import { resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { errMsg, normalizeRel } from './util.js';
import {
  AGENT_PROFILES,
  ALL_PROFILE,
  SurfaceSet,
  buildSurfaceSet,
  isMarkdownLikePath,
  profileNames,
  resolveProfiles,
  whichProfilesMatch,
} from './surfaces.js';
import { Finding, applyRules, computeVerdict, sortFindings } from './rules.js';
import { MAX_FILE_BYTES, SkippedFile, scanFiles } from './scan.js';
import { collectEventTexts, ghApi, scanEventTexts } from './events.js';
import { parseUnifiedDiff } from './diff.js';
import { RigConfig, loadRigConfig } from './config.js';
import {
  RunReport,
  VERSION,
  certificationFor,
  renderGithub,
  renderJson,
  renderSarif,
  renderText,
} from './report.js';

const FORMATS = ['text', 'github', 'json', 'sarif'] as const;
type Format = (typeof FORMATS)[number];

interface ParsedArgs {
  command?: string;
  positionals: string[];
  flags: Map<string, string[]>;
}

const VALUE_FLAGS = new Set(['--format', '--profile', '--config', '--diff', '--repo', '--issue', '--pr']);
const BOOL_FLAGS = new Set(['--warn-only', '-h', '--help']);

function parseArgv(argv: string[]): { parsed?: ParsedArgs; error?: string } {
  const flags = new Map<string, string[]>();
  const positionals: string[] = [];
  let command: string | undefined;
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i] as string;
    if (VALUE_FLAGS.has(a)) {
      const v = argv[++i];
      if (v === undefined) return { error: `${a} requires a value` };
      const list = flags.get(a) ?? [];
      list.push(v);
      flags.set(a, list);
    } else if (BOOL_FLAGS.has(a)) {
      flags.set(a, ['true']);
    } else if (a.startsWith('--')) {
      return { error: `unknown option: ${a}` };
    } else if (command === undefined) {
      command = a;
    } else {
      positionals.push(a);
    }
  }
  return { parsed: { command, positionals, flags } };
}

function flagValues(args: ParsedArgs, name: string): string[] {
  return args.flags.get(name) ?? [];
}

function flag(args: ParsedArgs, name: string): string | undefined {
  return flagValues(args, name)[0];
}

function usage(): string {
  return `${'repo-inject-guard'} v${VERSION} — protect coding agents from the repositories and trackers they read

Usage:
  repo-inject-guard scan [path] [options]      Full scan of agent auto-read surfaces in a local repo
  repo-inject-guard gate [path] [options]      CI mode: PR-changed files (diff or GitHub API)
                                              intersected with agent surfaces + any tracker events
  repo-inject-guard certify [path] [options]   Pre-fork verdict: SAFE / CAUTION / DO NOT,
                                              plus exactly what was and was NOT inspected
  repo-inject-guard surfaces [options]         List what each agent profile auto-reads

Options:
  --profile <name>    Agent surface profile (repeatable; default: all)
  --format <fmt>      text | github | json | sarif          (default: text)
  --config <path>     rig.yaml location (default: ./rig.yaml in the CURRENT directory,
                      never inside the scanned repo — a hostile repo cannot opt itself out)
  --diff <file.patch> gate only: inspect a unified diff fixture instead of the GitHub API
  --repo <owner>/<r>  gate only: repository for tracker inspection via gh
  --issue <n>         gate only: issue number to inspect (with --repo)
  --pr <n>            gate only: pull request number to inspect (with --repo)
  --warn-only         Report findings but always exit 0
  -h, --help          Show this help

Exit codes: 0 pass (or --warn-only), 1 FAIL verdict, 2 harness/config error.
Not-inspected ≠ clean: anything you did not point this tool at was NOT checked.
`;
}

function fail(message: string): number {
  process.stderr.write(`repo-inject-guard: error: ${message}\n`);
  return 2;
}

function emit(format: Format, report: RunReport): void {
  switch (format) {
    case 'github':
      process.stdout.write(renderGithub(report));
      break;
    case 'json':
      process.stdout.write(renderJson(report));
      break;
    case 'sarif':
      process.stdout.write(renderSarif(report));
      break;
    default:
      process.stdout.write(renderText(report));
  }
}

function parseFormat(args: ParsedArgs): { format?: Format; error?: string } {
  const raw = flag(args, '--format') ?? 'text';
  if (!(FORMATS as readonly string[]).includes(raw)) {
    return { error: `invalid --format "${raw}" (expected ${FORMATS.join(' | ')})` };
  }
  return { format: raw as Format };
}

async function assertDirectory(target: string, command: string): Promise<string | number> {
  const abs = resolve(target);
  try {
    const st = await stat(abs);
    if (!st.isDirectory()) throw new Error('not a directory');
  } catch {
    return fail(`${command}: cannot read directory: ${abs}`);
  }
  return abs;
}

interface SurfaceSetup {
  profileNames: string[];
  surface: SurfaceSet;
  config: RigConfig;
  notices: string[];
  error?: string;
}

async function setupSurfaces(args: ParsedArgs): Promise<SurfaceSetup> {
  const cfg = await loadRigConfig(flag(args, '--config'));
  if (cfg.error) {
    return { profileNames: [], surface: buildSurfaceSet(['all']), config: {}, notices: [], error: cfg.error };
  }
  const config: RigConfig = cfg.config ?? {};
  const fromFlags = flagValues(args, '--profile');
  const names = fromFlags.length > 0 ? fromFlags : config.profiles?.length ? config.profiles : ['all'];
  const { errors } = resolveProfiles(names);
  if (errors.length > 0) {
    return {
      profileNames: [],
      surface: buildSurfaceSet(['all']),
      config: {},
      notices: [],
      error: `unknown profile(s): ${errors.join(', ')} — valid profiles: ${profileNames().join(', ')}`,
    };
  }
  const surface = buildSurfaceSet(names, config.extraPaths ?? []);
  return { profileNames: names, surface, config, notices: cfg.notices };
}

/** Read a set of repo-relative files from a checkout and apply rules to those on a surface. */
async function scanLocalFiles(
  base: string,
  files: string[],
  surface: SurfaceSet,
  notices: string[]
): Promise<{ findings: Finding[]; surfaceFiles: { path: string; profiles: string[] }[]; skipped: SkippedFile[] }> {
  const findings: Finding[] = [];
  const surfaceFiles: { path: string; profiles: string[] }[] = [];
  const skipped: SkippedFile[] = [];
  for (const raw of files) {
    const rel = normalizeRel(raw);
    const matched = whichProfilesMatch(rel, surface);
    if (matched.length === 0) continue;
    let buf: Buffer;
    try {
      buf = await readFile(resolve(base, rel));
    } catch {
      skipped.push({ path: rel, reason: 'not present/readable in checkout' });
      continue;
    }
    if (buf.length > MAX_FILE_BYTES) {
      skipped.push({ path: rel, reason: 'too large' });
      continue;
    }
    if (buf.includes(0)) {
      skipped.push({ path: rel, reason: 'binary' });
      continue;
    }
    const text = buf.toString('utf8');
    const md = isMarkdownLikePath(rel);
    findings.push(
      ...applyRules(text, {
        kind: 'file',
        location: { kind: 'file', path: rel, line: 1 },
        markdownLike: md,
        instructionFile: md,
        trust: 'neutral',
      })
    );
    surfaceFiles.push({ path: rel, profiles: matched });
  }
  if (skipped.length > 0) {
    notices.push(`${skipped.length} changed file(s) on agent surfaces could not be inspected: ${skipped.map((s) => `${s.path} (${s.reason})`).join('; ')}. Not-inspected ≠ clean.`);
  }
  return { findings, surfaceFiles, skipped };
}

function changedFilesNotice(notices: string[]): void {
  notices.push('Files that are not agent auto-read surfaces were NOT inspected (README, source code, docs — your agent may still read them on task).');
}

async function cmdScan(args: ParsedArgs, certify: boolean): Promise<number> {
  const fmt = parseFormat(args);
  if (fmt.error) return fail(fmt.error);
  const target = args.positionals[0] ?? '.';
  const root = await assertDirectory(target, certify ? 'certify' : 'scan');
  if (typeof root === 'number') return root;

  const setup = await setupSurfaces(args);
  if (setup.error) return fail(setup.error);

  const scan = await scanFiles(root, setup.surface, setup.config.ignore ?? []);

  const findings = scan.findings;
  const verdict = computeVerdict(findings);
  const offSurface = scan.allFiles.filter((f) => whichProfilesMatch(f, setup.surface).length === 0);

  const notices = [...setup.notices];
  if (scan.skipped.length > 0) {
    notices.push(`${scan.skipped.length} agent-surface file(s) skipped: ${scan.skipped.map((s) => `${s.path} (${s.reason})`).join('; ')}. Not-inspected ≠ clean.`);
  }
  changedFilesNotice(notices);
  notices.push(
    'Issue/PR bodies and comments were NOT inspected. Use `gate` in CI, or --repo owner/name --issue N, before trusting tracker text.'
  );

  const report: RunReport = {
    command: certify ? 'certify' : 'scan',
    target: root,
    profiles: setup.profileNames,
    surfaceFiles: scan.scanned.map((s) => ({ path: s.path, profiles: s.matchedProfiles })),
    events: [],
    skipped: scan.skipped,
    offSurfaceCount: offSurface.length,
    offSurfaceExamples: offSurface.slice(0, 5),
    findings,
    notices,
    verdict,
    certification: certify ? certificationFor(verdict) : undefined,
  };
  emit(fmt.format as Format, report);
  return verdict === 'FAIL' && !args.flags.has('--warn-only') ? 1 : 0;
}

async function cmdGate(args: ParsedArgs): Promise<number> {
  const fmt = parseFormat(args);
  if (fmt.error) return fail(fmt.error);
  const warnOnly = args.flags.has('--warn-only');

  const repoFlag = flag(args, '--repo');
  const issueRaw = flag(args, '--issue');
  const prRaw = flag(args, '--pr');
  let issueNum: number | undefined;
  let prNum: number | undefined;
  if (issueRaw !== undefined && !/^\d+$/.test(issueRaw)) return fail(`--issue expects a number, got "${issueRaw}"`);
  if (prRaw !== undefined && !/^\d+$/.test(prRaw)) return fail(`--pr expects a number, got "${prRaw}"`);
  issueNum = issueRaw !== undefined ? parseInt(issueRaw, 10) : undefined;
  prNum = prRaw !== undefined ? parseInt(prRaw, 10) : undefined;
  if ((issueNum !== undefined || prNum !== undefined) && repoFlag === undefined) {
    return fail('--issue/--pr require --repo owner/name');
  }
  if (issueNum !== undefined && prNum !== undefined) {
    return fail('pass either --issue or --pr, not both');
  }

  const setup = await setupSurfaces(args);
  if (setup.error) return fail(setup.error);

  const base = await assertDirectory(args.positionals[0] ?? '.', 'gate');
  if (typeof base === 'number') return base;

  const diffPath = flag(args, '--diff');
  const eventPath = process.env['GITHUB_EVENT_PATH']?.trim() || undefined;
  const eventName = process.env['GITHUB_EVENT_NAME']?.trim() || undefined;

  const findings: Finding[] = [];
  const notices = [...setup.notices];
  const surfaceFiles: { path: string; profiles: string[] }[] = [];
  let skipped: SkippedFile[] = [];
  let changedFiles: string[] | undefined;

  // --- events ---
  const gh =
    repoFlag && (issueNum ?? prNum) !== undefined
      ? { repo: repoFlag as string, number: (issueNum ?? prNum) as number, kind: (prNum !== undefined ? 'pr' : 'issue') as 'pr' | 'issue' }
      : undefined;
  const ev = await collectEventTexts({ eventPath, eventName, gh });
  notices.push(...ev.notices);
  findings.push(...scanEventTexts(ev.texts));

  // --- changed files ---
  let sawSource = false;
  if (diffPath) {
    sawSource = true;
    let text: string;
    try {
      text = await readFile(resolve(diffPath), 'utf8');
    } catch (e) {
      return fail(`gate: cannot read --diff file ${diffPath} (${errMsg(e)})`);
    }
    const files = parseUnifiedDiff(text);
    if (files.length === 0) {
      notices.push('The diff contained no scannable file additions — nothing was inspected from the patch. Not-inspected ≠ clean.');
    }
    changedFiles = files.map((f) => f.path);
    for (const f of files) {
      const rel = normalizeRel(f.path);
      const matched = whichProfilesMatch(rel, setup.surface);
      if (matched.length === 0) continue;
      const addedText = f.addedLines.map((a) => a.text).join('\n');
      const md = isMarkdownLikePath(rel);
      const fileFindings = applyRules(addedText, {
        kind: 'file',
        location: { kind: 'file', path: rel, line: 1 },
        markdownLike: md,
        instructionFile: md,
        trust: 'neutral',
      });
      // remap line numbers from "line N of added text" to real file lines
      const remapped = fileFindings.map((fx) =>
        fx.location.kind === 'file'
          ? {
              ...fx,
              location: {
                kind: 'file' as const,
                path: rel,
                line: f.addedLines[fx.location.line - 1]?.line ?? fx.location.line,
              },
            }
          : fx
      );
      findings.push(...remapped);
      surfaceFiles.push({ path: rel, profiles: matched });
    }
    if (ev.texts.length === 0 && !gh) {
      notices.push('Tracker text (issue/PR bodies, comments) was NOT inspected: no event source for this gate run. Not-inspected ≠ clean.');
    }
  } else if (eventPath && ev.prContext) {
    sawSource = true;
    const { repo, number } = ev.prContext;
    const res = ghApi(`repos/${repo}/pulls/${number}/files`);
    if (res.ok && Array.isArray(res.data)) {
      changedFiles = (res.data as { filename?: string }[]).map((d) => String(d.filename ?? '')).filter(Boolean);
      const local = await scanLocalFiles(base, changedFiles, setup.surface, notices);
      findings.push(...local.findings);
      surfaceFiles.push(...local.surfaceFiles);
      skipped = local.skipped;
    } else {
      notices.push(
        `Could not enumerate PR changed files via gh (${res.error ?? 'unexpected response'}); falling back to a FULL agent-surface scan — broader, never narrower. Not-inspected ≠ clean.`
      );
      const full = await scanFiles(base, setup.surface, setup.config.ignore ?? []);
      findings.push(...full.findings);
      for (const s of full.scanned) surfaceFiles.push({ path: s.path, profiles: s.matchedProfiles });
      skipped = full.skipped;
    }
  } else if (eventPath) {
    sawSource = true;
    notices.push('Non-PR event: no per-PR diff to scan; scanning ALL agent surfaces of the checkout instead.');
    const full = await scanFiles(base, setup.surface, setup.config.ignore ?? []);
    findings.push(...full.findings);
    for (const s of full.scanned) surfaceFiles.push({ path: s.path, profiles: s.matchedProfiles });
    skipped = full.skipped;
  } else if (gh) {
    sawSource = true;
    notices.push('No diff source: local repository files were NOT scanned; only tracker text was inspected. Not-inspected ≠ clean.');
  }

  if (!sawSource) {
    return fail('gate: no input source. Use --diff <file.patch>, run inside GitHub Actions (GITHUB_EVENT_PATH), or pass --repo owner/name with --issue/--pr.');
  }

  const verdict = computeVerdict(findings);
  changedFilesNotice(notices);

  const report: RunReport = {
    command: 'gate',
    target: base,
    profiles: setup.profileNames,
    surfaceFiles,
    changedFiles,
    events: ev.texts,
    skipped,
    offSurfaceCount: undefined,
    findings: sortFindings(findings),
    notices,
    verdict,
  };
  emit(fmt.format as Format, report);
  return verdict === 'FAIL' && !warnOnly ? 1 : 0;
}

function cmdSurfaces(args: ParsedArgs): number {
  const raw = flag(args, '--format') ?? 'text';
  if (raw !== 'text' && raw !== 'json') {
    return fail(`invalid --format "${raw}" for surfaces (expected text | json)`);
  }
  const all = [...AGENT_PROFILES, ALL_PROFILE];
  if (raw === 'json') {
    process.stdout.write(
      JSON.stringify(
        { tool: 'repo-inject-guard', version: VERSION, profiles: all },
        null,
        2
      ) + '\n'
    );
    return 0;
  }
  const L: string[] = [];
  L.push('agent surface profiles — files each agent AUTO-READS (and therefore obeys)');
  L.push('');
  for (const p of all) {
    L.push(`${p.name} — ${p.description}`);
    for (const pattern of p.patterns) L.push(`    ${pattern}`);
    L.push('');
  }
  L.push('Bare filenames match at any depth; directory globs are anchored at the repo root.');
  L.push('Matching is case-insensitive (case tricks are cheap obfuscation).');
  L.push('Add custom surfaces via rig.yaml (extraPaths) — see the README configuration reference.');
  process.stdout.write(L.join('\n') + '\n');
  return 0;
}

export async function run(argv: string[]): Promise<number> {
  const { parsed, error } = parseArgv(argv);
  if (error || !parsed) return fail(error ?? 'invalid arguments');
  const command = parsed.command ?? 'help';
  switch (command) {
    case 'scan':
      return await cmdScan(parsed, false);
    case 'certify':
      return await cmdScan(parsed, true);
    case 'gate':
      return await cmdGate(parsed);
    case 'surfaces':
      return cmdSurfaces(parsed);
    case 'help':
      process.stdout.write(usage());
      return 0;
    default:
      process.stderr.write(usage());
      return fail(`unknown command: ${command}`);
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  run(process.argv.slice(2)).then((code) => {
    process.exitCode = code;
  });
}
