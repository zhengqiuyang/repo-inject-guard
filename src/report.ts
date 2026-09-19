/**
 * Output rendering: human text, GitHub Actions annotations, JSON and SARIF
 * 2.1.0. Every renderer gets the same RunReport.
 */
import {
  Finding,
  FindingLocation,
  RULE_ORDER,
  RULES,
  RuleId,
  TrustLevel,
  Verdict,
  countBySeverity,
} from './rules.js';
import type { EventText } from './events.js';
import type { SkippedFile } from './scan.js';

export const VERSION = '0.1.0';
export const TOOL_NAME = 'repo-inject-guard';

export interface RunReport {
  command: 'scan' | 'gate' | 'certify';
  target?: string;
  profiles: string[];
  surfaceFiles: { path: string; profiles: string[] }[];
  changedFiles?: string[];
  events: EventText[];
  skipped: SkippedFile[];
  /** repo files seen during the walk that are NOT on any agent surface */
  offSurfaceCount?: number;
  offSurfaceExamples?: string[];
  findings: Finding[];
  notices: string[];
  verdict: Verdict;
  certification?: string;
}

export function certificationFor(verdict: Verdict): string {
  switch (verdict) {
    case 'PASS':
      return 'SAFE TO POINT AN AGENT AT THIS REPOSITORY';
    case 'WARN':
      return 'CAUTION — REVIEW FINDINGS BEFORE POINTING AN AGENT AT THIS REPOSITORY';
    case 'FAIL':
      return 'DO NOT POINT AN AGENT AT THIS REPOSITORY';
  }
}

function locationLabel(loc: FindingLocation): string {
  if (loc.kind === 'file') return `${loc.path}:${loc.line}`;
  const author = loc.author ? `by ${loc.author}` : 'unknown author';
  const assoc = loc.authorAssociation ? `, association ${loc.authorAssociation}` : '';
  return `${loc.source} — ${author}${assoc}`;
}

function trustNote(f: Finding): string {
  if (f.location.kind !== 'event') return '';
  if (f.trust === 'trusted' && f.ruleId !== 'CREDS_EXFIL') {
    return ' [author trusted: downgraded to warning]';
  }
  if (f.trust === 'untrusted' && f.severity === 'medium') {
    return ' [author untrusted: medium severity fails]';
  }
  return '';
}

const VERDICT_EXPLANATION: Record<Verdict, string> = {
  PASS: 'No findings on the surfaces that were inspected. This is not a clean bill of health for anything not inspected.',
  WARN: 'Findings below failure threshold. Review them before trusting this content with an agent.',
  FAIL: 'High-severity finding(s), or medium findings from an untrusted author. Do not point an agent at this content before a human reviews it.',
};

export function renderText(r: RunReport): string {
  const L: string[] = [];
  const bar = '='.repeat(78);

  L.push(`${TOOL_NAME} v${VERSION} — ${r.command}`);
  if (r.target) L.push(`target: ${r.target}`);
  L.push(`profiles: ${r.profiles.join(', ')}`);
  L.push('');

  if (r.changedFiles) {
    L.push(`files changed in the PR: ${r.changedFiles.length}`);
    for (const cf of r.changedFiles) {
      const surfaceHit = r.surfaceFiles.find((s) => s.path === cf);
      L.push(`  ${cf}${surfaceHit ? `  [on agent surface: ${surfaceHit.profiles.join(' ')}]` : '  (off-surface — not scanned)'}`);
    }
    L.push('');
  }

  L.push(`agent-surface files inspected: ${r.surfaceFiles.length}`);
  for (const f of r.surfaceFiles) {
    L.push(`  ${f.path}  [${f.profiles.join(' ')}]`);
  }
  if (r.events.length > 0) {
    L.push('');
    L.push(`tracker text inspected: ${r.events.length}`);
    for (const e of r.events) {
      L.push(`  ${e.source}${e.author ? ` — by ${e.author}` : ''}${e.authorAssociation ? ` (${e.authorAssociation})` : ''}`);
    }
  }
  if (r.skipped.length > 0) {
    L.push('');
    L.push(`skipped files (${r.skipped.length}):`);
    for (const s of r.skipped) L.push(`  ${s.path} (${s.reason})`);
  }
  L.push('');

  if (r.findings.length === 0) {
    L.push('findings: none on the inspected surfaces');
  } else {
    const c = countBySeverity(r.findings);
    L.push(`findings: ${r.findings.length} (${c.high} high, ${c.medium} medium, ${c.low} low)`);
    L.push('');
    r.findings.forEach((f, i) => {
      L.push(`${String(i + 1).padStart(3)}. [${f.severity.toUpperCase()}] ${f.ruleId} — ${locationLabel(f.location)}${trustNote(f)}`);
      L.push(`     ${f.message}`);
      if (f.evidence) L.push(`     evidence: "${f.evidence}"`);
    });
  }
  L.push('');

  if (r.certification) {
    L.push(bar);
    L.push(`VERDICT: ${r.certification}`);
    L.push(bar);
    L.push(VERDICT_EXPLANATION[r.verdict]);
    L.push('');
    L.push('WHAT WAS INSPECTED');
    L.push(`  - ${r.surfaceFiles.length} file(s) on agent auto-read surfaces (${r.profiles.join(', ')})`);
    if (r.events.length > 0) {
      L.push(`  - ${r.events.length} tracker text(s): ${r.events.map((e) => e.source).join('; ')}`);
    }
    L.push(`  - rules: ${RULE_ORDER.join(', ')}`);
    L.push('');
    L.push('WHAT WAS *NOT* INSPECTED (NOT-INSPECTED ≠ CLEAN)');
    if (r.offSurfaceCount !== undefined && r.offSurfaceCount > 0) {
      const ex = (r.offSurfaceExamples ?? []).join(', ');
      L.push(`  - ${r.offSurfaceCount} file(s) outside agent auto-read surfaces${ex ? ` (e.g. ${ex})` : ''}.`);
      L.push('    Your agent may still read these while working a task.');
    }
    if (r.events.length === 0) {
      L.push('  - issue/PR bodies and comments. Run `gate` in CI or pass --repo owner/name --issue N');
      L.push('    (or --pr N) to inspect tracker text before trusting it.');
    }
    if (r.skipped.length > 0) {
      L.push(`  - ${r.skipped.length} skipped file(s) listed above (binary or oversized).`);
    }
    L.push('  - behavior at runtime: this is signature-based static analysis; an obfuscated or');
    L.push('    novel payload can evade every rule. Certification is a filter, not a proof.');
  } else {
    L.push(`verdict: ${r.verdict}`);
    L.push(`  ${VERDICT_EXPLANATION[r.verdict]}`);
  }

  if (r.notices.length > 0) {
    L.push('');
    L.push('NOTICES (not-inspected ≠ clean)');
    for (const n of r.notices) L.push(`  - ${n}`);
  }
  return L.join('\n') + '\n';
}

function escapeAnnotation(s: string): string {
  return s.replace(/%/g, '%25').replace(/\r/g, '%0D').replace(/\n/g, '%0A');
}

export function renderGithub(r: RunReport): string {
  const L: string[] = [];
  const levelFor = (f: Finding): 'error' | 'warning' | 'note' =>
    f.severity === 'high' ? 'error' : f.severity === 'medium' ? 'warning' : 'note';
  for (const f of r.findings) {
    const level = levelFor(f);
    const msg = `${f.ruleId}: ${f.message}${f.evidence ? ` — "${f.evidence}"` : ''}`;
    if (f.location.kind === 'file') {
      const file = f.location.path.replace(/,/g, '%2C');
      L.push(
        `::${level} file=${file},line=${f.location.line},title=${f.ruleId}::${escapeAnnotation(msg)}`
      );
    } else {
      const src = `source: ${f.location.source}${f.location.author ? `, author ${f.location.author} (${f.location.authorAssociation ?? 'unknown'})` : ''}`;
      L.push(`::${level} title=${f.ruleId}::${escapeAnnotation(`${msg} — ${src}`)}`);
    }
  }
  const summaryLevel = r.verdict === 'FAIL' ? 'error' : r.verdict === 'WARN' ? 'warning' : 'notice';
  L.push(`::${summaryLevel} ::${TOOL_NAME} ${r.command} verdict: ${r.verdict}${r.certification ? ` — ${r.certification}` : ''}`);
  for (const n of r.notices) {
    L.push(`::notice ::${escapeAnnotation(n)}`);
  }
  return L.join('\n') + '\n';
}

interface SerializedFinding {
  ruleId: RuleId;
  severity: string;
  message: string;
  evidence: string;
  trust: TrustLevel;
  authorTrustEffect?: string;
  location:
    | { kind: 'file'; path: string; line: number }
    | { kind: 'event'; source: string; url?: string; author?: string; authorAssociation?: string };
}

function serializeFinding(f: Finding): SerializedFinding {
  const out: SerializedFinding = {
    ruleId: f.ruleId,
    severity: f.severity,
    message: f.message,
    evidence: f.evidence,
    trust: f.trust,
    location: f.location,
  };
  if (f.trust === 'trusted' && f.ruleId !== 'CREDS_EXFIL') {
    out.authorTrustEffect = 'downgraded to warning by author trust';
  }
  return out;
}

export function renderJson(r: RunReport): string {
  return (
    JSON.stringify(
      {
        tool: TOOL_NAME,
        version: VERSION,
        command: r.command,
        target: r.target,
        profiles: r.profiles,
        verdict: r.verdict,
        certification: r.certification,
        counts: {
          findings: r.findings.length,
          ...countBySeverity(r.findings),
          surfaceFilesInspected: r.surfaceFiles.length,
          offSurfaceFiles: r.offSurfaceCount ?? 0,
          eventsInspected: r.events.length,
          skippedFiles: r.skipped.length,
        },
        changedFiles: r.changedFiles,
        surfaceFiles: r.surfaceFiles,
        events: r.events,
        skipped: r.skipped,
        findings: r.findings.map(serializeFinding),
        notices: r.notices,
      },
      null,
      2
    ) + '\n'
  );
}

export function renderSarif(r: RunReport): string {
  const sarif = {
    $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
    version: '2.1.0',
    runs: [
      {
        tool: {
          driver: {
            name: TOOL_NAME,
            version: VERSION,
            informationUri: 'https://github.com/repo-inject-guard/repo-inject-guard',
            rules: RULE_ORDER.map((id) => ({
              id,
              shortDescription: { text: RULES[id].summary },
              properties: { severity: RULES[id].severity },
            })),
          },
        },
        results: r.findings.map((f) => {
          const uri =
            f.location.kind === 'file' ? f.location.path : `event:${f.location.source}`;
          const messageText =
            f.location.kind === 'event'
              ? `${f.message} (source: ${f.location.source}${f.location.author ? `, author ${f.location.author} (${f.location.authorAssociation ?? 'unknown'})` : ''}) — evidence: "${f.evidence}"`
              : `${f.message} — evidence: "${f.evidence}"`;
          const physical: Record<string, unknown> = {
            artifactLocation: { uri },
          };
          if (f.location.kind === 'file') {
            physical['region'] = { startLine: f.location.line };
          }
          return {
            ruleId: f.ruleId,
            level: f.severity === 'high' ? 'error' : f.severity === 'medium' ? 'warning' : 'note',
            message: { text: messageText },
            locations: [{ physicalLocation: physical }],
          };
        }),
      },
    ],
  };
  return JSON.stringify(sarif, null, 2) + '\n';
}
