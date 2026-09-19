/**
 * Detection rules. Precision-first: a false positive that blocks a legitimate
 * contribution costs more than a missed exotic payload, so every rule is
 * scoped (agent-surface files / instruction files / events) and the noisiest
 * rule (AGENT_DIRECTIVE) requires corroboration (2+ distinct lines).
 */
import { excerpt, splitLines, findHiddenCodepointNames } from './util.js';

export type Severity = 'high' | 'medium' | 'low';
export type TrustLevel = 'trusted' | 'neutral' | 'untrusted';
export type Verdict = 'PASS' | 'WARN' | 'FAIL';

export type RuleId =
  | 'INSTR_OVERRIDE'
  | 'SYSTEM_PROMPT_EXFIL'
  | 'CREDS_EXFIL'
  | 'ENV_PROBE'
  | 'HIDDEN_UNICODE'
  | 'AGENT_DIRECTIVE'
  | 'RULES_BACKDOOR'
  | 'RESOURCE_LURE';

export interface RuleInfo {
  id: RuleId;
  severity: Severity;
  summary: string;
  description: string;
}

export const RULES: Record<RuleId, RuleInfo> = {
  INSTR_OVERRIDE: {
    id: 'INSTR_OVERRIDE',
    severity: 'high',
    summary: 'Instruction-override attempt',
    description:
      'Text tries to cancel or replace the agent\'s standing instructions ("ignore previous instructions" family).',
  },
  SYSTEM_PROMPT_EXFIL: {
    id: 'SYSTEM_PROMPT_EXFIL',
    severity: 'medium',
    summary: 'System prompt extraction',
    description: 'Asks the agent to reveal its system prompt.',
  },
  CREDS_EXFIL: {
    id: 'CREDS_EXFIL',
    severity: 'high',
    summary: 'Credential / environment exfiltration',
    description:
      'Actual secret data flow: an output/transfer verb on a credential file, an echo of an environment variable VALUE, a broad environment dump, or curl/wget POST paired with secret references in the same file. Prose merely mentioning "env vars" does not fire.',
  },
  ENV_PROBE: {
    id: 'ENV_PROBE',
    severity: 'medium',
    summary: 'Scoped credential presence probe',
    description:
      'Prints whether ONE named variable is set (env | grep NAME, printenv NAME, ${VAR:+SET}) — a common debugging idiom, not a dump. Reported so reviewers see it, but it does not fail trusted content.',
  },
  HIDDEN_UNICODE: {
    id: 'HIDDEN_UNICODE',
    severity: 'high',
    summary: 'Hidden Unicode characters',
    description:
      'Zero-width or bidi control characters that can smuggle instructions past human review. Always reported on their own, without needing other signals.',
  },
  AGENT_DIRECTIVE: {
    id: 'AGENT_DIRECTIVE',
    severity: 'low',
    summary: 'Second-person agent directives',
    description:
      'Two or more imperative lines addressed to the agent ("you must run ...", "note to the AI ...") in one agent-surface file.',
  },
  RULES_BACKDOOR: {
    id: 'RULES_BACKDOOR',
    severity: 'high',
    summary: 'Rules-file backdoor phrasing',
    description:
      'Instruction files telling the agent to conceal actions from the user ("do not tell the user", "hide this from", "secretly", "without the user\'s knowledge").',
  },
  RESOURCE_LURE: {
    id: 'RESOURCE_LURE',
    severity: 'medium',
    summary: 'Resource lure',
    description:
      'Long base64 blobs or mixed-script (homoglyph) URLs impersonating trusted domains.',
  },
};

export const RULE_ORDER: RuleId[] = [
  'INSTR_OVERRIDE',
  'SYSTEM_PROMPT_EXFIL',
  'CREDS_EXFIL',
  'HIDDEN_UNICODE',
  'AGENT_DIRECTIVE',
  'RULES_BACKDOOR',
  'RESOURCE_LURE',
];

export interface FileLocation {
  kind: 'file';
  path: string;
  line: number;
}

export interface EventLocation {
  kind: 'event';
  source: string;
  url?: string;
  author?: string;
  authorAssociation?: string;
}

export type FindingLocation = FileLocation | EventLocation;

export interface Finding {
  ruleId: RuleId;
  severity: Severity;
  message: string;
  /** Capped at 120 chars, control characters escaped. */
  evidence: string;
  location: FindingLocation;
  trust: TrustLevel;
}

export interface RuleContext {
  kind: 'file' | 'event';
  location: FindingLocation;
  /** markdown-ish text (md files, .cursorrules, issue bodies) */
  markdownLike: boolean;
  /** instruction files (agent-surface markdown) and tracker text */
  instructionFile: boolean;
  trust?: TrustLevel;
}

// ---------------------------------------------------------------------------
// Patterns
// ---------------------------------------------------------------------------

const INSTR_OVERRIDE_PATTERNS: RegExp[] = [
  /\bignore\s+(?:\w+\s+){0,2}?(?:previous|prior|above)\s+(?:instructions?|rules?|context|guidance|prompts?)\b/i,
  /\bdisregard\s+(?:\w+\s+){0,2}?(?:instructions?|rules?|prompts?)\b/i,
  /\bforget\s+(?:\w+\s+){0,2}?(?:previous|prior|above|all|your)\s+(?:instructions?|rules?|context|guidance|prompts?)\b/i,
];

const SYSTEM_PROMPT_EXFIL_RE =
  /\b(?:reveal|print|show|share|repeat|output|display)\s+(?:me\s+|us\s+)?(?:your\s+|the\s+)?system\s+prompt\b/i;

/** Credential FILES and material: SSH keys, cloud/registry credential files. */
const FILE_CRED_RE =
  /(~\/\.ssh|\/\.ssh\/|\.ssh\/|id_rsa|id_ed25519|id_ecdsa|authorized_keys|\.aws\/credentials|\.aws\/config|\.netrc|\.npmrc|\.pypirc|\.docker\/config\.json|\.gnupg|kubeconfig|service[_-]?account(?:\s+key)?\s+file)/i;

/**
 * Scoped credential presence probe: prints whether ONE named variable is set
 * (env | grep NAME, printenv NAME, ${VAR:+SET}) — a debugging idiom, not a
 * dump. Reported at medium so trusted content still passes.
 */
const SCOPED_PROBE_RE = /\b(?:env\s*\|\s*grep|printenv)\s+["']?[A-Za-z_][A-Za-z0-9_]*["']?/;

/** Broad environment dump: bare `env`/`printenv` flowing onward (pipe, redirect, chain). */
const BROAD_DUMP_RE = /\b(?:printenv|env)\b\s*(?:$|[|>&;])/;

/**
 * True value flow: a $VAR / ${VAR} expansion that is NOT the presence-only
 * forms (${VAR:+...}, ${VAR:-...}) — those never reveal the value itself.
 */
function hasValueExpansion(line: string): boolean {
  const stripped = line.replace(/\$\{[A-Za-z_][A-Za-z0-9_]*(?::[-+?][^}]*)?\}/g, (m) =>
    /:(?:\+|-|\?)/.test(m) ? '' : m,
  );
  return /\$(?:\{[A-Za-z_][A-Za-z0-9_]*\}|[A-Za-z_][A-Za-z0-9_]*)/.test(stripped);
}

/** Verbs that move or expose data. Single-word forms only, word-bounded. */
const EXFIL_VERB_RE =
  /\b(?:print|show|echo|send|post|upload|reveal|dump|cat|include|attach|exfiltrate|leak|paste|forward|write\s+out|read\s+out)\b/i;

/** Prose "print all environment variables" instructions (no literal data flow). */
const PROSE_ENV_RE =
  /\b(?:print|show|dump|reveal|send|paste|include|attach|forward|echo)\b[^.\n]{0,60}\b(?:all\s+)?(?:the\s+)?(?:environment\s+variables?|env\s+vars?|process\.env)\b/i;

const POST_TOOL_RE = /\b(?:curl|wget|Invoke-WebRequest|Invoke-RestMethod)\b/i;
const POST_FLAG_RE =
  /(\s-d\b|\s--data\b|--data-raw|--data-binary|--data-urlencode|-X\s*POST|--post-data|--body-file|\s--form\b|\s-F\b|--upload-file|\s-T\s)/i;

const AGENT_DIRECTIVE_RE =
  /^(?:you\s+must|always|never|before\s+every|from\s+now\s+on)[,;:]?\s+(?:use|run|execute|call|send|write|delete)\b/i;
const NOTE_TO_AGENT_RE = /\bnotes?\s+to\s+(?:the\s+)?(?:ai|agent|reviewer|ci)\b/i;

const RULES_BACKDOOR_PATTERNS: RegExp[] = [
  /\bdo\s+not\s+(?:tell|inform|show|notify|alert|warn)\s+(?:the\s+|your\s+)?user/i,
  /\bhide\s+this\s+from/i,
  /\bsecretly\b/i,
  /\bwithout\s+(?:the\s+)?(?:user'?s|users'?|your)\s+knowledge/i,
];

/** Strictly more than 120 consecutive standard base64 characters. */
const BASE64_BLOB_RE = /[A-Za-z0-9+/]{121,}={0,2}/;
const URL_RE = /https?:\/\/[^\s<>"'`)\]}]+/gi;

// ---------------------------------------------------------------------------
// Rule application
// ---------------------------------------------------------------------------

function fileLineOf(ctx: RuleContext, lineIndex: number): FindingLocation {
  if (ctx.location.kind === 'file') {
    return { kind: 'file', path: ctx.location.path, line: lineIndex + 1 };
  }
  return ctx.location;
}

function scriptOf(ch: string): string | null {
  if (/[a-zA-Z]/.test(ch)) return 'latin';
  if (/[\u0400-\u04FF]/.test(ch)) return 'cyrillic';
  if (/[\u0370-\u03FF\u1F00-\u1FFF]/.test(ch)) return 'greek';
  if (/[\u0531-\u058F]/.test(ch)) return 'armenian';
  if (/[\u0590-\u05FF]/.test(ch)) return 'hebrew';
  if (/[\u0600-\u06FF]/.test(ch)) return 'arabic';
  if (/[\u3040-\u30FF\u4E00-\u9FFF\uAC00-\uD7AF]/.test(ch)) return 'cjk';
  if (ch.charCodeAt(0) > 127) return 'other-nonascii';
  return null; // digits, dots, hyphens, ports
}

/** Mixed-script / non-latin hostname detector (homoglyph lookalike domains). */
export function homoglyphHostCheck(host: string): { flag: boolean; scripts: string[] } {
  const scripts = new Set<string>();
  for (const ch of host) {
    const s = scriptOf(ch);
    if (s) scripts.add(s);
  }
  const list = [...scripts];
  const hasNonLatin = list.some((s) => s !== 'latin');
  return { flag: list.length >= 2 || hasNonLatin, scripts: list };
}

function hostOf(url: string): string {
  let h = url.replace(/^https?:\/\//i, '').split(/[\/?#]/)[0] ?? '';
  const at = h.lastIndexOf('@');
  if (at !== -1) h = h.slice(at + 1);
  return h;
}

export function applyRules(text: string, ctx: RuleContext): Finding[] {
  const lines = splitLines(text);
  const findings: Finding[] = [];
  const trust: TrustLevel = ctx.trust ?? 'neutral';

  const push = (ruleId: RuleId, message: string, evidence: string, location: FindingLocation) => {
    findings.push({
      ruleId,
      severity: RULES[ruleId].severity,
      message,
      evidence: excerpt(evidence),
      location,
      trust,
    });
  };

  // INSTR_OVERRIDE + SYSTEM_PROMPT_EXFIL: any scanned text
  lines.forEach((line, i) => {
    if (INSTR_OVERRIDE_PATTERNS.some((re) => re.test(line))) {
      push(
        'INSTR_OVERRIDE',
        'Instruction-override attempt: text tries to cancel or replace the agent\'s standing instructions.',
        line,
        fileLineOf(ctx, i)
      );
    }
    if (SYSTEM_PROMPT_EXFIL_RE.test(line)) {
      push(
        'SYSTEM_PROMPT_EXFIL',
        'System prompt extraction: asks the agent to reveal its system prompt.',
        line,
        fileLineOf(ctx, i)
      );
    }
  });

  // CREDS_EXFIL (high: real data flow) + ENV_PROBE (medium: presence probe)
  const credLines = new Set<number>();
  lines.forEach((line, i) => {
    if (SCOPED_PROBE_RE.test(line)) {
      credLines.add(i);
      push(
        'ENV_PROBE',
        'Scoped credential presence probe: prints whether one named variable is set — a debugging idiom, not a dump.',
        line,
        fileLineOf(ctx, i)
      );
      return;
    }
    const verb = EXFIL_VERB_RE.test(line);
    const fileCred = FILE_CRED_RE.test(line);
    if (fileCred && (verb || BROAD_DUMP_RE.test(line))) {
      credLines.add(i);
      push(
        'CREDS_EXFIL',
        'Credential/environment exfiltration: an output or transfer verb on credential material.',
        line,
        fileLineOf(ctx, i)
      );
      return;
    }
    if (BROAD_DUMP_RE.test(line)) {
      credLines.add(i);
      push(
        'CREDS_EXFIL',
        'Credential/environment exfiltration: broad environment dump.',
        line,
        fileLineOf(ctx, i)
      );
      return;
    }
    if (verb && hasValueExpansion(line)) {
      credLines.add(i);
      push(
        'CREDS_EXFIL',
        'Credential/environment exfiltration: prints an environment variable value.',
        line,
        fileLineOf(ctx, i)
      );
      return;
    }
    // Prose instruction to expose environment variables — no literal data flow
    // on the line. Advisory for trusted content (own repos use this idiom in
    // lessons), gating for untrusted authors.
    if (PROSE_ENV_RE.test(line)) {
      credLines.add(i);
      push(
        'ENV_PROBE',
        'Instructs exposing environment variables in prose; no single-variable data flow detected. Advisory for trusted content, gating for untrusted authors.',
        line,
        fileLineOf(ctx, i)
      );
    }
  });
  const sawCredAnywhere = lines.some((l) => FILE_CRED_RE.test(l) || hasValueExpansion(l));
  if (sawCredAnywhere) {
    lines.forEach((line, i) => {
      if (!credLines.has(i) && POST_TOOL_RE.test(line) && POST_FLAG_RE.test(line)) {
        push(
          'CREDS_EXFIL',
          'Credential/environment exfiltration: curl/wget POST combined with secret references elsewhere in the same file.',
          line,
          fileLineOf(ctx, i)
        );
      }
    });
  }

  // HIDDEN_UNICODE: always a finding, line 1 leading BOM excepted (real BOMs)
  lines.forEach((line, i) => {
    const hay = i === 0 && line.startsWith('\uFEFF') ? line.slice(1) : line;
    const names = findHiddenCodepointNames(hay);
    if (names.length > 0) {
      push(
        'HIDDEN_UNICODE',
        `Hidden Unicode detected (${names.join(', ')}): invisible or bidi characters can carry instructions humans cannot see.`,
        line,
        fileLineOf(ctx, i)
      );
    }
  });

  // AGENT_DIRECTIVE: markdown-like text, 2+ distinct directive lines required
  if (ctx.markdownLike) {
    const directiveLines: { line: number; text: string }[] = [];
    lines.forEach((line, i) => {
      if (AGENT_DIRECTIVE_RE.test(line) || NOTE_TO_AGENT_RE.test(line)) {
        directiveLines.push({ line: i + 1, text: line });
      }
    });
    if (directiveLines.length >= 2) {
      const first = directiveLines[0] as { line: number; text: string };
      push(
        'AGENT_DIRECTIVE',
        `${directiveLines.length} imperative line(s) addressed to the agent (fires at 2+): second-person commands a normal document rarely needs.`,
        first.text,
        ctx.location.kind === 'file'
          ? { kind: 'file', path: ctx.location.path, line: first.line }
          : ctx.location
      );
    }
  }

  // RULES_BACKDOOR: instruction files and tracker text only
  if (ctx.instructionFile) {
    lines.forEach((line, i) => {
      if (RULES_BACKDOOR_PATTERNS.some((re) => re.test(line))) {
        push(
          'RULES_BACKDOOR',
          'Rules-file backdoor phrasing: instructs the agent to conceal actions from the user.',
          line,
          fileLineOf(ctx, i)
        );
      }
    });
  }

  // RESOURCE_LURE: base64 blobs in markdown-like text, homoglyph URLs anywhere scanned
  if (ctx.markdownLike) {
    lines.forEach((line, i) => {
      const m = line.match(BASE64_BLOB_RE);
      if (m && m[0].length > 0) {
        push(
          'RESOURCE_LURE',
          `Long base64 blob (${m[0].length} chars): common carrier for smuggled payloads.`,
          line,
          fileLineOf(ctx, i)
        );
      }
    });
  }
  lines.forEach((line, i) => {
    const urls = line.match(URL_RE);
    if (!urls) return;
    for (const url of urls) {
      const host = hostOf(url);
      const check = homoglyphHostCheck(host);
      if (check.flag && host.length > 0) {
        push(
          'RESOURCE_LURE',
          `Lookalike URL host "${host}" mixes scripts (${check.scripts.join(' + ')}): likely homoglyph impersonation of a trusted domain.`,
          line,
          fileLineOf(ctx, i)
        );
      }
    }
  });

  return findings;
}

// ---------------------------------------------------------------------------
// Author trust + verdicts
// ---------------------------------------------------------------------------

/**
 * GitHub author_association -> trust tier.
 * MEMBER/OWNER are trusted; NONE/FIRST_TIME_CONTRIBUTOR are untrusted
 * (stricter verdict); everything else (CONTRIBUTOR, COLLABORATOR, unknown)
 * is neutral.
 */
export function associationToTrust(association?: string): TrustLevel {
  const a = (association ?? '').toUpperCase();
  if (a === 'MEMBER' || a === 'OWNER') return 'trusted';
  if (a === 'NONE' || a === 'FIRST_TIME_CONTRIBUTOR' || a === 'FIRST_TIMER' || a === 'MANNEQUIN') {
    return 'untrusted';
  }
  return 'neutral';
}

/**
 * Does this finding, on its own, force a FAIL verdict?
 *
 *   severity | neutral (files) | untrusted author | trusted author
 *   high     | FAIL            | FAIL             | WARN *  (* except CREDS_EXFIL: always FAIL,
 *   medium   | WARN            | FAIL             | WARN      a compromised owner account is a
 *   low      | WARN            | WARN             | WARN      real attack path)
 */
export function findingCausesFail(f: Finding): boolean {
  if (f.trust === 'trusted' && f.ruleId !== 'CREDS_EXFIL') return false;
  if (f.severity === 'high') return true;
  if (f.severity === 'medium') return f.trust === 'untrusted';
  return false;
}

export function computeVerdict(findings: Finding[]): Verdict {
  let fail = false;
  let warn = false;
  for (const f of findings) {
    if (findingCausesFail(f)) fail = true;
    else warn = true;
  }
  return fail ? 'FAIL' : warn ? 'WARN' : 'PASS';
}

const SEVERITY_RANK: Record<Severity, number> = { high: 0, medium: 1, low: 2 };

export function sortFindings(findings: Finding[]): Finding[] {
  return [...findings].sort((a, b) => {
    const s = SEVERITY_RANK[a.severity] - SEVERITY_RANK[b.severity];
    if (s !== 0) return s;
    const ra = RULE_ORDER.indexOf(a.ruleId) - RULE_ORDER.indexOf(b.ruleId);
    if (ra !== 0) return ra;
    const la = a.location.kind === 'file' ? `${a.location.path}:${a.location.line}` : a.location.source;
    const lb = b.location.kind === 'file' ? `${b.location.path}:${b.location.line}` : b.location.source;
    return la.localeCompare(lb);
  });
}

export function countBySeverity(findings: Finding[]): { high: number; medium: number; low: number } {
  const c = { high: 0, medium: 0, low: 0 };
  for (const f of findings) c[f.severity] += 1;
  return c;
}
