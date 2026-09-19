/**
 * Event scanning: issues / PR bodies and comments, which coding agents read
 * (and obey) as eagerly as repository files.
 *
 * Two sources:
 *  - Actions mode: GITHUB_EVENT_PATH payload (issue/comment/pull_request events),
 *    including the author association for trust context.
 *  - Local mode: `gh` CLI (gh api repos/{o}/{r}/issues/{n}, /comments, pulls/...).
 *
 * When neither is available the events are skipped with an explicit notice —
 * never silently treated as clean.
 */
import { readFile } from 'node:fs/promises';
import { spawnSync } from 'node:child_process';
import { Finding, associationToTrust, applyRules, sortFindings } from './rules.js';
import { errMsg } from './util.js';

export interface EventText {
  source: string;
  text: string;
  author?: string;
  authorAssociation?: string;
  url?: string;
}

export interface GhRunnerResult {
  status: number | null;
  stdout: string;
  stderr: string;
  error?: unknown;
}

export type GhRunner = (args: string[]) => GhRunnerResult;

export const defaultGhRunner: GhRunner = (args) => {
  const r = spawnSync('gh', args, { encoding: 'utf8' });
  return {
    status: r.status,
    stdout: r.stdout ?? '',
    stderr: r.stderr ?? '',
    error: r.error,
  };
};

export interface GhApiResult {
  ok: boolean;
  data?: unknown;
  error?: string;
}

export function ghApi(path: string, runner: GhRunner = defaultGhRunner): GhApiResult {
  let r: GhRunnerResult;
  try {
    r = runner(['api', path]);
  } catch (e) {
    return { ok: false, error: `gh CLI could not be executed (${errMsg(e)})` };
  }
  if (r.status === 0) {
    try {
      return { ok: true, data: JSON.parse(r.stdout) };
    } catch {
      return { ok: false, error: 'gh api returned non-JSON output' };
    }
  }
  const errText = `${r.stderr}\n${r.stdout}`.toLowerCase();
  if (r.error || r.status === 127 || errText.includes('command not found') || errText.includes('is not recognized')) {
    return { ok: false, error: 'gh CLI not found on PATH' };
  }
  if (errText.includes('not logged in') || errText.includes('auth') || errText.includes('credential')) {
    return { ok: false, error: 'gh CLI is not authenticated (no GitHub token)' };
  }
  return { ok: false, error: `gh api exited with status ${r.status}` };
}

export interface EventExtractResult {
  texts: EventText[];
  notices: string[];
  eventType: string;
  /** set only for pull_request* events: repo + PR number for changed-file lookup */
  prContext?: { repo: string; number: number };
}

interface IssueLike {
  number?: number;
  title?: string | null;
  body?: string | null;
  user?: { login?: string } | null;
  author_association?: string | null;
  html_url?: string | null;
}

function pushIssueLike(texts: EventText[], it: IssueLike | null | undefined, label: string): void {
  if (!it) return;
  const title = typeof it.title === 'string' ? it.title : '';
  const body = typeof it.body === 'string' ? it.body : '';
  const text = `${title}\n\n${body}`.trim();
  if (!text) return;
  texts.push({
    source: label,
    text,
    author: it.user?.login,
    authorAssociation: it.author_association ?? undefined,
    url: it.html_url ?? undefined,
  });
}

export function extractTextsFromEventPayload(payload: unknown, eventName?: string): EventExtractResult {
  const p = (payload ?? {}) as Record<string, any>;
  const type = String(eventName ?? p['name'] ?? 'unknown');
  const texts: EventText[] = [];
  const notices: string[] = [];
  const issue = p['issue'] as IssueLike | undefined;
  const pr = p['pull_request'] as IssueLike | undefined;
  const repo = p['repository']?.full_name as string | undefined;

  switch (type) {
    case 'issues':
      pushIssueLike(texts, issue, `issue #${issue?.number ?? '?'} (title+body)`);
      break;
    case 'issue_comment': {
      pushIssueLike(texts, issue, `issue #${issue?.number ?? '?'} (title+body)`);
      const c = p['comment'] as IssueLike | undefined;
      if (c && typeof c.body === 'string' && c.body.trim()) {
        texts.push({
          source: `comment on issue #${issue?.number ?? '?'}`,
          text: c.body,
          author: c.user?.login,
          authorAssociation: c.author_association ?? undefined,
          url: c.html_url ?? undefined,
        });
      }
      break;
    }
    case 'pull_request':
      pushIssueLike(texts, pr, `PR #${pr?.number ?? '?'} (title+body)`);
      break;
    case 'pull_request_review': {
      const review = p['review'] as IssueLike | undefined;
      if (review && typeof review.body === 'string' && review.body.trim()) {
        texts.push({
          source: `review on PR #${pr?.number ?? '?'}`,
          text: review.body,
          author: review.user?.login,
          authorAssociation: review.author_association ?? undefined,
          url: review.html_url ?? undefined,
        });
      }
      break;
    }
    case 'pull_request_review_comment': {
      const c = p['comment'] as IssueLike | undefined;
      if (c && typeof c.body === 'string' && c.body.trim()) {
        texts.push({
          source: `review comment on PR #${pr?.number ?? '?'}`,
          text: c.body,
          author: c.user?.login,
          authorAssociation: c.author_association ?? undefined,
          url: c.html_url ?? undefined,
        });
      }
      break;
    }
    default:
      notices.push(
        `GitHub event type "${type}" is not inspected by repo-inject-guard (only issues, issue_comment, pull_request, pull_request_review, pull_request_review_comment). Not-inspected ≠ clean.`
      );
      break;
  }

  const prContext =
    pr && typeof pr.number === 'number' && repo ? { repo, number: pr.number } : undefined;

  return { texts, notices, eventType: type, prContext };
}

export interface GhEventRequest {
  repo: string;
  number: number;
  kind: 'issue' | 'pr';
}

export interface EventScanOutcome {
  texts: EventText[];
  notices: string[];
  prContext?: { repo: string; number: number };
}

export async function collectEventTexts(opts: {
  eventPath?: string;
  eventName?: string;
  gh?: GhEventRequest;
  runner?: GhRunner;
}): Promise<EventScanOutcome> {
  const notices: string[] = [];
  const texts: EventText[] = [];
  let prContext: { repo: string; number: number } | undefined;

  if (opts.eventPath) {
    let payload: unknown;
    try {
      payload = JSON.parse(await readFile(opts.eventPath, 'utf8'));
    } catch (e) {
      notices.push(
        `Could not read GITHUB_EVENT_PATH (${opts.eventPath}): ${errMsg(e)}. Event text NOT inspected — not-inspected ≠ clean.`
      );
    }
    if (payload !== undefined) {
      const ex = extractTextsFromEventPayload(payload, opts.eventName);
      texts.push(...ex.texts);
      notices.push(...ex.notices);
      prContext = ex.prContext;
    }
  }

  if (opts.gh) {
    const runner = opts.runner ?? defaultGhRunner;
    const { repo, number, kind } = opts.gh;
    const label = kind === 'pr' ? 'PR' : 'issue';
    const issue = ghApi(`repos/${repo}/issues/${number}`, runner);
    if (!issue.ok || typeof issue.data !== 'object' || issue.data === null) {
      notices.push(
        `${label} #${number} text NOT inspected via gh: ${issue.error ?? 'unexpected response'}. Not-inspected ≠ clean.`
      );
    } else {
      const d = issue.data as Record<string, any>;
      pushIssueLike(
        texts,
        {
          number,
          title: d['title'],
          body: d['body'],
          user: d['user'],
          author_association: d['author_association'],
          html_url: d['html_url'],
        },
        `${label} #${number} (title+body)`
      );
      const comments = ghApi(`repos/${repo}/issues/${number}/comments`, runner);
      if (comments.ok && Array.isArray(comments.data)) {
        comments.data.forEach((c: any, i: number) => {
          if (typeof c?.body === 'string' && c.body.trim()) {
            texts.push({
              source: `comment ${i + 1} on ${label} #${number}`,
              text: c.body,
              author: c.user?.login,
              authorAssociation: c.author_association ?? undefined,
              url: c.html_url ?? undefined,
            });
          }
        });
      } else {
        notices.push(`Comments on ${label} #${number} NOT inspected via gh: ${comments.error}. Not-inspected ≠ clean.`);
      }
      if (kind === 'pr') {
        const reviewComments = ghApi(`repos/${repo}/pulls/${number}/comments`, runner);
        if (reviewComments.ok && Array.isArray(reviewComments.data)) {
          reviewComments.data.forEach((c: any, i: number) => {
            if (typeof c?.body === 'string' && c.body.trim()) {
              texts.push({
                source: `review comment ${i + 1} on PR #${number}`,
                text: c.body,
                author: c.user?.login,
                authorAssociation: c.author_association ?? undefined,
                url: c.html_url ?? undefined,
              });
            }
          });
        }
      }
    }
  }

  return { texts, notices, prContext };
}

export function scanEventTexts(texts: EventText[]): Finding[] {
  const out: Finding[] = [];
  for (const t of texts) {
    const trust = associationToTrust(t.authorAssociation);
    out.push(
      ...applyRules(t.text, {
        kind: 'event',
        location: {
          kind: 'event',
          source: t.source,
          url: t.url,
          author: t.author,
          authorAssociation: t.authorAssociation,
        },
        markdownLike: true,
        instructionFile: true,
        trust,
      })
    );
  }
  return sortFindings(out);
}
