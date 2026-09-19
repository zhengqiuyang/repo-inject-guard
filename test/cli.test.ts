import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const cli = fileURLToPath(new URL('../src/cli.js', import.meta.url));
const fixture = (p: string): string =>
  fileURLToPath(new URL(`../../test/fixtures/${p}`, import.meta.url));

interface CliResult {
  status: number | null;
  stdout: string;
  stderr: string;
}

function runCli(args: string[], opts: { cwd?: string } = {}): CliResult {
  const env: Record<string, string> = {};
  for (const [k, v] of Object.entries(process.env)) {
    if (v !== undefined) env[k] = v;
  }
  env['GITHUB_EVENT_PATH'] = '';
  env['GITHUB_EVENT_NAME'] = '';
  const res = spawnSync(process.execPath, [cli, ...args], {
    encoding: 'utf8',
    cwd: opts.cwd,
    env,
  });
  return { status: res.status, stdout: res.stdout ?? '', stderr: res.stderr ?? '' };
}

test('scan: poisoned repo fails with cited findings across rules', () => {
  const res = runCli(['scan', fixture('poisoned-repo')]);
  assert.equal(res.status, 1);
  assert.match(res.stdout, /verdict: FAIL/);
  for (const id of ['INSTR_OVERRIDE', 'CREDS_EXFIL', 'HIDDEN_UNICODE', 'RULES_BACKDOOR', 'AGENT_DIRECTIVE', 'RESOURCE_LURE']) {
    assert.match(res.stdout, new RegExp(id));
  }
  assert.match(res.stdout, /\.cursorrules:3/);
  assert.match(res.stdout, /U\+200B/);
  assert.match(res.stdout, /not-inspected ≠ clean/i);
});

test('scan: clean repo passes with exit 0', () => {
  const res = runCli(['scan', fixture('clean-repo')]);
  assert.equal(res.status, 0);
  assert.match(res.stdout, /verdict: PASS/);
  assert.match(res.stdout, /findings: none on the inspected surfaces/);
  // README.md content ("Always run ...") is off-surface and must not be scanned
  assert.doesNotMatch(res.stdout, /README\.md\s+\[/);
});

test('scan: --profile cursor still catches .cursorrules payloads', () => {
  const res = runCli(['scan', fixture('poisoned-repo'), '--profile', 'cursor']);
  assert.equal(res.status, 1);
  assert.match(res.stdout, /profiles: cursor/);
  assert.match(res.stdout, /\.cursorrules/);
});

test('scan: --format json stays parseable and caps evidence at 120 chars', () => {
  const res = runCli(['scan', fixture('poisoned-repo'), '--format', 'json']);
  assert.equal(res.status, 1);
  const parsed = JSON.parse(res.stdout) as {
    verdict: string;
    findings: { evidence: string; ruleId: string }[];
    notices: string[];
  };
  assert.equal(parsed.verdict, 'FAIL');
  assert.ok(parsed.findings.length >= 5);
  for (const f of parsed.findings) {
    assert.ok(f.evidence.length <= 120, `evidence too long for ${f.ruleId}`);
    assert.ok(f.ruleId);
  }
  assert.ok(parsed.notices.length >= 2, 'not-inspected notices are always present');
});

test('scan: --format github on the clean repo emits no error annotations', () => {
  const res = runCli(['scan', fixture('clean-repo'), '--format', 'github']);
  assert.equal(res.status, 0);
  assert.doesNotMatch(res.stdout, /::error/);
  assert.match(res.stdout, /::notice ::/);
});

test('scan: nonexistent path is a harness error (exit 2)', () => {
  const res = runCli(['scan', fixture('definitely/missing-repo')]);
  assert.equal(res.status, 2);
  assert.match(res.stderr, /cannot read directory/);
});

test('scan: unknown profile is a config error (exit 2)', () => {
  const res = runCli(['scan', fixture('clean-repo'), '--profile', 'nope']);
  assert.equal(res.status, 2);
  assert.match(res.stderr, /unknown profile/);
});

test('certify: poisoned repo -> DO NOT verdict and exit 1', () => {
  const res = runCli(['certify', fixture('poisoned-repo')]);
  assert.equal(res.status, 1);
  assert.match(res.stdout, /VERDICT: DO NOT POINT AN AGENT AT THIS REPOSITORY/);
  assert.match(res.stdout, /WHAT WAS \*NOT\* INSPECTED/);
  assert.match(res.stdout, /README\.md/);
});

test('certify: clean repo -> SAFE verdict and exit 0', () => {
  const res = runCli(['certify', fixture('clean-repo')]);
  assert.equal(res.status, 0);
  assert.match(res.stdout, /VERDICT: SAFE TO POINT AN AGENT AT THIS REPOSITORY/);
});

test('surfaces: lists every profile and its auto-read files', () => {
  const res = runCli(['surfaces']);
  assert.equal(res.status, 0);
  for (const token of ['claude-code', 'codex', 'cursor', 'copilot', 'gemini', 'opencode', 'all']) {
    assert.match(res.stdout, new RegExp(`^${token} — `, 'm'));
  }
  assert.match(res.stdout, /\.cursorrules/);
  assert.match(res.stdout, /GEMINI\.md/);
  assert.match(res.stdout, /\.github\/copilot-instructions\.md/);
});

test('help: exits 0 and documents the exit-code contract', () => {
  const res = runCli(['help']);
  assert.equal(res.status, 0);
  assert.match(res.stdout, /Exit codes: 0 pass \(or --warn-only\), 1 FAIL verdict, 2 harness\/config error/);
});
