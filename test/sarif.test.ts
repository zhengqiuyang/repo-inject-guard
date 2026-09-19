import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const cli = fileURLToPath(new URL('../src/cli.js', import.meta.url));
const fixture = (p: string): string =>
  fileURLToPath(new URL(`../../test/fixtures/${p}`, import.meta.url));

function sarifFor(args: string[]): any {
  const env: Record<string, string> = {};
  for (const [k, v] of Object.entries(process.env)) {
    if (v !== undefined) env[k] = v;
  }
  env['GITHUB_EVENT_PATH'] = '';
  env['GITHUB_EVENT_NAME'] = '';
  const res = spawnSync(process.execPath, [cli, ...args], {
    encoding: 'utf8',
    env,
  });
  assert.equal(res.status, 1, 'poisoned fixture must fail first');
  return JSON.parse((res.stdout as string).trim());
}

test('SARIF: version and schema are declared', () => {
  const sarif = sarifFor(['gate', '--diff', fixture('diffs/poisoned.patch'), '--format', 'sarif']);
  assert.equal(sarif.version, '2.1.0');
  assert.equal(typeof sarif.$schema, 'string');
});

test('SARIF: tool driver names the tool and registers all 7 rules', () => {
  const sarif = sarifFor(['gate', '--diff', fixture('diffs/poisoned.patch'), '--format', 'sarif']);
  const driver = sarif.runs[0].tool.driver;
  assert.equal(driver.name, 'repo-inject-guard');
  assert.equal(driver.rules.length, 7);
  for (const rule of driver.rules) {
    assert.ok(rule.id, 'rule id required');
    assert.ok(rule.shortDescription.text);
    assert.ok(['high', 'medium', 'low'].includes(rule.properties.severity));
  }
  const expected = [
    'AGENT_DIRECTIVE',
    'CREDS_EXFIL',
    'HIDDEN_UNICODE',
    'INSTR_OVERRIDE',
    'RESOURCE_LURE',
    'RULES_BACKDOOR',
    'SYSTEM_PROMPT_EXFIL',
  ].sort();
  assert.deepEqual(
    driver.rules.map((r: any) => r.id).sort(),
    expected
  );
});

test('SARIF: results carry ruleId, level, message and file locations', () => {
  const sarif = sarifFor(['gate', '--diff', fixture('diffs/poisoned.patch'), '--format', 'sarif']);
  const results = sarif.runs[0].results;
  assert.ok(results.length >= 3);
  for (const result of results) {
    assert.ok(result.ruleId);
    assert.ok(['error', 'warning', 'note'].includes(result.level));
    assert.ok(result.message.text.length > 0);
    const loc = result.locations[0].physicalLocation;
    assert.ok(loc.artifactLocation.uri);
    assert.equal(loc.artifactLocation.uri, '.cursorrules');
    assert.equal(typeof loc.region.startLine, 'number');
    assert.ok(loc.region.startLine >= 1);
  }
  assert.ok(results.some((r: any) => r.ruleId === 'INSTR_OVERRIDE' && r.level === 'error'));
});

test('SARIF: file findings use relative repo URIs with regions', () => {
  const sarif = sarifFor(['scan', fixture('poisoned-repo'), '--format', 'sarif']);
  assert.equal(sarif.runs[0].results.length > 0, true);
  for (const result of sarif.runs[0].results) {
    const loc = result.locations[0].physicalLocation;
    const uri: string = loc.artifactLocation.uri;
    // relative repo paths for file findings; no absolute or scheme URIs
    assert.ok(!/^[a-z]+:/.test(uri) && !uri.startsWith('/'), `uri must be relative: ${uri}`);
    assert.equal(typeof loc.region?.startLine, 'number', 'file findings carry a region');
  }
});
