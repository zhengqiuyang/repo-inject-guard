/**
 * rig.yaml configuration. IMPORTANT: the config is read from the OPERATOR's
 * side (--config flag or the current working directory), never from the
 * repository being scanned — a hostile repo must not be able to ship a
 * rig.yaml that opts its own poison out of the scan.
 */
import { readFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { parse as parseYaml } from 'yaml';
import { errMsg } from './util.js';

export interface RigConfig {
  profiles?: string[];
  extraPaths?: string[];
  ignore?: string[];
}

export interface ConfigLoadResult {
  config: RigConfig | null;
  sourcePath?: string;
  notices: string[];
  error?: string;
}

const KNOWN_KEYS = ['profiles', 'extraPaths', 'ignore'];

function stringArray(value: unknown, key: string, source: string): string[] {
  if (value === undefined || value === null) return [];
  if (!Array.isArray(value) || value.some((x) => typeof x !== 'string')) {
    throw new Error(`${source}: "${key}" must be a list of strings`);
  }
  return value as string[];
}

export async function loadRigConfig(explicitPath?: string): Promise<ConfigLoadResult> {
  const candidates = explicitPath ? [explicitPath] : ['rig.yaml', 'rig.yml'];
  for (const cand of candidates) {
    const p = resolve(cand);
    let text: string;
    try {
      text = await readFile(p, 'utf8');
    } catch {
      continue; // no config at this candidate — fine, config is optional
    }
    let doc: unknown;
    try {
      doc = parseYaml(text);
    } catch (e) {
      return { config: null, notices: [], error: `${p}: invalid YAML (${errMsg(e)})` };
    }
    if (doc == null) {
      return { config: {}, sourcePath: p, notices: [`${p}: empty config, using defaults`] };
    }
    if (typeof doc !== 'object' || Array.isArray(doc)) {
      return { config: null, notices: [], error: `${p}: top level must be a mapping` };
    }
    const raw = doc as Record<string, unknown>;
    const notices: string[] = [];
    for (const key of Object.keys(raw)) {
      if (!KNOWN_KEYS.includes(key)) notices.push(`${p}: ignoring unknown key "${key}"`);
    }
    let config: RigConfig;
    try {
      const profiles = stringArray(raw['profiles'], 'profiles', p);
      const extraPaths = stringArray(raw['extraPaths'], 'extraPaths', p);
      const ignore = stringArray(raw['ignore'], 'ignore', p);
      config = { profiles, extraPaths, ignore };
      notices.unshift(
        `${p}: config loaded (profiles: ${profiles.join(', ') || 'all'}; extra paths: ${extraPaths.length}; ignore: ${ignore.length}). ` +
          'Config is honored from the operator side only — a rig.yaml inside the scanned repo is never auto-loaded.'
      );
    } catch (e) {
      return { config: null, notices: [], error: errMsg(e) };
    }
    return { config, sourcePath: p, notices };
  }
  return { config: null, notices: [] };
}
