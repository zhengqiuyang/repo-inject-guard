/**
 * Agent surface profiles: the files and directories each coding agent
 * AUTO-READS when it works inside a repository. These files are parsed as
 * instructions by the agent, which makes them the highest-value place to
 * plant prompt-injection payloads.
 */
import { pathMatchesGlob } from './util.js';

export interface SurfaceProfile {
  name: string;
  description: string;
  patterns: string[];
}

export const AGENT_PROFILES: SurfaceProfile[] = [
  {
    name: 'claude-code',
    description: 'Anthropic Claude Code',
    patterns: ['CLAUDE.md', 'AGENTS.md', '.claude/**', '.mcp.json', 'skills/**/SKILL.md'],
  },
  {
    name: 'codex',
    description: 'OpenAI Codex CLI',
    patterns: ['AGENTS.md', '.codex/**'],
  },
  {
    name: 'cursor',
    description: 'Cursor IDE / agent',
    patterns: ['.cursor/rules/**', '.cursorrules', 'AGENTS.md'],
  },
  {
    name: 'copilot',
    description: 'GitHub Copilot coding agent',
    patterns: ['.github/copilot-instructions.md', '.github/instructions/*.md', 'AGENTS.md'],
  },
  {
    name: 'gemini',
    description: 'Google Gemini CLI',
    patterns: ['GEMINI.md', 'AGENTS.md'],
  },
  {
    name: 'opencode',
    description: 'OpenCode',
    patterns: ['AGENTS.md', '.opencode/**'],
  },
];

function dedupe(patterns: string[]): string[] {
  const out: string[] = [];
  const lower = new Set<string>();
  for (const p of patterns) {
    const k = p.toLowerCase();
    if (!lower.has(k)) {
      lower.add(k);
      out.push(p);
    }
  }
  return out;
}

export const ALL_PROFILE: SurfaceProfile = {
  name: 'all',
  description: 'Union of every known agent auto-read surface',
  patterns: dedupe(AGENT_PROFILES.flatMap((p) => p.patterns)),
};

export function findProfile(name: string): SurfaceProfile | undefined {
  if (name === ALL_PROFILE.name) return ALL_PROFILE;
  return AGENT_PROFILES.find((p) => p.name === name);
}

export function profileNames(): string[] {
  return [...AGENT_PROFILES.map((p) => p.name), ALL_PROFILE.name];
}

export interface ResolvedProfiles {
  profiles: SurfaceProfile[];
  errors: string[];
}

export function resolveProfiles(names: string[]): ResolvedProfiles {
  const profiles: SurfaceProfile[] = [];
  const errors: string[] = [];
  for (const name of names) {
    const p = findProfile(name);
    if (p) {
      if (!profiles.includes(p)) profiles.push(p);
    } else {
      errors.push(name);
    }
  }
  if (profiles.length === 0 && errors.length === 0) {
    profiles.push(ALL_PROFILE);
  }
  return { profiles, errors };
}

export interface SurfaceSet {
  profileNames: string[];
  /** pattern -> profiles that auto-read it ('all' when the union profile is selected) */
  globOwners: { glob: string; profiles: string[] }[];
  extraGlobs: string[];
}

export function buildSurfaceSet(profileNames: string[], extraGlobs: string[] = []): SurfaceSet {
  const { profiles } = resolveProfiles(profileNames.length > 0 ? profileNames : ['all']);
  const owners = new Map<string, string[]>();
  for (const profile of profiles) {
    for (const glob of profile.patterns) {
      const list = owners.get(glob.toLowerCase()) ?? [];
      // If the union profile is active, attribute the glob to 'all' only.
      if (profile === ALL_PROFILE) {
        list.length = 0;
        if (!list.includes('all')) list.push('all');
      } else if (!list.includes('all') && !list.includes(profile.name)) {
        list.push(profile.name);
      }
      owners.set(glob.toLowerCase(), list);
    }
  }
  const globOwners = [...owners.entries()].map(([lower, profs]) => {
    const original = profiles
      .flatMap((p) => p.patterns)
      .find((p) => p.toLowerCase() === lower);
    return { glob: original ?? lower, profiles: profs };
  });
  return {
    profileNames: profiles.map((p) => p.name),
    globOwners,
    extraGlobs: [...extraGlobs],
  };
}

/**
 * Which profiles auto-read this repo-relative path? Empty array means the
 * file is off-surface. Extra globs from rig.yaml report as 'custom'.
 */
export function whichProfilesMatch(relPosix: string, surface: SurfaceSet): string[] {
  const out: string[] = [];
  for (const { glob, profiles } of surface.globOwners) {
    if (pathMatchesGlob(relPosix, glob)) {
      for (const p of profiles) if (!out.includes(p)) out.push(p);
    }
  }
  if (surface.extraGlobs.some((g) => pathMatchesGlob(relPosix, g))) {
    if (!out.includes('custom')) out.push('custom');
  }
  return out;
}

export function isOnSurface(relPosix: string, surface: SurfaceSet): boolean {
  return whichProfilesMatch(relPosix, surface).length > 0;
}

/**
 * Treat a path as markdown-like for rule scoping purposes:
 * .md/.markdown/.mdx files, plus extensionless dotfiles such as .cursorrules.
 * JSON config files like .mcp.json are NOT markdown-like.
 */
export function isMarkdownLikePath(relPosix: string): boolean {
  const name = relPosix.slice(relPosix.lastIndexOf('/') + 1);
  if (/\.(md|markdown|mdx)$/i.test(name)) return true;
  const dot = name.lastIndexOf('.');
  if (dot <= 0) return true; // no extension, or a bare dotfile like ".cursorrules"
  return false;
}
