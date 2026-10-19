# repo-inject-guard

> **If this helps you, please give it a star** — it helps others find it. Thanks!

**A static scanner that protects coding agents from the repositories and issue trackers they read.**

Modern coding agents do not just *execute* code — they **read** your repository and **obey** what they find.
`CLAUDE.md`, `AGENTS.md`, `.cursorrules`, `.github/copilot-instructions.md`, `.cursor/rules/**`, `.claude/**`,
`.mcp.json`, `skills/**/SKILL.md` — every one of these files is parsed as instructions by at least one agent.
So is every GitHub issue body and PR comment the agent is asked to look at. A malicious repository (or a
malicious issue on *your* repository) is therefore a prompt-injection delivery mechanism with a filesystem
and a shell on the other end.

The 2026 incident wave made this concrete: **GitLost** shipped crafted GitHub Issues whose hidden-Unicode
payloads hijacked agents that read them; **FakeGit** lured agents into cloning attacker repositories;
**RoguePilot** pushed Copilot injections through review comments; the **Backslash** attack stole AWS and npm
credentials via a planted `AGENTS.md`; and the **Rules File Backdoor** showed that a single quiet edit to a
rules file persists across every future session. Vendors responded by hardening *their own* agents — GitHub
strips hidden characters for Copilot only; Claude Code ships no untrusted-repo quarantine. Nothing protects
the *operator* pointing an arbitrary agent at an arbitrary repository. The ~15 scanners that do exist are
zero-star markdown-only linters that ignore tracker text entirely.

repo-inject-guard fills that gap with three capabilities nobody else owns:

1. **Issues/PR bodies + comments via API, with author-trust context** — an instruction override posted by a
   first-time contributor fails the gate; the same text from the repo owner is downgraded to a warning
   (credential exfiltration excepted).
2. **Pre-fork certification** — run `certify` against a repository you are *about* to clone and get a
   SAFE / CAUTION / DO NOT verdict before an agent ever touches it.
3. **A per-agent manifest of auto-read surfaces** — you scan exactly the files each agent actually loads,
   per profile, instead of "all markdown files".

It completes the detection family: `mcp-test` probes MCP servers, `agent-pr-gate` verifies agent-authored
PRs, and **repo-inject-guard** scans the INPUT surface — the untrusted text your agent reads before it acts.

---

## Install

```bash
npm install -g repo-inject-guard     # or: npx repo-inject-guard <command>
```

Requires Node 20+. Single runtime dependency (`yaml`).

## Quickstart

```bash
# 1. Point an agent at an unknown repo? Certify it FIRST, before cloning:
repo-inject-guard certify /path/to/cloned-or-extracted-repo

# 2. Inside a repo you already work in:
repo-inject-guard scan .                       # full scan of agent auto-read surfaces

# 3. In CI, on every PR (reads GITHUB_EVENT_PATH, annotates the diff):
repo-inject-guard gate --format github

# 4. What does each agent auto-read, exactly?
repo-inject-guard surfaces
```

### The pre-fork certify workflow

This is the mode nobody else ships, and the cheapest defense you will ever run:

```bash
# you found an interesting repo and want an agent to work on it
git clone --depth 1 https://github.com/someone/unknown-repo /tmp/candidate
repo-inject-guard certify /tmp/candidate
#   VERDICT: DO NOT POINT AN AGENT AT THIS REPOSITORY   -> delete it, done.
#   VERDICT: CAUTION — ...                              -> human reviews the findings.
#   VERDICT: SAFE TO POINT AN AGENT AT THIS REPOSITORY  -> proceed (still not a proof; see below)
```

`certify` is deliberately file-only (a pre-fork machine has no reason to hold tracker credentials); its
not-inspected section tells you to run `gate --repo owner/name --issue N` for tracker text. It always prints
**what was and was NOT inspected** — because *not-inspected ≠ clean* is the load-bearing honesty of this tool.

## Commands

| Command | What it does | Exit codes |
| --- | --- | --- |
| `scan [path]` | Walk the agent auto-read surfaces of a local repo and apply all rules | 0 pass / 1 FAIL / 2 error |
| `gate [path]` | CI mode: only files changed in the PR (diff via `GITHUB_EVENT_PATH` + `gh api pulls/files`, or `--diff file.patch` for offline/fixture runs) intersected with the surfaces, **plus** issue/PR body & comment scanning | same |
| `certify [path]` | Full scan + SAFE / CAUTION / DO NOT verdict + explicit inspected/not-inspected report | same |
| `surfaces` | List what each agent profile auto-reads (self-documenting) | 0 / 2 |

Formats for `scan`/`gate`/`certify`: `--format text` (default), `--format github` (workflow annotations),
`--format json`, `--format sarif` (SARIF 2.1.0 with rules + located results). `--warn-only` reports failures
but exits 0.

Gate inputs (any one): `--diff <file.patch>` (offline fixture mode), GitHub Actions environment
(`GITHUB_EVENT_PATH` with a `pull_request` event → changed files via `gh api`, `issues`/`issue_comment`/
`pull_request_review*` events → tracker text), or `--repo owner/name --issue N` / `--pr N` (local `gh` CLI).
**No token available? Events are skipped with an explicit notice — never silently treated as clean.**

## Agent surface profiles

| Profile | Auto-read surfaces |
| --- | --- |
| `claude-code` | `CLAUDE.md`, `AGENTS.md`, `.claude/**`, `.mcp.json`, `skills/**/SKILL.md` |
| `codex` | `AGENTS.md`, `.codex/**` |
| `cursor` | `.cursor/rules/**`, `.cursorrules`, `AGENTS.md` |
| `copilot` | `.github/copilot-instructions.md`, `.github/instructions/*.md`, `AGENTS.md` |
| `gemini` | `GEMINI.md`, `AGENTS.md` |
| `opencode` | `AGENTS.md`, `.opencode/**` |
| `all` (default) | union of the above |

Bare filenames match at any depth (agents discover nested copies); directory globs are anchored at the repo
root; matching is case-insensitive because `agents.md`-vs-`AGENTS.md` is a free obfuscation.

## Detection rules

| Rule | Severity | Fires on |
| --- | --- | --- |
| `INSTR_OVERRIDE` | high | "ignore (all) previous/prior/above instructions", "disregard your system instructions" |
| `SYSTEM_PROMPT_EXFIL` | medium | "reveal/print/show (me) (your) system prompt" |
| `CREDS_EXFIL` | high | actual secret data flow: output/transfer verb on credential material, an env-var VALUE echoed, a broad env dump (`printenv`, `env \| curl`), or curl/wget POST paired with secret references in the same file. Prose merely mentioning "env vars" does not fire. |
| `ENV_PROBE` | medium | scoped presence probe — `env \| grep NAME`, `printenv NAME`, `${VAR:+SET}`: prints whether one named variable is set. A debugging idiom, not a dump: advisory for trusted content, gating for untrusted authors. |
| `HIDDEN_UNICODE` | high | zero-width (U+200B–200D, U+2060, U+FEFF) and bidi (U+202A–202E, U+2066–2069) characters — reported **always**, with file, line and codepoint, never only alongside other signals. A genuine leading UTF-8 BOM is tolerated. |
| `AGENT_DIRECTIVE` | low | second-person commands a normal document rarely contains ("you must run…", "always/never/before every/from now on + use/run/execute/call/send/write/delete", "note to the AI/agent/reviewer/CI") — requires **2+ distinct directive lines** in one file to fire |
| `RULES_BACKDOOR` | high | in rules/instruction files: "do not tell/inform/show the user", "hide this from", "secretly", "without the user's knowledge" |
| `RESOURCE_LURE` | medium | base64 blobs >120 chars in markdown; mixed-script homoglyph URL hosts on agent surfaces (e.g. `gіthub.com` with a Cyrillic і) |

### Verdicts and the author-trust model

| Severity | File scan (neutral) | Untrusted author (NONE, FIRST_TIME_CONTRIBUTOR) | Trusted author (OWNER, MEMBER) |
| --- | --- | --- | --- |
| high | FAIL | FAIL | WARN * |
| medium | WARN | FAIL | WARN |
| low | WARN | WARN | WARN |

\* **CREDS_EXFIL is never downgraded** — a compromised maintainer account exfiltrating credentials is a real
attack path, so credential exfiltration fails regardless of who posted it. `CONTRIBUTOR`/`COLLABORATOR`
(middle tiers) behave like neutral.

### The precision philosophy

**A false positive that blocks a legitimate contribution costs more than a missed exotic payload.** So every
rule is scoped (instruction-file rules do not run on JSON config; directive rules only on markdown-like
text), the noisiest rule needs corroboration (2+ directive lines), a genuine BOM is not "hidden Unicode", and
`README.md` advice like *"always run the full test suite before opening a PR"* never fires — it is not on an
agent surface and lacks second-person-to-agent framing.

**Not-inspected ≠ clean.** A passing scan means: *the files you pointed us at, parsed by these signatures,
contain nothing we recognize.* It does not mean the repo is safe. Files outside the surfaces, tracker text
you did not connect us to, binaries, oversized files, and novel obfuscations are all outside the claim — and
the tool says so, in every output format, every time.

## Configuration (`rig.yaml`)

```yaml
# rig.yaml — read from your working directory (or --config), NEVER from the scanned
# repository: a hostile repo must not be able to opt its own poison out of the scan.
profiles:        # default: [all]
  - claude-code
  - cursor
extraPaths:      # additional files YOUR agent auto-reads (e.g. a custom README agent doc)
  - docs/AGENT-NOTES.md
ignore:          # paths to exclude from scanning (use sparingly)
  - .claude/commands/internal.md
```

`rig.example.yaml` ships in this repository as a starting point.

## CI usage

```yaml
# .github/workflows/gate.yml
name: agent-input-gate
on: [pull_request, issues, issue_comment]
permissions:
  contents: read
  pull-requests: read
jobs:
  gate:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0
      - uses: actions/setup-node@v4
        with:
          node-version: 22
      - run: npm i -g repo-inject-guard
      - run: repo-inject-guard gate --format github
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
```

On `pull_request`, changed files come from `gh api pulls/{n}/files` (with GITHUB_TOKEN) and only
surface-intersecting files are scanned; on `issues`/`issue_comment`, the body/comments are scanned with
author-trust context; if `gh` is unavailable the gate falls back to a **full** surface scan — broader, never
narrower — and says so.

## Honest kill risks

This project can die, and you should know how before you adopt it:

- **Scope land-grab.** If Snyk/NVIDIA-class vendors fold "repository prompt-injection scanning" into
  existing security suites, the standalone wedge collapses. Our defense is the per-agent surface manifest
  and tracker-author-trust model — the parts a generic SAST vendor is structurally slow to copy.
- **GitHub native scanning.** GitHub already strips hidden characters for Copilot; a native
  "injection-safe repo" check would absorb the largest distribution channel. We would remain the
  multi-vendor, self-hostable option.
- **Agent-side sandboxing.** If agents shrink their blast radius (no network, no credentials, quarantined
  untrusted-repo mode), injection becomes noise and nobody gates it. Mitigation: we also catch *data*
  exfiltration and tracker attacks that sandboxing alone does not neutralize — but this is the deepest risk.
- **Signature evasion.** Deterministic regexes miss novel phrasing; an arms race we cannot win alone. The
  rules are deliberately conservative and every finding cites evidence so humans can adjudicate.

## Development

```bash
npm install
npm run build     # tsc -> dist/ (ESM)
npm test          # test/run-tests.mjs enumerates dist/test/*.test.js and execs node --test
                  # with an explicit file list (portable: no glob args, works on Node 20+, Windows-safe)
```

Tests are fixture-driven and fully offline (`test/fixtures/`: a poisoned repo with real zero-width and
homoglyph payloads, a clean repo, GitHub event payloads, PR diff patches). All parsing is CRLF-tolerant;
`.gitattributes` enforces LF in git. MIT — see LICENSE, © 2026 repo-inject-guard contributors.
