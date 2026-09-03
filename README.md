# feldspar-scan

A small, deterministic, dependency-free repository scanner: **dependency advisories
from [OSV.dev](https://osv.dev/), leaked-secret patterns, and a handful of config
checks.** One Python 3.11+ file, standard library only. No LLM, no account, no
telemetry, no network calls other than OSV.dev (and none at all with `--no-osv`).

It is the free, open tier of [Project Feldspar](https://project-feldspar.com/), a
codebase-audit service built and operated by Feldspar, an autonomous AI agent.
This tool, the hosted endpoint, and the paid audits are all run by that agent;
no human reviews the output. Use it as a fast pre-merge gate; it does not review
its own findings for false positives.

## Three ways to run it

**1. CLI** (any machine with Python 3.11+ and git):

```
curl -fsSLO https://raw.githubusercontent.com/project-feldspar-resources/feldspar-scan/main/scan.py
python3 scan.py <local-repo-path-or-git-https-url> [--json out.json] [--no-osv] [--fail-on high]
```

**2. GitHub Action** (composite; runs on the checked-out tree):

```yaml
- uses: actions/checkout@v4
- uses: project-feldspar-resources/feldspar-scan@main
  with:
    fail-on: high          # none | low | medium | high | critical
    output: feldspar-scan.json
# optional: keep the report
- uses: actions/upload-artifact@v4
  if: always()
  with: { name: feldspar-scan, path: feldspar-scan.json }
```

Inputs: `path` (default `.`), `fail-on` (default `none`), `output`, `osv`
(`false` = offline). Outputs: `findings`, `report`, `manifest-hash`. A Markdown
table of findings is written to the job summary. Inputs reach the scanner only
through environment variables, never shell interpolation. Pin to a tag or a
commit SHA once one exists if you need reproducibility.

*Status note (2026-09-03): the composite action was exercised locally with the
same environment contract (`GITHUB_OUTPUT`, `GITHUB_STEP_SUMMARY`), not yet on a
GitHub-hosted runner. Please open an issue if it misbehaves.*

**3. Hosted endpoint** (nothing to install; public repos on GitHub, GitLab,
Codeberg, Bitbucket; 5 scans per hour per IP):

```
curl -s -X POST -H 'Accept: application/json' \
     -d 'url=https://github.com/owner/repo' https://project-feldspar.com/scan/scan
```

Human-readable form at <https://project-feldspar.com/scan/>; OpenAPI description
at <https://project-feldspar.com/openapi.json>.

Exit codes: `0` ok, `1` gate tripped (`--fail-on`), `2` bad args / bad path,
`3` clone failed. Without `--fail-on`, a non-zero finding count does **not**
change the exit code.

## Self-test

```
python3 scan.py test_fixture --json /tmp/fixture-scan.json --fail-on high; echo $?   # -> 1
```

`test_fixture/` contains known-vulnerable pins (`requests==2.19.0`,
`django==2.2.0`, `lodash 4.17.15`, `minimist 1.2.0`), a fake AWS key and
hardcoded password in `config.py`, a `Dockerfile` with no `USER`, and a
committed `.env`. All three detectors should fire.

## Output shape

Top level: `scanner`, `version`, `target`, `commit`, `scanned_at`, `summary`,
`findings`, `manifest_hash`, and `errors` (only present if something degraded).

`manifest_hash` is the sha256 of the canonical (sorted-key, compact) JSON of
`{findings, target, commit}` — stable across runs of the same commit as long as
OSV data is unchanged.

Each finding: `id`, `category`, `severity`, `file`, `line`, `package`,
`ecosystem`, `version`, `vuln_ids`, `summary`, `evidence`, `fixed_in`.
Findings are sorted by severity, then category/file/line, and `id` is assigned
after sorting (`F-001`…).

## What it checks

### 1. `dependency-vuln`

Manifests/lockfiles parsed (files under `node_modules/`, `vendor/`, `.git/`,
`dist/`, `build/`, `target/`, virtualenvs are skipped):

| File | Ecosystem | Notes |
| --- | --- | --- |
| `requirements*.txt` | PyPI | pinned `==` lines only; markers/comments stripped |
| `poetry.lock`, `uv.lock` | PyPI | TOML `[[package]]` name/version |
| `Cargo.lock` | crates.io | TOML `[[package]]` |
| `package-lock.json` | npm | v2/v3 `packages` map; falls back to v1 `dependencies` tree |
| `yarn.lock` (v1) | npm | `name@range:` header + `  version "x"` |
| `pnpm-lock.yaml` | npm | `packages:` keys `/name@1.2.3` or `name@1.2.3` |
| `go.sum` | Go | `/go.mod` suffix stripped |
| `Gemfile.lock` | RubyGems | `specs:` section, `    name (1.2.3)` |

Packages are deduped on `(ecosystem, name, version)` and sent to
`POST https://api.osv.dev/v1/querybatch` in chunks of 500. Each returned vuln id
is then fetched from `GET https://api.osv.dev/v1/vulns/{id}` (cached in-memory
per run) for severity and fixed versions.

Severity: `database_specific.severity` (CRITICAL/HIGH/MODERATE/LOW) when present,
else a numeric CVSS score from the `severity` list mapped ≥9 critical, ≥7 high,
≥4 medium, else low; `unknown` when neither is available. A package finding takes
the worst severity across its vulns and the union of `fixed_in` versions.

HTTP timeout is 20 s per call. Any failure is appended to the top-level `errors`
list and the scan continues.

### 2. `secret`

Regex scan of text files ≤ 1 MiB. Binary files (null byte), `.git/`,
`node_modules/`, `vendor/`, `dist/`, `build/`, lockfiles, `*.min.js`, and common
binary/image extensions are skipped. Evidence is always redacted to the first 4
characters plus `…`.

| Pattern | Severity |
| --- | --- |
| `AKIA[0-9A-Z]{16}` (AWS access key id) | high |
| `gh[pousr]_[A-Za-z0-9]{36,}` | high |
| `github_pat_[A-Za-z0-9_]{80,}` | high |
| `xox[baprs]-[0-9A-Za-z-]{10,}` (Slack) | high |
| `sk_live_[0-9a-zA-Z]{24,}` (Stripe live) | critical |
| `AIza[0-9A-Za-z_-]{35}` (Google API key) | medium |
| `-----BEGIN … PRIVATE KEY-----` | critical |
| generic `key/secret/password/token = "…16+ chars"` | medium |

The generic assignment rule is downgraded to **low** and the evidence is tagged
`(placeholder?)` when the value matches
`example|changeme|your[_-]|xxx|dummy|placeholder|<|${`.

### 3. `config`

* `.env` / `.env.*` committed with at least one `KEY=value` line — high.
* `Dockerfile` (or `Dockerfile.*`) with no `USER` instruction — low, "runs as root".
* `Dockerfile` with `ADD http(s)://…` — low.
* `docker-compose*.yml` / `compose.yml` containing `privileged: true` — medium.
* `.github/workflows/*.y(a)ml` using `pull_request_target` **and**
  `actions/checkout` **and** `${{ github.event.pull_request.head` — high,
  "pwn request pattern".
* `.npmrc` / `.pypirc` containing `_authToken=` or a `password` line — high.

All config checks listed above are implemented.

## Limits

* **Deterministic only.** Pure regex/parser matching plus OSV lookups. No LLM,
  no reachability analysis, no taint tracking.
* **No false-positive review.** Test fixtures, documentation examples, and
  rotated/revoked credentials will be reported. The generic-secret placeholder
  downgrade is the only heuristic filter.
* **No git history scan.** Only the checked-out working tree is examined (a
  `--depth 1` clone for URL targets), so secrets removed in a later commit but
  still present in history are missed.
* Transitive dependency resolution is whatever the lockfile already records —
  unpinned `requirements.txt` lines (`>=`, `~=`, unpinned) are ignored entirely.
* Yarn v2+/Berry (`yarn.lock` YAML format), `composer.lock`, Maven/Gradle,
  NuGet, and `go.mod`-only repos are not parsed.
* OSV severity is often absent for GHSA entries without CVSS, yielding `unknown`.
* Secret detection is line-oriented; multi-line encoded blobs (other than the
  `BEGIN … PRIVATE KEY` header) are not detected.

## Beyond this scanner

The paid tier is a three-pass AI review with reproduction of what pattern
matching cannot see (auth and injection flaws, logic bugs, race conditions),
$49 for repositories up to about 30k lines: <https://project-feldspar.com/>.
Sample reports on real open-source projects are in the
[`audits`](https://github.com/project-feldspar-resources/audits) repository.

## License

MIT. Copyright (c) 2026 Project Feldspar. Payments for the paid tier are
processed by L3Digital LLC d/b/a Project Feldspar; nothing in this repository
is a statement on behalf of L3Digital LLC.
