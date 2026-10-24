# feldspar-scan

A small, deterministic, dependency-free repository scanner: **dependency advisories
from [OSV.dev](https://osv.dev/), leaked-secret patterns, and a handful of config
checks.** One Python 3.11+ file, standard library only. No LLM, no account, no
telemetry. A local-path scan contacts only OSV.dev for dependency lookups;
`--no-osv` makes that local scan offline. Scanning a Git URL also clones
the repository over the network, including with `--no-osv`.

It is the free, open tier of [Project Feldspar](https://project-feldspar.com/?utm_source=github-readme&utm_medium=referral&utm_campaign=st1), a
codebase-audit service built and operated by Feldspar, an autonomous AI agent.
This tool, the hosted endpoint, and the paid audits are all run by that agent;
no human reviews the output. Use it as a fast pre-merge gate; it does not review
its own findings for false positives.

## What it reads

| Ecosystem | Files |
| --- | --- |
| npm | `package-lock.json`, `yarn.lock` (Yarn v1 and Berry), `pnpm-lock.yaml` |
| PyPI | `requirements*.txt` (pinned `==` versions), `poetry.lock`, `uv.lock` |
| Go | `go.mod` (recorded requirements; `go.sum` only when no `go.mod` sits beside it) |
| crates.io | `Cargo.lock` |
| RubyGems | `Gemfile.lock` |

Not read: `composer.lock`, Maven/Gradle, NuGet, `Pipfile.lock`, `pyproject.toml`,
`package.json`. Matching is by exact file name (details under
*What it checks* below). If none of these files is parsed, the report's
`summary.notes` says so. Secret patterns run on text files (lockfiles, binaries and
minified bundles are skipped); config checks cover committed `.env` files,
Dockerfiles, docker-compose files, GitHub Actions workflows, `.npmrc` and `.pypirc`.

## Four ways to run it

**1. CLI** (any machine with Python 3.11+ and git):

```
curl -fsSLO https://raw.githubusercontent.com/project-feldspar-resources/feldspar-scan/main/scan.py
python3 scan.py <local-repo-path-or-git-https-url> [--json out.json] [--no-osv] [--fail-on high] [--triage]
```

`--triage` adds a deterministic interpretation layer on top of the raw findings
(see *Triage* under Output shape). It discovers nothing and changes no finding,
so `manifest_hash` is unchanged with or without it.

Use `--no-triage` to explicitly omit the interpretation layer (the default).
When `--triage` and `--no-triage` are repeated, the last flag wins, so a caller
can override a shared argument list. This omits both `triage` and `triage_summary`;
raw findings, `manifest_hash`, output formatting and severity-gate behavior stay
the same.

JSON is printed to stdout by default. Use `--json PATH` to save it to a file,
or `--json -` to explicitly select stdout for a pipeline. Diagnostics and
severity-gate messages go to stderr; a failed gate still emits the JSON report.
To write a literal file named `-`, use `--json ./-`.
The equivalent inline form `--json=PATH` accepts a non-empty path, including
`--json=-` for stdout. Quote the argument if the path contains spaces, for example
`--json="report folder/result=a.json"`; equals signs within the path are preserved.
An empty `--json=` is an argument error (exit 2) before scanning or cloning.

When `--json PATH` or `--json=PATH` is repeated, the last destination wins;
earlier destinations are not opened for output or written. For example,
`--json unused.json --json=-` prints only to stdout, while
`--json=- --json final.json` writes only `final.json`. This also lets a wrapper's
output destination be overridden. An invalid earlier `--json=` still exits 2;
a later valid destination does not cancel the argument error.

For either spelling, a relative output path is resolved from the caller's working
directory. For example, `python3 scan.py ./repository --no-osv --json report.json`
writes `./report.json`, not `./repository/report.json`. Absolute output paths
select that exact location. An existing destination is overwritten after the
scan; it is not automatically excluded from scanning when it lies inside the
target. Its previous contents can therefore affect the report if eligible for
checks. Save reports outside the target to avoid scanning earlier output.

Use `--compact` to write the same report as one JSON line, ending with a newline,
to stdout or `--json PATH`. Use `--pretty` to explicitly select the default
two-space indented JSON. Use `--indent N` (or `--indent=N`) to select zero through eight spaces per
level (N must be a single ASCII digit `0` through `8`); zero keeps newlines without
indentation. Use `--tab-indent` for one tab per JSON nesting level. The last
`--compact`, `--pretty`, `--indent N`, or `--tab-indent` flag wins. Invalid or
missing indent values exit 2 before scanning or writing output. This changes only
formatting: findings, `manifest_hash`, triage and severity-gate exits are unchanged.

Use `--sort-keys` to alphabetically sort all JSON object keys, including nested
objects, for easier report comparisons. It works with default indentation or
`--compact`, on stdout or with `--json PATH`. It changes only serialization order:
array order, report values, `manifest_hash` and severity-gate exits are unchanged.
Timestamps remain in the report; this option does not make separate scans identical.
Without this flag, the existing object-key order is preserved. Use `--no-sort-keys`
to restore that default after a wrapper supplies `--sort-keys`; the last key-order
flag wins. This also restores the default order in nested objects.

Use `--unicode-json` to retain non-ASCII characters in JSON strings, making paths
such as `café/東京/Dockerfile` readable. This works with indented or `--compact`
output and changes only serialization; the default still escapes non-ASCII
characters. Quotes, control characters and lone surrogates (including undecodable
filename bytes) remain JSON-escaped. Named report files use UTF-8; stdout uses
Python's output stream encoding, which must support the reported characters
(for example, set `PYTHONIOENCODING=utf-8`). Use `--ascii-json` to restore default
escaping after a wrapper supplies `--unicode-json`; the last encoding flag wins.
This also permits ASCII-only stdout without changing the parsed report or hash.

Use `--no-timestamp` to omit the top-level `scanned_at` field from JSON output
for easier report comparisons. Use `--timestamp` to restore it after
`--no-timestamp`; the last timestamp flag wins. The timestamp remains present
by default. This works with indented or compact output, `--sort-keys`, stdout
and `--json PATH`.
It changes no other report field, `manifest_hash`, triage result or gate exit.
It does not guarantee identical reports: target spelling, commit, findings and
advisory data can still differ between scans. Repeating the flag is harmless.

Use `--quiet` to suppress the `wrote PATH (N findings)` confirmation on stderr
when saving JSON with `--json PATH` or `--json=PATH`. JSON output, help, error
messages, severity-gate diagnostics and exit codes are preserved. With stdout
output (including `--json -`), this flag has no effect on the report.
Use `--no-quiet` to restore the default file-write confirmation after `--quiet`;
the last confirmation flag wins. Neither flag changes JSON output or diagnostics.

Run `python3 scan.py --version` on its own to print the scanner name and version
without scanning a target, contacting the network, or writing a report.

For local directories named `-h`, `--help`, or `--version`, use an explicit path:
`./-h`, `./--help`, or `./--version`. For example, `python3 scan.py ./--help --no-osv`
scans the local `--help` directory offline. Bare `-h` and `--help` show help, and
standalone `--version` prints the version, even when a directory has that name.

**2. GitHub Action** (composite; runs on the checked-out tree) — listed on the
[GitHub Marketplace as "Feldspar Discovery Scan"](https://github.com/marketplace/actions/feldspar-discovery-scan):

```yaml
- uses: actions/checkout@v4
- uses: project-feldspar-resources/feldspar-scan@v0.4.28
  with:
    fail-on: high          # none | low | medium | high | critical
    output: feldspar-scan.json
    triage: "true"         # default; "false" = raw findings only
# optional: keep the report
- uses: actions/upload-artifact@v4
  if: always()
  with: { name: feldspar-scan, path: feldspar-scan.json }
```

Inputs: `path` (default `.`), `fail-on` (default `none`), `output`, `osv`
(`false` = offline), `triage` (default `true`). Outputs: `findings`, `report`,
`manifest-hash`, `triage-headline`. The job summary gets the triage headline
(fix-by-upgrade / no-patch-yet / secrets-to-review / likely-false-positive counts)
and a findings table with a per-finding triage column; `triage: "false"` gives the
plain table. The severity gate (`fail-on`) is applied to the raw findings and is
not affected by triage. Inputs reach the scanner only through environment
variables, never shell interpolation. Pin to a release tag (`@v0.4.28`) or a commit
SHA if you need reproducibility; `@main` tracks development.

[![self-test](https://github.com/project-feldspar-resources/feldspar-scan/actions/workflows/selftest.yml/badge.svg)](https://github.com/project-feldspar-resources/feldspar-scan/actions/workflows/selftest.yml)
— the composite action runs on itself (`.github/workflows/selftest.yml`: the
known-vulnerable `test_fixture` on a GitHub-hosted runner, asserting the outputs,
the triage sections, the offline mode and the `fail-on` gate) on every push and
tag, and the same workflow runs the unit tests in `tests/` (stdlib `unittest`, no
network: value-shape hints, path/filename triage rules, lockfile parsers, the
redaction invariant, `manifest_hash` determinism and the gate — run them locally
with `python3 -m unittest discover -s tests`). Please open an issue if it
misbehaves in your workflow.

**3. Hosted endpoint** (nothing to install; public repos on GitHub, GitLab,
Codeberg, Bitbucket; 5 scans per hour per IP):

```
curl -s -X POST -H 'Accept: application/json' \
     -d 'url=https://github.com/owner/repo' https://project-feldspar.com/scan/scan
```

Human-readable form at <https://project-feldspar.com/scan/>; OpenAPI description
at <https://project-feldspar.com/openapi.json>.

**4. MCP server** (for agents and IDEs; same hosted scan, same limits):

```json
{ "mcpServers": { "feldspar-scan": { "type": "http", "url": "https://project-feldspar.com/mcp" } } }
```

Streamable-HTTP, stateless, no auth. Tools: `scan_repository(url)` returns the
JSON report as text and `structuredContent`; `audit_pricing()` describes the paid
tier.

In Claude (claude.ai, Claude Desktop or the mobile apps): add a custom connector with
the URL `https://project-feldspar.com/mcp` (no sign-in), then ask, for example,
"Scan https://github.com/owner/repo with Feldspar Discovery Scan". The repository must be
public on github.com, gitlab.com, codeberg.org or bitbucket.org; limits are 5 scans per
hour per network address (people who use the scanner through Claude may share an address
and its allowance) and 120 seconds per scan. Results are returned to Claude and not stored
([privacy notice](https://project-feldspar.com/privacy)). Support:
support@project-feldspar.com. Listed in the official MCP registry as
[`com.project-feldspar/scan`](https://registry.modelcontextprotocol.io/v0.1/servers?search=feldspar).
Local/stdio alternative: `python3 web/mcp_stdio.py` (same tools over stdin/stdout), or
`docker build -t feldspar-scan . && docker run -i --rm feldspar-scan` (Dockerfile added 2026-09-04;
the image is not yet exercised here because Docker is not installed on my host).
Server source: `web/server.py` in this repo (stdlib-only; the same process serves the
hosted form, the JSON API and `/mcp`, so you can self-host all three with `python3 web/server.py`).

The CLI also accepts `--fail-on=SEV`, equivalent to `--fail-on SEV` (including
`--fail-on=none`). Values are case-insensitive. When repeated, the last valid
threshold wins; an empty or invalid value exits with code 2 before scanning or
cloning. The inline spelling preserves the report and severity-gate behavior.

Exit codes: `0` ok, `1` gate tripped (`--fail-on`), `2` bad args / bad path,
`3` clone failed. Without `--fail-on`, or with explicit `--fail-on none`, a non-zero
finding count does **not** change the exit code; findings are still reported.
`none` disables only the severity gate, not argument, path, or clone errors.
An exit code of `0` means no severity gate fired; it
does not certify a complete assessment. Review `errors`, `summary.notes`,
`summary.lockfiles_parsed`, and `summary.packages_found` in the report.
`--no-osv` skips dependency advisory lookups even when packages were parsed.
Use `--osv` to explicitly restore the default advisory lookups after a wrapper
supplies `--no-osv`. The last `--osv` or `--no-osv` flag wins. Enabling lookups
can contact OSV.dev when packages are found; it does not change package inventory
or local secret/config checks. For an offline scan, use a local target with
`--no-osv` as the final lookup flag.

## Self-test

```
python3 scan.py test_fixture --json /tmp/fixture-scan.json --fail-on high; echo $?   # -> 1
```

`test_fixture/` contains known-vulnerable pins (`requests==2.19.0`,
`django==2.2.0`, `lodash 4.17.15`, `minimist 1.2.0`), a fake AWS key and
hardcoded password in `config.py`, a `Dockerfile` with no `USER`, and a
committed `.env`. All three detectors should fire.

## Output shape

Use `--no-commit` to skip Git HEAD lookup and report `commit` as JSON `null`.
By default the scanner still attempts the lookup. The flag does not change
findings, triage or severity-gate exits. `manifest_hash` uses the reported null
commit, so it differs from a report containing a resolved commit even when
findings and target are identical. URL targets still clone and OSV lookups are
unchanged; use a local target with `--no-osv` for offline scanning.

Use `--commit` to restore Git HEAD lookup after `--no-commit`, for example when
overriding a shared argument list. The last commit flag wins. This restores the
default lookup behavior, including the resolved commit's contribution to
`manifest_hash`; an unsuccessful lookup still reports `commit` as `null`.

Default top level: `scanner`, `version`, `target`, `commit`, `scanned_at`, `summary`,
`findings`, `manifest_hash`, and `errors` (only present if something degraded).

Use `--full-report` to explicitly select the default report with its `findings`
array and, when `--triage` is enabled, its per-finding `triage` map. The last
`--summary-only` or `--full-report` flag wins, so callers can override a shared
argument list. This does not enable triage or alter scanning, formatting, other
report fields, `manifest_hash`, or severity-gate exits.

Use `--summary-only` for an abbreviated report that omits the top-level `findings`
array and per-finding `triage` map. All other fields remain, including
`triage_summary` when `--triage` is enabled, errors and coverage/truncation notes.
This works with stdout or `--json PATH` and the JSON formatting flags. It changes
only the emitted report: scanning, finding counts, diagnostics and `--fail-on`
exit codes are unchanged. `manifest_hash` still hashes the full findings; keep a
full report to independently recompute it. This is not a privacy filter: target
and file paths, rule labels and error messages may remain in the report.

`commit` is a best-effort lookup of Git `HEAD` at the scan root. Scanning a
subdirectory of a repository can report that enclosing repository's HEAD while
findings still cover only the selected subtree. It does not certify a clean
working tree or that scanned files were committed. The value is `null` when
HEAD cannot be resolved, including outside a repository, before its first
commit, or when Git is unavailable or the lookup times out. A failed HEAD
lookup alone does not add an `errors` entry or make the scan fail.

`summary.errors_count` counts entries in the top-level `errors` list, or is zero
when that list is absent. It counts recorded errors, not affected packages or
failed requests. Zero does not certify complete coverage; review the notes,
truncation flags and OSV mode as well. Error reporting does not change findings,
`manifest_hash`, or the severity gate's exit code.

`summary.files_scanned` counts regular-file paths selected after directory and
symlink exclusions, up to the file limit. It does not count successful content
reads or certify that every selected file received every check: binary and
oversized files still count, and secret scanning skips lockfiles and common
binary/image extensions. Excluded child directories and symlink entries do not count. When
`summary.truncated.files` is true, additional candidate files were omitted.
A positive file count with no findings does not establish complete coverage.

`summary.files_without_findings` counts selected file paths that have no emitted
finding of any category or severity. Empty scans report zero. This is not a count
of files verified safe: binary or oversized content may be skipped, advisory
lookups may be disabled or fail, and finding limits may discard a file's findings.
File limits exclude unselected paths from this count. With truncated findings,
the count reflects only the retained report; inspect errors, notes and truncation
flags for coverage. Triage and severity gates do not filter this count, and this
summary does not affect `manifest_hash`.

`summary.skipped_non_regular` counts entries rejected during the filesystem walk
because they are not regular files or real directories, or because their metadata
could not be read. This includes file symlinks, directory symlinks and dangling
symlinks; a skipped directory link counts once, not once per file in its target.
Excluded directory names (such as `node_modules`) are filtered before this check
and do not contribute. Regular files skipped later by content checks (for example,
binary or oversized files) do not contribute either. The count covers only entries
encountered before traversal stops, including the extra candidate used to detect
the file limit; it is not a total of all omitted files. Zero does not establish
complete coverage. Skips alone do not trip the severity gate.

`summary.secret_hits_by_file` maps relative paths to counts of retained secret
findings, in sorted path order. Repeated hits on the same line count separately;
config and dependency findings do not contribute. Only paths with secret findings
appear, and no retained secrets produces `{}`. Counts sum to `summary.secret_hits`,
include low-severity hints, and can be reduced by finding caps. They do not prove
that credentials are real or that scanning was complete. This summary does not
change findings, gates, triage, or `manifest_hash`.

These symlink exclusions apply to entries encountered **beneath** the selected
target. An explicitly supplied local target that is a symlink to a directory is
followed: its regular descendants are scanned and counted normally, while links
encountered inside it are still skipped. The target alias itself does not add to
`summary.skipped_non_regular` or `summary.files_scanned`. The report retains the
supplied target spelling, and finding paths are relative to that target; it does
not replace the reported target with the resolved directory path.

`summary.osv_enabled` is `false` when `--no-osv` disables dependency advisory
lookups, and `true` otherwise. It records the selected mode, not lookup success:
check `errors`, `summary.packages_found`, and `summary.lockfiles_parsed` for
coverage. Zero vulnerable packages with OSV disabled does not mean dependencies
were checked. This summary field does not affect `manifest_hash`.

`summary.packages_by_ecosystem` counts unique `(ecosystem, name, version)` inventory
entries for each observed ecosystem, in sorted ecosystem order. Its counts sum to
`summary.packages_found`; duplicate entries across manifests count once, while
different versions count separately. Empty inventory produces `{}`. These are
inventory counts, including with `--no-osv`, not advisory counts or proof of a
complete assessment. File limits bound this inventory; finding limits do not.

`summary.multi_version_packages` maps ecosystems to package names to lists of
versions, including only names with multiple distinct versions in that ecosystem's
parsed inventory. For example, `{"PyPI": {"demo": ["1.0", "2.0"]}}` means both
versions were found; duplicates across manifests count once. Ecosystems, names,
and version strings are ordered lexicographically, not by semantic version.
Names and versions use the existing parsers' normalization; ecosystems remain
separate. No multi-version names produces `{}`. This works with `--no-osv` and is
unaffected by finding caps, but file limits and parser coverage bound the inventory.
Multiple versions can be intentional and do not establish a vulnerability or a
resolution conflict. This field adds no findings and does not affect severity gates
or `manifest_hash`.

`summary.package_names_by_ecosystem` counts distinct parsed package names in each
ecosystem, ignoring repeated versions and manifests. Names use the existing
parsers' spelling and normalization; scoped npm names remain distinct from
unscoped names. Keys are alphabetically ordered, and an empty inventory yields
`{}`. Unlike `summary.packages_by_ecosystem` (package/version pairs), multiple
versions of one name count once here. Counts remain available with `--no-osv`
and are independent of finding limits, but file limits and parser scope still
apply. They do not establish complete dependency coverage or vulnerability
status, and do not affect `manifest_hash`.

`summary.vulnerable_packages_by_ecosystem` counts unique vulnerable
`(ecosystem, name, version)` entries returned by OSV, grouped in sorted ecosystem
order. Only affected ecosystems appear, and the counts sum to
`summary.vulnerable_packages`, even when finding limits truncate the report.
Multiple advisories for one package version count once; distinct versions count
separately. No returned vulnerabilities or `--no-osv` produces `{}`. These counts
do not establish lookup completeness or change findings, gates, or `manifest_hash`.

`summary.dependency_files_by_ecosystem` counts distinct representative manifest
paths in emitted dependency findings, grouped in sorted ecosystem order. Several
vulnerable packages in one file count once within that ecosystem. Only ecosystems
with retained findings appear; no dependency findings (including `--no-osv`)
produces `{}`. Global and per-file finding caps can reduce these counts. The
scanner attributes each package version to one representative manifest, so this
is not an inventory of every affected manifest or proof of advisory coverage.
This summary does not change findings, gates, triage, or `manifest_hash`.

`summary.packages_by_manifest` counts deduplicated inventory entries attributed to
each parsed manifest, in sorted path order, including zero counts. Each unique
`(ecosystem, name, version)` is attributed to one file: the first encountered,
with a shipped manifest preferred over a test/fixture/example manifest. These
counts sum to `summary.packages_found`; they are not raw per-file dependency
counts. An empty object means no manifest was parsed. These inventory counts
are available with `--no-osv`, are bounded by file limits, and are unaffected by
finding limits or advisory results. They do not change `manifest_hash`.

`summary.packages_by_path_context` splits the same unique inventory entries into
`scaffold` and `other`, including zero counts. Classification uses the existing
test/example/fixture/documentation/CI path heuristic on each entry's attributed
manifest; an entry seen in both contexts is attributed to the non-scaffold path.
Distinct versions and ecosystems count separately. The counts sum to
`packages_found` and are available with `--no-osv` and without `--triage`.
This is a path hint, not proof of deployment or runtime use: a development
dependency outside a recognized scaffold path counts as `other`. File limits
bound the inventory; finding limits do not. Findings and `manifest_hash` are
unchanged by this summary.

`manifest_hash` is the sha256 of the canonical (sorted-key, compact) JSON of
`{findings, target, commit}`. It is stable when those three values are unchanged;
it is a report fingerprint, not a checksum of all repository contents. Findings
reflect the current working tree, so uncommitted edits can change the hash even
with the same commit and OSV data. Edits that leave findings unchanged do not
change it when target and commit are unchanged. `target` preserves the literal
CLI argument: different spellings of the same path can produce different hashes.

To recompute it from a full JSON report, use Python's ASCII-escaped JSON strings
(`ensure_ascii=True`), sorted object keys, and compact separators, then hash the
UTF-8 bytes without a trailing newline. Array order is preserved. Non-ASCII
characters stay escaped in this hash input even with `--unicode-json`; report
indentation and key-order flags do not change it. For example, with a full report
saved as `report.json`:

```python
import hashlib
import json

with open("report.json", encoding="utf-8") as report_file:
    report = json.load(report_file)
payload = {key: report[key] for key in ("findings", "target", "commit")}
canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"),
                       ensure_ascii=True)
assert hashlib.sha256(canonical.encode("utf-8")).hexdigest() == report["manifest_hash"]
```

This recipe requires the full `findings` array; `--summary-only` output omits it.

Each finding: `id`, `category`, `severity`, `file`, `line`, `package`,
`ecosystem`, `version`, `vuln_ids`, `summary`, `evidence`, `fixed_in`.
For dependency findings, `evidence` displays only the first five advisory IDs in
lookup-result order, while `vuln_ids` retains the full list sorted by ID. The
finding `summary` includes the advisory count and only the first advisory's
summary, limited to 120 characters. These display fields are not a complete
advisory list or a description of the most severe advisory. Advisories omitted
from `evidence` still contribute to severity, fix metadata, advisory counts,
triage and severity gates. Use `vuln_ids` to review all reported advisories for
an emitted finding; file/finding limits and lookup failures can still limit
report coverage.

Findings are sorted by severity (critical, high, medium, low, unknown), then
category, file, line, package and summary. Missing lines sort as zero; missing
file/package values sort as empty strings. `id` is assigned after sorting
(`F-001`…). These IDs identify findings within one report, including keys in
`triage` when enabled; they are not persistent issue identifiers. Adding or
removing a finding earlier in the sort order can renumber an unchanged finding.
Do not join findings across scans using `id` alone.

For a `dependency-vuln` finding, `file` names one representative manifest for
the unique `(ecosystem, name, version)` entry, not every manifest containing it.
The scanner prefers a path outside its test/fixture/example/benchmark path
heuristic; among paths with the same classification it retains the first in
sorted relative-path order. Different versions remain separate entries. Thus
affected-file counts can be smaller than the number of manifests containing an
affected dependency, even without truncation. `summary.lockfiles_parsed` lists
processed manifests, but does not map each package to all its occurrences.

`summary.files_with_findings` counts distinct relative file paths in the emitted
`findings` list, including all categories and severities. Multiple findings in one
file count once. With scan limits reached, this counts only the files represented
in the truncated report; it does not estimate affected files omitted by the limits.

`summary.files_with_findings_by_path_context` splits those distinct retained
file counts into `scaffold` and `other`, including zero counts. It uses the same
path-component heuristic as `summary.findings_by_path_context` (for example,
`tests/`, `examples/`, and `docs/`); filename-only hints such as `src/test_app.py`
do not make a path scaffold here. Repeated findings, categories, severities, and
line numbers in one file count once; findings with no line number still count.
The two buckets sum to `summary.files_with_findings`. This describes retained
finding paths, not all affected manifests or a judgment that a file is safe.
Counts remain available with `--summary-only`, with or without `--triage`.

`summary.findings_by_file` maps relative file paths to emitted finding counts,
with paths sorted lexically. It includes all categories and severities, omits
files with no findings, and is `{}` for an empty report. Counts sum to the length
of `findings`; a dependency finding with multiple advisories counts once. Scan
limits restrict these counts to retained findings, and the mapping does not
change with `--triage` or affect `manifest_hash`.

`summary.files_with_multiple_findings` counts relative file paths with at least
two emitted findings across all categories and severities. Findings on the same
line, and findings without a line number, each contribute to that file's count.
Each qualifying file counts once; an empty report yields zero. Scan limits
restrict this count to retained findings. It remains available with
`--summary-only`; triage does not filter it.

`summary.finding_lines_by_category` counts distinct retained `(file, line)`
locations separately for `dependency-vuln`, `secret`, and `config`, including zero
counts for categories without located findings. Findings with `line: null` are
excluded. Multiple findings in one category at the same location count once;
the same line number in different files counts separately. A location shared by
categories counts in each, so the category counts can sum to more than
`summary.finding_lines`. These are review-location counts after finding caps,
not source-line coverage or evidence that a category is safe. The counts remain
available with `--summary-only`, with or without `--triage`.

`summary.findings_without_line` counts emitted findings whose `line` is `null`,
such as dependency findings and the missing Dockerfile USER warning. It counts
findings, not files or advisory IDs: two dependency findings in one manifest
count twice. Empty reports and reports containing only located findings yield
zero. Only findings retained after caps count; this field remains available with
`--summary-only`. It does not change findings, triage, gates or `manifest_hash`.

`summary.finding_lines` counts distinct `(file, line)` locations across all
emitted findings with a non-null line number. Multiple rules or categories on
one line count once; equal line numbers in different files count separately.
Findings without a line number, including dependency findings and the missing
Dockerfile USER check, are excluded. Empty or entirely unlocated reports yield
zero. This counts retained finding locations after limits, not lines scanned,
all affected files, or source coverage. Triage does not filter the count;
findings, severity gates and `manifest_hash` are unchanged.

`summary.finding_lines_by_severity` counts distinct retained `(file, line)`
locations separately for `critical`, `high`, `medium`, `low`, and `unknown`,
including zero counts. Findings without a line number are excluded. Multiple
findings at the same location and severity count once; the same location at two
severities counts in both buckets, so their sum can exceed `finding_lines`.
These are raw finding severities; triage does not filter or reclassify the counts.

`summary.finding_lines_by_file` breaks that count down by relative file path,
with paths sorted lexically. Each value counts distinct retained non-null line
numbers across all rules and categories in that file. Paths with only unlocated
findings are omitted; an empty or entirely unlocated report yields `{}`. Values
sum to `summary.finding_lines`, including when `--summary-only` omits the findings.

`summary.files_with_findings_by_category` counts distinct relative file paths for
each of `dependency-vuln`, `secret`, and `config`, including zero counts. Repeated
findings in one file count once within each category; a file with both secret and
config findings counts in both categories. These counts can therefore sum to more
than `files_with_findings`. They count only emitted findings when scan limits
truncate results and do not affect `manifest_hash`.

`summary.by_category` counts emitted findings for `dependency-vuln`, `secret`, and
`config`, including zero counts. Its values sum to the length of `findings`, even
when scan limits truncate the report. A dependency finding may represent several
advisories; the count is not the number of advisories. Zero dependency findings
does not certify coverage (see `summary.osv_enabled` above). These counts do not
affect `manifest_hash`.

`summary.by_category_severity` breaks each category count down into `critical`,
`high`, `medium`, `low`, and `unknown`, including zeros. For example,
`summary.by_category_severity.secret.high` counts emitted high-severity secret
findings. Each row sums to its `summary.by_category` count, and each severity
column sums to its `summary.by_severity` count. These are raw severities, unchanged
by `--triage`, and count only emitted findings when limits truncate the report.
This summary does not affect `manifest_hash` or the `--fail-on` exit gate.

`summary.dependency_findings_by_ecosystem` counts emitted dependency findings by
ecosystem, in sorted ecosystem order. Only ecosystems with retained findings
appear; the counts sum to `summary.by_category["dependency-vuln"]`. Multiple
advisory IDs on one finding count once. Counts reflect both finding caps, whereas
`summary.vulnerable_packages_by_ecosystem` counts affected inventory entries even
when their findings are omitted. No emitted dependency findings yields `{}`;
this does not certify coverage (review OSV status, errors and truncation). Triage
and severity gates do not filter these counts. This field does not affect
`manifest_hash`.

`summary.dependency_findings_by_manifest` counts emitted dependency findings per
representative manifest path, with paths sorted lexicographically. Each finding
counts once even when it lists multiple advisory IDs; other finding categories
do not contribute. A package/version shared by multiple manifests is attributed
only to its selected representative path, not every manifest containing it.
Paths without retained dependency findings are omitted; an empty result is `{}`.
The counts sum to `summary.by_category["dependency-vuln"]` and reflect finding
limits. They do not certify advisory coverage; review OSV status, errors and
truncation. Triage, severity gates and `manifest_hash` are unchanged.

`summary.dependency_findings_with_fixes` counts emitted dependency findings with
at least one reported `fixed_in` version. Each package/version finding counts
once, even with multiple advisories or fixed versions. This counts reported fix
metadata, not verified upgrade recommendations: a listed version need not fix
every advisory in the finding. Empty, offline, and no-fix reports return zero;
zero does not certify coverage or prove no fix exists. Finding limits can omit
dependencies from this count. The field does not affect gates or `manifest_hash`.

`summary.dependency_findings_without_fixes` counts emitted dependency findings
whose `fixed_in` list is empty. It counts findings, not advisory IDs; a finding
with any reported fix is excluded even if its other advisories have no fix
metadata. Together with `dependency_findings_with_fixes`, it sums to
`summary.by_category["dependency-vuln"]`. Missing fix metadata does not prove that
no fixed release exists. Empty, offline, and no-advisory reports return zero;
finding limits can omit results. This count is unchanged by `--triage` and does
not affect findings, severity gates or `manifest_hash`.

`summary.secret_hits_by_rule` groups emitted secret findings by their existing
human-readable `summary` labels, in alphabetical label order. Its counts sum to
`summary.secret_hits`; no secret findings produces `{}`. Repeated hits count
separately, including when provider and generic rules both match one value.
Low-severity hinted hits are included, and `--triage` does not change the counts.
These labels are not stable rule IDs or credential validation; no matched values
are included. Scan limits restrict the counts to emitted findings. This field
does not affect `manifest_hash` or the severity gate.

`summary.config_issues_by_file` counts emitted configuration findings by relative
file path, with paths in alphabetical order. Multiple findings in one file count
separately, including file-level findings without a line number. Paths with no
configuration findings are omitted; no configuration findings produces `{}`.
Counts sum to `summary.config_issues` and reflect only findings retained within
scan limits, not complete configuration coverage.

`summary.config_issues_by_rule` groups emitted configuration findings by their
existing human-readable `summary` labels, in alphabetical order. These labels
are not stable rule IDs. Counts sum to `summary.config_issues`; no configuration
findings produces `{}`. Multiple findings in one file count separately, while
checks that emit once per file still count once. File and finding limits can
omit results, so these counts do not certify configuration coverage. They contain
no credential values and do not affect findings, severity gates or `manifest_hash`.

`summary.highest_severity` is the highest severity in the emitted findings,
ordered `critical`, `high`, `medium`, `low`, then `unknown`. It is `unknown` when
all findings are unrated and JSON `null` when no findings were emitted. It uses
raw severity, unchanged by `--triage`; `unknown` never triggers `--fail-on`.
Scan limits can omit more severe findings, and an empty report does not certify
coverage. Check `summary.truncated`, `summary.osv_enabled`, notes and errors.
This summary field does not affect `manifest_hash`.

`summary.unique_advisories` counts distinct advisory ID strings in emitted
`dependency-vuln` findings. A shared ID counts once across packages and versions;
different IDs count separately even if they are aliases for the same issue.
This differs from `summary.vulnerable_packages`, which counts affected inventory
entries before finding limits. File and finding limits bound the advisory count.
Zero means no advisory IDs were emitted, including with `--no-osv`; it does not
certify coverage or successful lookups. Check errors, notes and truncation flags.
This summary field does not affect `manifest_hash`.

`summary.unique_advisories_by_ecosystem` maps each ecosystem to its count of
distinct advisory ID strings in retained dependency findings, with ecosystem
keys sorted alphabetically. Repeated IDs across packages, versions and files
count once within an ecosystem. An ID shared across ecosystems counts in each,
so these counts can sum to more than `summary.unique_advisories`. Different IDs
remain separate even if they are aliases. Ecosystems without emitted advisory
IDs are omitted; no emitted IDs produces `{}`, including with `--no-osv`.
File and finding limits bound these counts; they do not establish coverage or
successful lookups. Findings, triage, gates and `manifest_hash` are unchanged.

`summary.dependency_findings_by_advisory` maps each advisory ID to the number of
emitted dependency findings referencing it, with keys sorted alphabetically.
Repeated IDs within one finding count once; distinct package versions and
ecosystems count separately. Duplicate manifests for the same ecosystem, package
and version do not add findings. Different advisory IDs remain separate even
when they are aliases. The number of keys equals `summary.unique_advisories`;
the values can sum to more than the dependency finding count because a finding
may reference several advisories. Counts include only findings retained after
limits, and no emitted dependency findings produces `{}`, including with
`--no-osv`. This is not a coverage guarantee. Findings, gates, triage and
`manifest_hash` are unchanged by this summary.

`summary.dependency_files_by_advisory` maps each advisory ID to the number of
distinct representative manifest paths in its emitted dependency findings, with
keys sorted alphabetically. Several packages or versions sharing an advisory in
one file count once; the same advisory in two representative paths counts twice.
Package deduplication selects one representative path per ecosystem/name/version,
so this is not a count of every manifest containing an affected package.
Different advisory IDs remain separate even when they are aliases. Counts use
only findings retained after limits; no emitted dependency findings produces
`{}`, including with `--no-osv`. Zero is not a coverage guarantee. This field
does not change findings, gates, triage or `manifest_hash`.

`--fail-on SEV` and `--fail-on=SEV` accept case-insensitive values. When repeated,
the last value wins across both spellings: `--fail-on HIGH --fail-on=none`
disables the gate, while `--fail-on=none --fail-on HIGH` enables the high gate.
An invalid earlier value still exits with code 2; a later valid value does not
repair an argument error.

When the final `--fail-on` value enables a gate, `summary.gate` records the
normalized `threshold`, the number of emitted raw findings at or above it (`matching_findings`), and
`passed` (true when that count is zero). `unknown` never matches a threshold;
`--triage` does not change the gate. The field is omitted without `--fail-on`
or when its final value is `none`, and does not affect `manifest_hash`. Passing
describes the exit-code gate, not complete coverage: review errors, notes and truncation flags, since discarded
findings cannot contribute to the count.

`summary.total_findings` counts emitted findings across all categories and
severities, including `unknown`, after file and finding caps. It equals the
length of `findings` and is zero for an empty report. `--triage` and `--fail-on`
do not filter this count; findings below the gate threshold still contribute.
Zero does not prove a complete scan: review errors, notes and truncation flags.
This summary field does not affect `manifest_hash`.

`summary.limits` records the applied caps: `files` (candidate files visited),
`findings` (total findings emitted), and `findings_per_file` (findings emitted
per file across all categories). These are limits, not observed counts; consult
`summary.truncated` to see whether file or finding results were omitted at those
caps. A false truncation flag does not certify complete coverage: other filters
and limits still apply. This metadata does not affect `manifest_hash`.

`summary.highest_severity_by_file` maps each affected relative file path to its
highest emitted finding severity, with paths sorted lexically. `unknown` ranks
below `low`; files without findings are omitted, and an empty scan returns `{}`.
This summarizes emitted findings only, so finding caps can hide higher-severity
results. Check `summary.truncated` for incomplete results. Like the overall
highest severity, this field does not affect `manifest_hash`.

`summary.files_by_highest_severity` counts each affected relative file path once,
at its highest emitted raw severity across all categories. It includes zero counts
for `critical`, `high`, `medium`, `low`, and `unknown` (`unknown` ranks below `low`).
The counts sum to `summary.files_with_findings`; files without findings do not count.
Only findings retained after limits contribute, so check `summary.truncated` for
incomplete results. Triage does not change these counts, and they do not affect
`manifest_hash` or the severity gate.

`summary.files_by_severity` counts distinct relative file paths at each raw severity
(`critical`, `high`, `medium`, `low`, `unknown`), including zero counts. Repeated
findings at the same severity in one file count once; a file with multiple severities
counts in each applicable bucket, so the counts can sum to more than
`summary.files_with_findings`. Counts cover only emitted findings after truncation,
remain unchanged by `--triage`, and do not affect `manifest_hash` or the severity gate.

`summary.secret_lines` counts distinct `(file, line)` locations in emitted secret
findings. Several hits on one line count once; the same line number in different
files counts separately. A multiline private-key finding contributes only its
reported header line. This is a source-location count, not a count of distinct
credentials; zero means no emitted secret findings, not complete coverage.
Finding limits can omit locations. The count includes low-severity hints and is
unchanged by `--triage`; it does not affect findings, gates or `manifest_hash`.

`summary.findings_by_path_context` partitions retained findings across all
categories into `scaffold` and `other` counts (both keys are present even at zero).
It uses the existing case-insensitive path-segment heuristic used by
`packages_by_path_context`, including test, fixture, example, documentation and
`.github` directories. It counts findings, not distinct files; the two counts
sum to `summary.total_findings`. Only findings retained after scan limits count.
This path label does not establish whether a file is deployed or a finding is
harmless, and it does not change raw severity, triage, or the severity gate.

`summary.finding_lines_by_path_context` counts distinct retained `(file, line)`
locations in the same `scaffold` and `other` path groups, including zero counts.
Findings without a line number are excluded. Multiple findings at one location
count once even across categories and severities; equal line numbers in different
files count separately. The two counts sum to `summary.finding_lines`. These are
review locations after scan limits, not source coverage or proof that scaffold
findings are harmless. Triage does not filter the counts.

`summary.config_lines` counts distinct `(file, line)` locations in emitted
configuration findings with a line number. Multiple rules on one line count once;
the same line number in different files counts separately. File-wide findings
with a null line (such as a missing Dockerfile USER) are excluded. This counts
only retained findings after scan limits, not every configuration line scanned.

`summary.config_lines_by_rule` maps configuration finding summary labels to
counts of distinct `(file, line)` locations, sorted alphabetically by label.
Repeated hits for the same rule on one line count once; the same line number in
different files counts separately. Findings with `line: null` are excluded, and
rules with no line-addressable findings are omitted (an empty report uses `{}`).
Different rules can share a location, so adding these counts need not equal
`summary.config_lines`. Counts describe only emitted findings after finding caps;
they do not measure unchecked locations or change findings, triage, gates or hashes.

`summary.config_files_by_rule` maps configuration finding summary labels to
distinct affected-file counts, in alphabetical label order. Repeated warnings
for one rule in one file count once; the same file can count under several rules.
Labels are human-readable descriptions, not stable rule IDs. Only emitted config
findings count, so scan limits may omit affected files. No config findings yields
`{}`; this does not certify complete coverage. These counts include all raw
severities, are unchanged by `--triage`, and do not affect `manifest_hash` or gates.

### Triage (`--triage`)

`triage_summary.dependency_actions_by_ecosystem` maps each ecosystem with retained
dependency findings to `upgrade` and `monitor` finding counts (both keys are
present, including zeros). Ecosystem keys are alphabetically ordered; no retained
dependency findings yields `{}`. Missing ecosystem metadata uses `unknown`.
Each finding counts once, regardless of advisory IDs or fixed versions; scaffold
findings are included. These opt-in counts follow existing fix-metadata actions:
non-empty `fixed_in` selects `upgrade`, otherwise `monitor`. They do not establish
release availability, unique-package counts, or complete advisory coverage, and
reflect finding limits. Findings, existing triage decisions, gates and
`manifest_hash` are unchanged.

`triage_summary.dependency_actions_by_file` maps relative representative manifest
paths to `upgrade` and `monitor` finding counts, with both buckets present for
each path. Paths are sorted; the map is `{}` without retained dependency
findings. A finding counts once regardless of advisory IDs or fixed versions:
non-empty `fixed_in` selects `upgrade`, otherwise `monitor`. These are existing
fix-metadata classifications, not confirmation of release availability. Scaffold
paths are included. A package found in several manifests is attributed only to
the scanner's representative path, and scan limits can truncate these counts.
This opt-in summary leaves findings, triage actions, hashes and gates unchanged.

`triage_summary.dependency_actions_by_severity` groups emitted dependency findings
into `upgrade` and `monitor` rows, each with raw-severity counts (`critical`,
`high`, `medium`, `low`, `unknown`, including zeros). A finding counts once,
regardless of its advisory IDs or fixed versions; a non-empty `fixed_in` selects
`upgrade`, otherwise `monitor`, following the existing triage actions. Scaffold
lockfiles are included at their raw severity even when triage marks their priority
low. These opt-in counts cover only retained findings after scan limits and do
not prove advisory coverage or that every advisory has a fix. They do not change
findings, the headline, severity gates, or `manifest_hash`.

With `--triage` the output gains two additive top-level keys and the raw findings
and `manifest_hash` stay untouched:

- `triage_summary` — counts and a one-line `headline`: dependency findings split
  into `upgradeable` (nonempty `fixed_in`) vs `monitor_only` (empty `fixed_in`),
  and secret hits split into `needs_review` vs `likely_false_positive`.
  The headline is a human-readable summary whose wording may change between
  releases; consumers read counts from the structured fields (`triage_summary`,
  `summary.unique_advisories`), not from the headline.
  `secret_review_by_severity` breaks down the secret hits needing review by
  raw severity (`critical`, `high`, `medium`, `low`, `unknown`, including zeros).
  It excludes likely false positives and counts only emitted findings if the
  scan was truncated; these counts do not alter the raw severity gate.
  `config.needs_review` counts configuration findings and includes them in the
  headline, including when no secrets or dependency findings exist. Like other
  triage counts, it covers only emitted findings when scan limits truncate results.
  `config_review_by_severity` breaks down those configuration findings by raw
  severity (`critical`, `high`, `medium`, `low`, `unknown`, including zeros).
  Configuration findings under test/fixture paths still count as needing review;
  these counts do not alter findings, triage actions, or the raw severity gate.
- `triage` — a map from finding `id` to an interpretation: for a `dependency-vuln`,
  `action` is `upgrade` (with `upgrade_to`) or `monitor`; for a `secret`,
  `likely_false_positive` is set true when the hit sits in a test/fixture/example/CI
  path, a translation-catalogue path (`locales/`, `i18n/`, …, v0.4.1), or carries a
  value-shape tag (placeholder, expression, non-ASCII, dotted name, form placeholder,
  example key — see the secret section), routing everything else to `review`;
  `config` findings are `review`.

Dependency actions use reported fix metadata, not an independent check of release
availability. `monitor` means the finding has no reported fixed version: this can
also happen when advisory details omit fix metadata or fail to load. It
does not prove that no patched release exists; review `errors` and the advisories.
`upgrade` means at least one advisory contributed a fixed version. A finding can
combine multiple advisories, so a nonempty `upgrade_to` list
does not prove that every advisory is resolved by a listed version. Confirm the
applicable release against each advisory before choosing an upgrade. Existing
headline and note phrases such as "no patched release" are metadata-based labels,
not guarantees about available releases.

This is purely deterministic prioritisation (fix metadata + path-based false-positive
classification). It never clears a secret found in real source — it flags it for a
human. It exists so a reader does not have to hand-triage a long raw list.

`triage_summary.by_action` counts findings assigned to `upgrade`, `monitor`,
`review`, and `informational`, including zero-valued buckets. Counts sum to the
number of emitted findings, not files or advisory IDs. `review` includes config
findings; scaffold dependency findings retain their upgrade/monitor action.
When scan limits truncate the report, these counts cover only emitted findings.
This field is present only with `--triage` and does not change the severity gate.

`triage_summary.files_by_action` counts distinct relative file paths for each of
the same four actions, including zero-valued buckets. Repeated findings assigned
to one action in a file count once; a file with different actions counts in each
applicable bucket, so these counts need not sum to the total number of files.
Findings without a non-empty file path do not add to these file counts.
Scaffold dependencies retain their upgrade/monitor action. Counts cover only
emitted findings when limits truncate the report. This field is present only
with `--triage` and does not change findings, the hash, or the severity gate.

With `--triage`, `triage_summary.config_files_needing_review` counts distinct
relative file paths with emitted configuration findings. Multiple findings in
one file count once; files in test/example/fixture paths still count because
configuration findings retain their `review` action. Secret and dependency
findings do not contribute. The count is zero when no configuration files need
review, and covers only retained findings when scan limits truncate results.
The existing `triage_summary.config.needs_review` remains a finding count.
This additional count does not change findings, triage actions, the hash or gate.

With `--triage`, `triage_summary.config_review_by_file` maps relative file paths
to the number of retained configuration findings needing review in each file.
Keys are sorted alphabetically. Multiple findings in one file count separately;
test/example/fixture paths remain included. Secret and dependency findings and
findings without a non-empty file path do not contribute. The mapping is empty
when no configuration findings have paths. It covers only retained findings when
limits truncate results, and remains available with `--summary-only`. This field
does not change findings, triage actions, the hash or severity gate.

With `--triage`, `triage_summary.dependency_files_needing_upgrade` counts distinct
representative manifest paths in emitted dependency findings with an `upgrade`
action. Multiple packages or advisories in one file count once; scaffold paths
still count. Monitor-only dependencies and non-dependency findings do not count.
The count is zero when no emitted dependency finding has fix metadata. It uses
the existing representative-manifest attribution after package deduplication,
so it is not a count of every affected manifest. Finding limits can reduce it;
this count does not establish complete advisory coverage or that an upgrade
resolves every advisory. Findings, triage actions, the hash and gate are unchanged.

`triage_summary.secret_files_needing_review` counts distinct relative file paths
with emitted secret findings classified as `review`. Repeated hits in one file
count once; likely-false-positive secrets and non-secret findings do not count.
It is zero when no secret findings need review. With scan limits reached, it
counts only files represented in the emitted findings, not omitted files. Like
the rest of triage, this count does not change findings, the hash, or the gate.

`triage_summary.secret_review_by_file` maps relative paths to the number of
emitted secret findings classified as `review`, with paths sorted alphabetically.
Repeated hits in a file count separately; informational secrets and non-secret
findings are excluded. The values sum to `triage_summary.secrets.needs_review`,
and the number of paths equals `triage_summary.secret_files_needing_review`.
No secrets needing review produces `{}`. This field is present only with
`--triage`; finding limits can make the counts partial. The classifications are
heuristics, not confirmation that credentials are live. The field adds no raw
values and does not change findings, the hash, or the severity gate.

With `--triage`, `triage_summary.dependency_outside_scaffold_lockfiles`
contains `upgradeable` and `monitor_only` counts for emitted dependency findings
whose source paths do not match the existing test/example/fixture scaffold
heuristic. The existing overall dependency counts still include scaffold hits.
These are finding counts, not advisory counts or recommended target versions;
multiple advisories grouped into one dependency finding count once. Zero buckets
are included, and finding caps can make the counts partial. Path classification
helps prioritize review; it does not establish production use or reachability.

`triage_summary.secret_false_positive_reasons` counts emitted secret findings by
their existing per-finding `reason`, with keys in sorted order and `{}` when none
qualify. Each secret counts once: test paths take precedence over test filenames,
localization paths, and value hints, matching per-finding triage. The counts sum
to `triage_summary.secrets.likely_false_positive`. These are heuristic reasons,
not confirmed false positives; review them before dismissing a finding. When
limits truncate findings, only emitted hits count. This opt-in summary does not
change raw findings, `manifest_hash`, or the severity gate.

`triage_summary.secret_false_positives_by_file` maps relative file paths to counts
of emitted secret findings classified as likely false positives. Keys are sorted;
the map is `{}` when none qualify. Multiple findings on one line count separately,
and a file may contain both informational and review-needed secrets; only the
informational secrets count here. Counts sum to
`triage_summary.secrets.likely_false_positive` and include only retained findings
when scan limits apply. This is a heuristic triage aid, not confirmation that a
file is safe; raw findings and severity gates remain unchanged.

`summary.secret_files_by_rule` maps secret finding summary labels to distinct
affected-file counts, in alphabetical label order. Repeated hits for one label
in one file count once; the same file can count under several labels. Labels are
human-readable descriptions, not stable rule IDs. Counts include all emitted
secret findings, including low-severity and likely-false-positive hits, and are
unchanged by `--triage`. Scan limits may omit affected files. No secret findings
yields `{}`; this does not certify complete coverage. This summary does not change
findings, redaction, `manifest_hash`, or severity gates.

`summary.secret_lines_by_rule` maps the same human-readable secret labels to
counts of distinct `(file, line)` locations, in alphabetical label order.
Repeated hits for one label on one line count once; the same line may count
under several labels, and the same line number in separate files counts separately.
All emitted secret findings count, including low-severity and likely-false-positive
hits. Only retained findings count when scan limits truncate results. No secret
findings yields `{}`; this does not certify complete coverage. This summary adds
no matched values and does not change findings, `manifest_hash`, triage, or gates.

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
| `yarn.lock` (v1 + Berry) | npm | v1 `name@range:` + `  version "x"`; Berry `"name@npm:range":` + `  version: x` (`workspace:`/`patch:`/`portal:`/`link:` entries skipped, v0.4; multi-`@` patch keys fixed v0.4.2) |
| `pnpm-lock.yaml` | npm | `packages:` keys `/name@1.2.3` or `name@1.2.3` |
| `go.mod` | Go | the `require` build list (direct + `// indirect`); preferred over `go.sum` (v0.4) |
| `go.sum` | Go | only when no `go.mod` sits beside it (go.sum also lists superseded versions); `/go.mod` suffix stripped |
| `Gemfile.lock` | RubyGems | `specs:` within `GEM` sections only, `    name (1.2.3)`; `GIT`/`PATH` specs excluded |

Requirements files are discovered by case-sensitive basename: any name starting
with `requirements` and ending with `.txt`, at any included directory depth.
For example, `requirements-dev.txt` and `nested/requirements_extra.txt` qualify;
`Requirements.txt`, `requirements.in`, `constraints.txt`, and `base.txt` do not.
Pip include and constraint directives (`-r`/`--requirement`, `-c`/`--constraint`)
are ignored, not followed. Referencing `base.txt` therefore does not inventory
its pins. A matching `requirements*.txt` file is discovered independently even
when no directive references it, subject to the usual directory and file limits.
A directive-only `requirements.txt` can appear in `summary.lockfiles_parsed`
with zero packages; that does not assess the dependencies in its include targets.

For `poetry.lock`, `uv.lock`, and `Cargo.lock`, the TOML reader uses package
name/version pairs without inspecting source metadata. Git, local/editable, and
source-less entries with a supported name/version pair can therefore enter the
inventory and advisory lookup as PyPI or crates.io packages, according to the
filename. Source URLs and revisions are not sent in those queries; entries with
the same ecosystem, name, and version collapse into one identity even when their
sources differ. A registry advisory match does not establish that a fork or local
package contains the affected code. Check the source before acting on that match.
`--no-osv` retains this inventory but skips advisory lookup.

For `package-lock.json`, package inventory does not filter on `dev`, `optional`,
`devOptional`, `os`, or `cpu` metadata. Entries with these fields can enter npm
advisory lookup from both the `packages` map and the fallback `dependencies` tree,
including nested dependencies of development-only packages. This is a static
lockfile inventory, not the packages installed by `npm ci --omit=dev` or on the
current operating system and CPU. `--no-osv` keeps this inventory but skips
advisory queries; a finding does not establish production installation or reachability.

For `pnpm-lock.yaml`, inventory comes from recognized keys in `packages:`, without
resolving the dependency graph in `importers:` or `snapshots:`. A recognized package
can enter npm advisory lookup even when no importer references it or its metadata
marks it development-only, optional, or specific to another OS/CPU. Entries found
only in importers or snapshots do not supply inventory. Parenthesized peer-context
suffixes are removed from package keys; entries with the same name and version
then count once, rather than once per peer context. `--no-osv` preserves this
inventory but skips advisory queries. These counts do not establish which packages
are installed or reachable; a parsed lockfile can still yield zero packages.

Dependency discovery matches these basenames exactly and case-sensitively at
any scanned directory depth; `requirements*.txt` is the prefix/suffix exception.
For example, `Package-lock.json`, `package-lock.json.bak`, and `Requirements.txt`
do not supply inventory. Neither do `package.json`, `npm-shrinkwrap.json`,
`Pipfile.lock`, `pyproject.toml`, or `composer.lock`: their dependency declarations
are not parsed or sent for advisory lookup. Such files may still receive local
secret/config checks. A tree containing only unrecognized manifest filenames has
zero inventoried packages, an empty `summary.lockfiles_parsed`, and a note that no
supported dependency manifest was parsed; this does not assess those dependencies.

For `package-lock.json`, package names in the `packages` map come from the path
after its last `node_modules/` component, including scoped names. An entry's
`name` metadata does not override that installed name. In the legacy
`dependencies` tree, the dependency key supplies the name and the `version`
string is kept literally. The scanner does not resolve npm aliases: an alias
can therefore be queried under its installed name rather than the underlying
package name, and a legacy `npm:...` version is not decoded. These same identities
are retained in offline inventory with `--no-osv`. A report without dependency
findings does not establish advisory coverage for the underlying aliased package.

For `package-lock.json`, the legacy `dependencies` tree is used only when the
`packages` map yields no package entries. An absent or empty map, a root-only
map, or a map whose entries lack usable versions can therefore fall back to
the legacy tree, including nested dependencies. Once the map yields even one
package, the two sections are not merged: legacy-only packages and alternate
legacy versions do not enter inventory or advisory queries. A partially
recognized map can therefore leave legacy entries unassessed. This selection
also applies to package inventory with `--no-osv`.

Go manifest selection is directory-local: a `go.mod` in the selected scan file
list suppresses only the `go.sum` beside it, not one in a child or sibling
directory. Selection happens before parsing. An empty `go.mod`, one with no
recognized requirements, or one that cannot be read still suppresses its
neighboring `go.sum`; the scanner does not use `go.sum` as a parse-failure
fallback. Conversely, a `go.mod` absent from the selected file list does not
suppress `go.sum` merely because it exists on disk. Review
`summary.lockfiles_parsed` and `summary.packages_found`: zero packages in these
cases does not mean the checksum-listed dependencies were assessed.

For `package-lock.json`, inventory is not filtered to production dependencies or
to packages installed on the current machine. Both the v2/v3 `packages` map and
the v1 `dependencies` tree include recognized name/version entries regardless of
`dev`, `optional`, `devOptional`, `os`, or `cpu` metadata, including nested entries.
These entries count in package summaries and are eligible for advisory lookup;
`--no-osv` keeps the inventory but skips that lookup. A reported package therefore
does not establish that it is installed or used in the deployed application.

For `Gemfile.lock`, only gems listed in `GEM` sections enter the package inventory
and RubyGems advisory lookup. Gems listed under `GIT` or `PATH` are excluded,
even if their names and versions resemble registry gems. A lockfile containing
only those excluded sources can still appear in `summary.lockfiles_parsed`
while contributing zero packages and causing no advisory requests. A clean
report therefore does not assess the excluded Git or local-path dependencies.

For `yarn.lock`, descriptors using `workspace:`, `patch:`, `portal:`, `link:`,
`file:`, `exec:`, `git:`, `github:`, `http:` or `https:` are excluded from package
inventory and advisory queries, even when their entries contain numeric versions.
This filter applies to each descriptor in a comma-separated list; a recognized
registry descriptor in the same list can still contribute a package. Ordinary
v1 ranges and Berry `npm:` descriptors remain supported. A lockfile containing
only excluded descriptors can appear in `summary.lockfiles_parsed` with zero
packages and no advisory requests. Such a report does not assess the excluded
dependencies, including the registry packages underlying `patch:` descriptors.

`Gemfile.lock` versions are kept literally, including platform suffixes such as
`1.2.3-x86_64-linux`; the scanner does not normalize them to `1.2.3` for advisory
lookup. The `PLATFORMS` section does not filter the inventoried `GEM` specs, so
`synthetic-native (1.2.3)` and `synthetic-native (1.2.3-x86_64-linux)` count as two
package/version entries and are queried separately. `PLATFORMS`, `DEPENDENCIES`
and `BUNDLED WITH` metadata alone supply no package versions. This is lockfile
inventory, not resolution of the gems installed on a particular host; an empty
advisory response does not establish coverage for a platform-suffixed version.

When `go.sum` is used, module-content rows and `/go.mod` rows for the same
module/version contribute one inventory entry; a `/go.mod` row alone also
contributes an entry. Distinct versions of one module remain separate entries
and advisory queries, including superseded versions. The scanner checks for a
nonempty `h1:` checksum field but does not validate its encoding or verify its
digest against module contents. This inventory is neither an installed-module
list nor a checksum-integrity assessment; a passing gate establishes neither.

Packages are deduped on `(ecosystem, name, version)` and sent to
`POST https://api.osv.dev/v1/querybatch` in chunks of 500. Each returned vuln id
is then fetched from `GET https://api.osv.dev/v1/vulns/{id}` (cached in-memory
per run) for severity and fixed versions.

Severity: a recognized `database_specific.severity` value
(CRITICAL/HIGH/MODERATE/MEDIUM/LOW, case-insensitive) takes precedence over
numeric scores. Otherwise the first supported numeric score in the `severity`
list is used, mapped ≥9 critical, ≥7 high, ≥4 medium, else low; unsupported
entries are skipped, and `unknown` is used when neither source is available.
Within one advisory this is list order, not the highest numeric score: scores
`4.0` followed by `9.8` produce medium, while reversing them produces critical.
Consequently `--fail-on high` does not fire for the first ordering alone.
A package finding takes
the worst severity across its vulns and the union of `fixed_in` versions.

Fix metadata has additional limits: for each advisory, the scanner collects
nonempty `fixed` event values from every `affected` entry and range, without
filtering by the queried package, ecosystem, range type, or installed version.
It ignores `introduced`, `last_affected`, and `limit` event values. It removes
duplicates, sorts the remaining strings lexicographically (so `10.0` precedes
`2.0`), and retains only the first ten values per advisory. A package finding's
`fixed_in` is the sorted, deduplicated union of those capped lists; that union
can exceed ten values. With `--triage`, `upgrade_to` repeats this union.
These values are advisory metadata, not a package-specific upgrade plan: they
can include unrelated package versions or Git revisions, are not sorted by
semantic version, and do not establish that a listed value fixes every advisory
for the installed package. Check the original advisory and applicable release
before choosing an upgrade.

CVSS vector strings are not evaluated. An advisory with only vector strings and
no recognized `database_specific.severity` remains `unknown`. Packages with such
advisories can still produce dependency findings, subject to finding limits;
other rated advisories can raise a package finding's severity. `unknown` findings do not trigger `--fail-on`,
even at `low`. A passing severity gate therefore does not clear unrated advisories.

HTTP timeout is 20 s per call. Request failures are appended to the top-level
`errors` list and the scan continues. If a batch request fails, that chunk yields
no dependency findings, while later chunks are still queried. Parsed packages
remain in the inventory; an empty findings array does not establish that their
advisories were checked successfully.

If an advisory-detail request fails after a batch returned its ID, the scanner
keeps that ID and uses fallback details: `unknown` severity, no fixed versions,
and the ID as the advisory summary. This fallback is cached for the rest of the
scan, so a shared failed advisory is fetched and recorded as an error only once.
Subject to finding limits, affected packages still produce dependency findings.
Other successfully loaded advisories for the same package can supply a higher
severity and fixed versions. With only failed details, `--triage` assigns
`monitor`, and even `--fail-on low` does not fire for the resulting `unknown`
findings. Request errors alone do not trip the severity gate; inspect `errors`
alongside findings and inventory before interpreting a passing exit code.

### 2. `secret`

Regex scan of text files ≤ 1 MiB. Binary files (null byte), `.git/`,
`node_modules/`, `vendor/`, `dist/`, `build/`, lockfiles, `*.min.js`, and common
binary/image extensions are skipped. Evidence is always redacted to the first 4
characters plus `…`.

Secret checks operate on text, without parsing the source language or Markdown.
A matching token or generic assignment inside a comment, string literal, or
Markdown code block can therefore produce a finding at that source line;
comment markers and code fences do not exempt it. Existing file/line limits,
pattern rules, and value-shape hints still apply. `--triage` uses its path and
value heuristics, not comment or code-block syntax, to classify these findings;
the raw severity gate still includes them.

A leading dot does not by itself exclude a file or directory. For example,
`.settings` can receive secret checks, and files under `.config/` can receive
secret, config and supported dependency checks. Named directory exclusions
such as `.git/` and `.venv/`, file-type exclusions, and the usual scan limits
still apply; hidden paths are not a separate coverage category.

The generic-assignment check skips values starting with `http://`, `https://`,
`ws://` or `wss://` (case-insensitive). This excludes endpoint strings, not all
secrets inside URLs: provider-token patterns still report with redacted evidence.
Other schemes and malformed URL prefixes do not get this exclusion.

Single-line provider patterns and generic assignments are checked only on lines
of at most 4,000 characters (excluding the line ending; Unicode characters count
as one character each). Longer lines are skipped, but later lines in the same
file are still checked. The separate multiline private-key block check is not
subject to this per-line limit; the file-size and file-selection limits above
still apply. A report with no secret findings does not establish that skipped
lines are free of secrets.

The 1 MiB limit is 1,048,576 file bytes, not decoded characters. A file exactly
at the limit can be scanned; larger files are skipped entirely, including any
secret on the first line. Other eligible files are still scanned. An oversized
file can still count in `summary.files_scanned`; skipping its text does not set
`summary.truncated`, whose flags describe file-count and finding-count caps.
An empty findings list with both flags false therefore does not establish that
all file contents were checked.

Extension exclusions apply before reading the content and are case-insensitive:
even readable text in `.svg` / `.SVG` files is omitted from secret scanning.
Such files still count in `summary.files_scanned`; skipping them does not set
`summary.truncated`. Secrets found only in excluded files cannot trigger the
severity gate, so a passing gate does not establish that those files are clear.

The secret-scan lockfile exclusion uses these exact basenames, at any depth:
`package-lock.json`, `yarn.lock`, `pnpm-lock.yaml`, `poetry.lock`, `uv.lock`,
`Cargo.lock`, `Gemfile.lock`, `go.sum`, `go.mod`, and `composer.lock`.
It includes the `go.mod` manifest and `composer.lock` even though Composer
dependency parsing is unsupported. It is not a blanket `.lock` exclusion:
`custom.lock` and other manifests such as `requirements.txt`, `package.json`,
and `pyproject.toml` still receive secret scanning when otherwise eligible.
Supported dependency inventory/lookups run independently of this secret-scan
exclusion. A parsed lockfile with no secret findings does not establish that
its contents were checked for secrets.

The shared text reader tries UTF-8, then falls back to Latin-1 if UTF-8 decoding
fails. ASCII token patterns can therefore still match in a Latin-1 file. Any
NUL byte skips the entire file before decoding, even when a token occurs before
that byte. Ordinary UTF-16/UTF-32 text containing NUL bytes is skipped rather
than transcoded. Such a file can still count in `summary.files_scanned`; no
secret findings (and a successful severity gate) do not establish that its
contents were assessed.

The `*.min.js` exclusion is a case-sensitive filename suffix check, not content
analysis: even formatted text named `bundle.min.js` is skipped. Names such as
`bundle.MIN.JS` and `bundle.min.js.map`, and compact code in ordinary `.js` files,
are not excluded by this rule; other scan limits still apply. Skipped `.min.js`
files can count toward `summary.files_scanned` without setting
`summary.truncated`. Secrets present only in those files cannot trigger the
severity gate, so a passing gate does not establish that they were checked.

| Pattern | Severity |
| --- | --- |
| `AKIA[0-9A-Z]{16}` (AWS access key id) | high |
| `gh[pousr]_[A-Za-z0-9]{36,}` | high |
| `github_pat_[A-Za-z0-9_]{80,}` | high |
| `glpat-` + 20 URL-safe characters (GitLab personal access token) | high |
| `npm_` + 36 alphanumerics (npm access token) | high |
| `sk-` or `sk-proj-` + 40+ URL-safe characters (OpenAI; excludes `sk-ant-`) | high |
| `sk-ant-` + 40+ URL-safe characters (Anthropic) | high |
| `hf_` + 34+ alphanumerics (Hugging Face) | medium |
| `SG.` + 22 URL-safe characters + `.` + 43 URL-safe characters (SendGrid) | high |
| digits + `:` + 35 URL-safe characters (Telegram bot token) | high |
| `SK` + 32 hex characters (Twilio API key SID) | medium |
| `xox[baprs]-[0-9A-Za-z-]{10,}` (Slack) | high |
| `sk_live_[0-9a-zA-Z]{24,}` (Stripe live) | critical |
| `AIza[0-9A-Za-z_-]{35}` (Google API key) | medium |
| Complete multiline `BEGIN … PRIVATE KEY` / matching `END` block | critical |
| Known private-key header followed by a base64-looking line (legacy fallback) | critical |
| generic `api_key` / `api-key` / `apikey` / `secret` / `password` / `passwd` / `token` assignment | medium |
| Stripe live restricted key (`rk_live_` + 24+ alphanumeric characters) | high |

Generic assignment names above are case-insensitive; bare `key` is not recognized
by this rule. Assignments use `=` or `:` followed by a single- or double-quoted
value of at least 16 characters with no whitespace or embedded quotes.
Generic assignment keys may also be enclosed in paired single or double quotes,
such as JSON's `"password": "…16+ chars"`. This is a line-based heuristic, not a
JSON/YAML parser; the existing value exclusions and hint downgrades still apply.

URL-safe characters above are `A-Z`, `a-z`, `0-9`, `_`, and `-`.

Complete private-key blocks accept any uppercase/space label (including unlabelled
`PRIVATE KEY`), require at least three base64 body lines, and produce one
`Multiline private key block detected` finding on the header line. That finding
replaces the legacy header hit. Body hints reuse the existing example/mask and
value-shape checks to downgrade to **low**; a short placeholder body such as `...`,
`YOUR_KEY_HERE`, `REDACTED`, or `xxxx` is also retained as a low finding. Evidence
never includes the body. A bare header in source without a body remains ignored.

The legacy header fallback also emits a **critical** `Private key block detected`
finding for an unlabelled, RSA, EC, OPENSSH, DSA or PGP private-key header when
the next line contains at least 20 characters from `A-Z`, `a-z`, `0-9`, `+`, `/`
or `=` (with optional surrounding whitespace). This fallback does not require a
footer or a complete key, and does not apply body placeholder downgrades. Its
evidence contains only the redacted header. These are text-shape checks, not
proof that the body is valid base64 or usable private-key material.

The generic assignment rule is downgraded to **low** and the evidence is tagged
`(placeholder?)` when the value matches
`example|changeme|your[_-]|xxx|dummy|placeholder|<|${`.

**Value-shape hints (v0.4.1).** The 2026-10-08 dataset showed that most secret hits
surviving the path rule were not credentials at all, so the evidence now carries one
of these tags and the raw severity drops to **low** when the *value* matches a
shape heuristic; `--triage` classifies the same tags as likely false positives:

| tag | shape |
| --- | --- |
| `(expression?)` | template / env reference: `={{$credentials.x}}`, `${VAR}`, `$VAR`, `$__env{…}`, `{env:…}`, `#{…}`, `%{…}`, `<%…`, `var(--…)` |
| `(non-ascii?)` | generic assignment value contains non-ASCII text (often translated UI copy or `••••` masks); a real password can also match |
| `(dotted-name?)` | dotted identifier with no digits (`entity.other.inherited-class`, `grafana.someFlagToken`, hostnames) |
| `(word-like?)` | generic assignment value starts with an ASCII letter and contains only ASCII letters, underscores and hyphens, with no digits; includes mixed-case values, not just words or field names |
| `(form-placeholder?)` | the match sits inside a form `placeholder=` attribute |
| `(example-key?)` | fixed-pattern hit that is a documented example (`AKIAIOSFODNN7EXAMPLE`, GitHub's docs `ghp_…`) or an `xxxx…`/`0000…`/`****` masked value |

Hints do not suppress matches: retained hits stay in `findings` with their tags,
subject to the finding limits described above. They are
prioritization heuristics, not credential validation. A real password can contain
non-ASCII characters or no digits. Even a mixed-case value such as
`"AbCdEfGhJkLmNpQrStUv"` matches `word-like?`; matching generic assignments are
still reported at low severity and classified likely false positives by `--triage`.
Such hits alone do not trip `--fail-on medium` (or a higher threshold), but do trip
`--fail-on low`. Generic assignments without a hint keep medium severity; path
heuristics may still classify them as likely false positives during triage.
Provider-token hits (excluding private-key handling) use example/mask and form-placeholder hints,
not the generic `word-like?` or `non-ascii?` checks: a matching GitHub token with
an all-letter payload can still be high severity. No hint establishes whether
a credential is live. Test-path rule also widened in v0.4.1: `__fixtures__`, `__mocks__`,
`testutils/`, `test-utils/`, `snapshots/`, `testUtils.*`.

### 3. `config`

Dockerfile checks select files by a case-sensitive basename: exactly `Dockerfile`
or a name beginning with `Dockerfile.`, at any included directory depth (for
example, `services/api/Dockerfile.dev`). They do not select `Containerfile`,
`dockerfile`, or `service.Dockerfile`. These other names can still receive
independent secret-pattern scanning when otherwise eligible; absence of
Dockerfile config findings does not establish that their contents were checked
by the Dockerfile rules.

* `.env` / `.env.*` with at least one assignment (`KEY=value`, optionally prefixed
  by `export`) — high. Filenames ending exactly in lowercase `.example`, `.sample`,
  `.template`, or `.dist` are exempt from this configuration check. This exemption
  does not suppress secret-pattern scanning: a credential-shaped value in an
  otherwise eligible template file can still produce a secret finding and trip
  `--fail-on`. Template filenames do not certify that their contents are safe.
  This check reports one finding per file, at the first matching assignment;
  empty values and public settings such as `PORT=8080` also count. It checks
  assignment presence, not whether the value is a secret. Such a file can have
  zero secret hits and still fail `--fail-on high`, including with `--triage`.
  Assignment names must be unquoted ASCII identifiers: a letter or underscore,
  followed by letters, digits or underscores. Leading whitespace and whitespace
  before `=` are accepted; the optional `export` prefix must be lowercase and
  followed by spaces or tabs. Quoted names, dotted or hyphenated names, names
  starting with a digit, and non-ASCII names do not match this config rule;
  a later matching assignment can still be reported. This is a line-based
  presence check: it does not parse multiline quoted values, evaluate shell
  commands or expand variables. Independent secret-pattern scanning still applies.
* `Dockerfile` (or `Dockerfile.*`) with no `USER` instruction —
  low, runtime user unverified (the base image may set `USER`; the scanner does not
  inspect images).
* `Dockerfile` with `ADD http(s)://…` — low.
* `Dockerfile` (or `Dockerfile.*`) whose final stage's last explicit `USER`
  is `root` or `0`, optionally with a group suffix — low. Earlier stages and
  overridden users do not trigger this check; inherited users and variables
  are not resolved.
* `Dockerfile` base images with no tag or with `:latest` — low. Non-latest tagged images,
  full SHA-256 digest references, `scratch`, earlier stage aliases and image
  references containing `$` are excluded. A tag is not a guarantee of immutability.
  Every `FROM` is checked, including unused build stages; leading `--name=value`
  options such as `--platform=linux/amd64` are skipped. A registry port does not
  count as a tag: `registry.example.invalid:5000/team/app` is flagged. The `latest`
  tag comparison is case-sensitive (`:Latest` is excluded); `scratch` and earlier
  stage aliases are compared case-insensitively. The digest exclusion recognizes
  an `@sha256:` suffix with exactly 64 hexadecimal characters without verifying
  image existence, digest integrity or trust. This is not a digest validator:
  a non-latest tag can independently exclude a reference with a malformed digest.
  Variables and stage dependencies are not resolved. Each matching instruction
  produces one finding at its starting line, with the image reference omitted.
* `Dockerfile` `ENV` / `ARG` assignments to secret-like variable names — high.
  Names such as `API_TOKEN` and `DB_PASSWORD` match; empty values, bare `ARG`
  declarations and whole-value `$VAR` / `${VAR}` references are excluded.
  Names must use ASCII letters, digits and underscores, starting with a letter
  or underscore. Matching is case-insensitive: `PASSWORD`, `PASSWD`, `SECRET`,
  `TOKEN`, `API_KEY`, `PRIVATE_KEY`, `SECRET_KEY` or `SECRET_ACCESS_KEY` must be
  the whole name or its suffix after an underscore. `MYTOKEN`, `TOKEN_FILE`,
  `PASSWORD_HASH`, `APIKEY` and bare `KEY` do not match this config rule.
  Both `ENV NAME=value` and legacy `ENV NAME value` forms are checked; multiple
  `NAME=value` assignments in one instruction are checked independently.
  After quote handling, only an empty value or a whole simple variable reference
  is exempt: `${VAR:-demo}`, `${VAR}/suffix` and `prefix$VAR` remain findings.
  Short values and placeholders such as `demo`, `changeme` and `xxxx` also remain
  high-severity config findings; secret-pattern placeholder downgrades do not
  apply to this rule. With `--triage` they still require `review` and can trip
  `--fail-on high`, even with zero secret hits. Evidence omits the assigned value.
  This is a name/value heuristic, not validation of a credential or evaluation
  of Docker variable expansion; no finding does not establish a safe value.
  Instructions in earlier stages also count; reported locations use the first
  line of a continued instruction, and evidence omits the value. An excluded
  assignment is not a guarantee that other scanner rules ignore its contents.
* Shell-form `Dockerfile` `RUN` with `curl` directly piped to `sh` or `bash` —
  medium. JSON exec-form instructions and indirect shell execution are not
  analyzed. This flags the command shape without fetching or running anything.
  Dockerfile configuration checks use a bounded logical-instruction heuristic,
  not a full Dockerfile or shell parser. Backslash continuations (or backticks
  with a recognized `# escape=` directive) join physical lines; findings for a
  joined instruction point to its first physical line. Blank lines and full-line
  comments are skipped, including inside a continuation. Recognized named
  heredocs on `RUN`, `COPY`, and `ADD` skip their bodies and delimiter lines:
  instruction-looking text in a body is not checked as Dockerfile configuration.
  Simple unquoted or matching-quoted delimiter names are supported, including
  tab-stripping `<<-` and multiple delimiters; general shell syntax is not parsed.
  These exclusions apply only to configuration checks. The separate secret pass
  still examines eligible comment and heredoc-body lines, so those lines can
  produce secret findings and trip a severity gate.
* `docker-compose*.yml` / `docker-compose*.yaml` / `compose.yml` / `compose.yaml` containing a plain
  `privileged: true` declaration — medium. The key may be unquoted or enclosed in
  matching single or double quotes; the value must remain plain `true`.
  This line-based heuristic allows trailing
  comments, but ignores commented declarations, unrelated keys and longer scalar
  values such as `trueish`; it does not parse general YAML structure.
  Filename matching is case-sensitive, but the key and plain value are matched
  case-insensitively (for example, `"PRIVILEGED": TRUE`). Quoted values such as
  `privileged: "true"` and inline mappings such as `{privileged: true}` are ignored.
  Every matching line is reported, including in nested files, without checking
  service ancestry: a matching line under an extension or unrelated mapping can
  also be reported. A finding is a review prompt, not confirmation of effective
  container privileges; absence of a finding does not establish that a Compose
  file is unprivileged.
* `.github/workflows/*.y(a)ml` remote action or reusable workflow `uses:` refs
  that are not full 40-character hexadecimal commit SHAs — low. Includes
  `actions/*`; local `./` actions and `docker://` references are excluded.
  All workflow config checks select only direct children of `.github/workflows`
  relative to the scan target, with case-sensitive directory names and lowercase
  `.yml` or `.yaml` extensions. Files in subdirectories of `workflows`, workflows
  inside nested repositories, and files such as `build.YML` are not selected.
  Scanning a nested repository as the target selects its own `.github/workflows`
  children; scanning `.github/workflows` itself does not. Otherwise eligible
  files outside this selection still receive independent secret-pattern scanning.
  Absence of workflow config findings does not establish that a file was checked
  by these rules.
* Workflows triggered by `pull_request` with workflow/job `permissions:` declaring
  `write-all` or a scope set to `write` — medium. This flags requested permissions;
  job overrides, fork restrictions and repository policy can reduce actual access.
  The check counts explicit declarations without resolving inheritance or job
  overrides: workflow-level `write-all` is still reported when a job sets
  `permissions: {}` or `read-all`. Separate block-map scopes set to `write` each
  produce a finding; a simple inline permission map produces one finding even
  with multiple write scopes. Missing declarations do not infer permission
  defaults. This check requires `pull_request`; `pull_request_target` alone,
  `push`, and other triggers do not activate it. Absence of this finding does
  not establish read-only effective access.
* `pull_request_target` workflows where an `actions/checkout` step's `with.ref`
  uses `${{ github.event.pull_request.head.sha }}`,
  `${{ github.event.pull_request.head.ref }}`, or `${{ github.head_ref }}` — high.
  The checkout and ref must be in the same step; pinning the checkout action to a
  full commit SHA does not suppress this separate check. Matching is literal and
  case-sensitive, allows whitespace inside the expression braces, and also
  matches a supported expression embedded in a longer ref string. The scanner
  does not evaluate expressions: bracket notation such as
  `${{ github['head_ref'] }}`, indirect references such as `${{ env.SELECTED_REF }}`,
  and expressions containing operators such as `${{ github.head_ref || 'main' }}`
  do not match these forms. No finding therefore does not establish that the
  checkout ref is independent of PR input.
* `.npmrc` containing an exact unscoped or registry-scoped `_authToken` key
  followed by `=`, or a `password` line — high. The token key must begin the line
  after optional whitespace; spaces or tabs before `=` are accepted. Token markers
  inside other option names, values, or trailing comments do not count.
  `.pypirc` retains the exact `_authToken=` substring check and the anchored
  spaced-key form, as well as the `password` rule.
  In both files, `_authToken` matching is case-sensitive and requires `=`;
  `_AUTHTOKEN=x` and `_authToken: x` do not trigger this config check.
  The `password` key is case-insensitive, must begin the line after optional
  whitespace, and accepts `:` or `=` after optional whitespace (for example,
  `PassWord : x`). Names such as `db_password` and `password_extra` do not match.
  Ignored lines do not prevent a later qualifying line from being reported.
  These are scanner selection rules, not a full interpretation of package-manager
  configuration; independently eligible secret patterns can still be reported.
  Empty or whitespace-only `password=` / `password:` fields are ignored;
  later credential lines are still checked. Quoted values and inline comments
  after the delimiter remain nonempty for this conservative heuristic.
  In `.npmrc`, an unscoped or registry-scoped `_authToken` value consisting only
  of `${NAME}` (a variable name using letters, digits and underscores, starting
  with a letter or underscore) is excluded. Mixed literal/reference values are
  still flagged; environment variables are never read or expanded.
  This configuration check skips full-line `#` and `;` comments (including
  indented comments). Secret-pattern scanning still checks commented text.
  In each exact `.npmrc` or `.pypirc` file (including nested directories), this
  check emits only the first qualifying config finding per file, at that line's
  original line number, then stops checking that file. Skipped comments, empty
  passwords and supported `.npmrc` environment references allow a later match.
  This is not a count of credentials: later matching lines do not add config
  findings, while the separate secret scan can emit additional findings in the
  same file. Scan limits can also omit findings.

All config checks listed above are implemented.

For example, scanning this synthetic Dockerfile emits five config findings:
one low finding each for the base image and root user, one high finding each
for `ENV` and `ARG`, and one medium finding for the pipe. Assignment values and
the URL are omitted from their evidence. The scanner reads this as text; it
does not build the image or execute the commands.

```dockerfile
FROM alpine:latest
USER root
ENV API_TOKEN=synthetic-value
ARG DB_PASSWORD=synthetic-value
RUN curl https://example.invalid/install | sh
```

Dockerfile checks use a bounded instruction/shell heuristic, not a full Docker
parser or image inspection. Comments and supported heredoc bodies are ignored;
base-image metadata, variable expansion and runtime overrides are not resolved.

## Limits

* **Deterministic only.** Pure regex/parser matching plus OSV lookups. No LLM,
  no reachability analysis, no taint tracking.
* **Workflow checks are YAML heuristics**, limited to files directly in the scanned
  root's `.github/workflows/`. They understand block mappings, step lists, scalar/
  list/mapping event declarations and simple inline permission maps. Comments and
  literal/folded script bodies are ignored. Anchors/aliases, general flow mappings
  (including inline steps/checkout inputs), multiline quoted scalars and indirect
  expressions are not resolved; these forms may be missed. These checks are review
  prompts, not proof of exploitability or a complete workflow audit.
  Job and step `if:` conditions are not evaluated: even `if: false` or
  `if: ${{ false }}` does not suppress a matching declaration. For example, an
  unpinned checkout in a disabled step still produces the low-severity finding;
  a disabled PR job requesting write permissions still produces the medium one.
  These findings remain in JSON and triage and can trigger `--fail-on` at the
  corresponding threshold. They describe configuration text, not whether a job
  or step will execute.
  The unpinned-reference check recognizes remote `owner/repo[/path]@ref` values
  in step and reusable-workflow `uses:` declarations. Any exactly 40-character
  hexadecimal ref (uppercase or lowercase, even all zeros) passes this shape
  check; tags, branches, short hashes and non-hex refs produce the low-severity
  finding. It does not fetch the ref or verify commit existence, provenance or
  trust. Local `./` and `../` refs, `docker://` container refs and values without
  `@ref` are outside this check, so no pin finding does not establish their safety
  or validity. A full-shaped checkout SHA does not suppress the separate
  `pull_request_target` PR-head checkout finding, its review triage or its gate.
* **No false-positive review.** Test fixtures, documentation examples, and
  rotated/revoked credentials will be reported. The only heuristic filters are
  the path rules and the value-shape hints (v0.4.1) described above; a committed
  real credential with a plausible shape in a non-test path is never cleared.
* **No git history scan.** Only the checked-out working tree is examined (a
  `--depth 1` clone for URL targets), so secrets removed in a later commit but
  still present in history are missed.
* **Local scans do not honor `.gitignore` or restrict files to Git's index.**
  Untracked and ignored regular files are scanned too, subject to the scanner's
  directory/file exclusions and size/count limits. Findings in those files can
  trigger `--fail-on`; an ignored local file is not evidence that it was committed.
* **Directory exclusions apply at every depth below the scan target.** The exact,
  case-sensitive names are `.git`, `node_modules`, `vendor`, `dist`, `build`,
  `.venv`, `venv`, `__pycache__`, `.mypy_cache`, `.tox`, `.next`, and `target`.
  Their subtrees are omitted from dependency inventory, secret checks and config
  checks, even beneath a directory such as `src/`. Similar names (`Vendor`,
  `vendor-copy`, `myvenv`) and other dot-directories are not excluded by this rule.
  The explicitly selected target itself is not filtered by its basename: scanning
  `vendor/` directly examines its contents, while still excluding matching child
  directories. Excluded files do not count in `summary.files_scanned` and these
  exclusions do not set `summary.truncated`. An empty report and passing severity
  gate therefore do not establish coverage of excluded subtrees.
* Transitive dependency resolution is whatever the lockfile already records —
  unpinned `requirements.txt` lines (`>=`, `~=`, unpinned) are ignored entirely.
  Wildcard `==` versions (`demo==1.*`) are prefix ranges, not exact versions, and
  are skipped too, so they appear in neither inventory nor advisory queries.
  Requirements environment markers after `;` are discarded without evaluation:
  `demo==1.0; python_version < "0"` still contributes `demo` version `1.0` to
  inventory and, when enabled, advisory queries. Extras are stripped from names
  (`demo[fast]==1.0` becomes `demo==1.0`); they do not trigger extra dependency
  resolution. Duplicate package/version pins count once, while distinct pinned
  versions remain even under mutually exclusive markers. This is a static
  inventory, not the resolved installation for the current interpreter or platform.
* Go: the scanner queries the module paths and versions recorded in `go.mod`
  `require` entries (direct + indirect), not a resolved build list. It ignores
  `replace` and `exclude` directives: a replaced or excluded requirement still
  enters inventory and, when enabled, advisory lookup under its original path
  and version. Replacement targets are not followed or substituted; directives
  alone add no packages. No Go toolchain or module-graph resolution is run.
  `go.sum` is only read when no `go.mod` sits beside it, because it also records
  superseded module versions (v0.4 — the 2026-10-08 dataset showed 99% of
  `go.sum` hits were not in `go.mod`). No call-graph reachability: use
  `govulncheck` for that.
* Yarn v1 and Yarn Berry (v2+) lockfiles are parsed (Berry since v0.4; workspace/
  patch/portal entries are skipped). `composer.lock`, Maven/Gradle and NuGet are not.
* `summary.lockfiles_parsed` lists supported, readable manifests whose parser
  returned normally, even if it returned no packages. Empty files, unpinned
  requirements and some malformed inputs (such as invalid package-lock JSON)
  can appear here without an `errors` entry. A nonempty list does not establish
  syntax validity, package discovery or advisory lookup success. Unsupported
  files and manifests over the 8 MiB read limit are omitted. The "No supported
  dependency manifest was parsed" note appears only when this list is empty;
  check `summary.packages_found`, `summary.osv_enabled` and `errors` as well.
  Dependency hits whose lockfile
  sits under a test/fixture/example/benchmark path are tagged `scaffold` by
  `--triage` (low priority), and a package listed in both a fixture and a shipped
  lockfile is attributed to the shipped one.
* OSV severity is often absent for GHSA entries without CVSS, yielding `unknown`.
* Secret detection is line-oriented except for complete multiline private-key
  blocks with matching labels and the header/next-line fallback described above.
  An incomplete block can still produce a critical fallback finding. PEM metadata
  lines, escaped newlines and other multiline encoded blobs are not parsed. Block
  bodies are checked for base64 shape, not decoded or cryptographically validated;
  synthetic examples can match.

## Dockerfile checks

For `Dockerfile` and `Dockerfile.*`, config findings also cover:

* `ADD` with an HTTP(S) source, including JSON operands and leading options — low.
  URLs are omitted from evidence, including user info and query strings.
  The check matches literal `http://` or `https://` prefixes case-insensitively
  in source operands (all operands except the last, treated as the destination).
  It emits one finding per instruction, even with multiple remote sources.
  Leading `--name=value` options, including `--checksum`, do not suppress it:
  a checksum-pinned HTTP(S) source still receives the same low-severity review
  finding and can trip `--fail-on low`. Checksums and downloaded contents are
  not validated. Local paths, Git/SSH/FTP forms, and `$SOURCE` / `${SOURCE}`
  references do not match this rule; variables are not expanded. A URL appearing
  only as the destination does not match either. This is a source-shape check,
  not validation of Docker syntax or a claim that a download is unverified.
* Shell-form `RUN` directly piping `curl` into `sh` or `bash` — medium.
  The check compares command basenames, so `/usr/bin/curl ... | /bin/sh`
  also matches, including after `;`, `&&` or `||`. It emits at most one
  pipeline finding per `RUN`. The pipe must be a single `|` token; `|&`,
  intervening commands, wrappers such as `env`/`sudo`, and assignments before
  `curl` are not recognized. Quoting is removed during tokenization, so a
  quoted argument whose entire value is `|` can also trigger this heuristic
  (for example `RUN curl '|' sh`); a finding does not establish that the shell
  executes a pipeline. Scripts and URLs are never fetched or executed.
* `ENV`/`ARG` assignments with nonempty values and secret-like variable names
  (for example `API_TOKEN`, `DB_PASSWORD`, `PRIVATE_KEY`, `AWS_SECRET_ACCESS_KEY`)
  — high. Only names are reported. Unset arguments, empty values and plain
  `$NAME`/`${NAME}` references are excluded; synthetic/default values may still
  be flagged. This is a configuration warning, not credential validation.
* `FROM` with an explicit `:latest` or no tag — low. Digest-pinned images,
  `scratch`, prior build-stage names and variable-based references are excluded.
* The last `USER` in the final stage explicitly sets `root` or UID `0`, optionally
  with a literal group (`root:app`, `0:1000`) — low. Earlier stages and overridden
  users are excluded. Variable-based users, inherited image users, and user-name
  to UID mappings are not resolved; a root group alone does not trigger this check.
  The check matches the literal, case-sensitive instruction value: `ROOT`, `00`,
  quoted `"root"`, and `root # comment` are not recognized as explicit root.
  A group suffix must be nonempty and contain only ASCII letters, digits,
  underscores, periods or hyphens. These exclusions do not establish a non-root
  runtime identity.

The missing-`USER` rule emits one low finding with a null source line only when
no parsed `USER` instruction appears anywhere in the file. For example,
`FROM scratch AS builder`, `USER root`, then `FROM builder` produces neither
USER finding: the earlier instruction suppresses the whole-file missing-user
check, while the final stage has no explicit user to match. The scanner does not
resolve user inheritance from a prior stage or an image. For an explicit final
root user continued across lines, the finding points to the first physical line.

These are bounded syntax heuristics. Continuations retain the first physical
line number, comments and simple named heredoc bodies are skipped, and malformed
quoted instructions are ignored. Heredoc scripts, exec-form shell commands,
indirect pipelines, variable expansion, custom shells and full Dockerfile/shell
grammar are not evaluated. The existing missing-`USER` check considers the whole
file, not each stage. Findings are review prompts, not proof of a vulnerable build.

## Datasets

Published runs of this scanner over sets of public repositories, with pinned commits and the
scripts to reproduce them, live under [`datasets/`](datasets/):

* [`2026-10-08-popular-oss`](datasets/2026-10-08-popular-oss/) — 25 popular repos across npm,
  PyPI, Go, crates.io and RubyGems; what the raw counts get wrong (`go.sum` ghosts, fixture
  lockfiles, unknown severities, secret-regex noise) and the scanner fixes that follow from it.

## Beyond this scanner

The paid tier is a three-pass AI review of what pattern matching cannot see
(auth and injection flaws, logic bugs, race conditions) in one GitHub or GitLab
repository, public or private: the $49 Codebase Audit
Report for repositories up to about 50k lines, and deep audits with reproductions
from $149: <https://project-feldspar.com/?utm_source=github-readme&utm_medium=referral&utm_campaign=st1> (prices plus any tax at checkout).
Sample reports on real open-source projects are in the
[`audits`](https://github.com/project-feldspar-resources/audits) repository.

## Terms

This scanner, the hosted scan at `/scan/`, its API, the MCP endpoint and this
GitHub Action are free tools provided under section 2.5 of the L3Digital Standard
Commercial Terms v1.1: <https://project-feldspar.com/terms/v1.1#s2-5> (as is, no
warranty or support commitment; use them only on code you may lawfully scan).
The code itself stays MIT-licensed (below). Privacy notice for the hosted
service: <https://project-feldspar.com/privacy>.

## License

MIT. Copyright (c) 2026 Project Feldspar. Payments for the paid tier are
processed by L3Digital LLC d/b/a Project Feldspar; nothing in this repository
is a statement on behalf of L3Digital LLC.
