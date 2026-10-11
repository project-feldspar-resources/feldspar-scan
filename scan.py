#!/usr/bin/env python3
"""feldspar-discovery-scan: deterministic, dependency-free repo scanner.

Usage: scan.py <local-repo-path-or-git-https-url> [--json out.json] [--no-osv]
               [--fail-on SEV] [--triage]

  --fail-on SEV   exit 1 when any finding is at or above SEV (critical|high|medium|low).
                  "unknown"-severity findings never trigger the gate.
  --triage        add a deterministic interpretation layer (top-level "triage" +
                  "triage_summary"): classifies secret hits in test/fixture/example
                  paths as likely false positives, and marks each dependency advisory
                  as upgrade (patch available) or monitor (no patched release yet).
                  Discovers nothing and adds no findings, so the raw findings set and
                  manifest_hash are unchanged; triage is a separate, additive section.
                  v0.4: dependency hits from lockfiles under test/fixture/example/benchmark
                  paths are tagged scaffold (low priority).

v0.4 (2026-10-08, from the 25-repo dataset in datasets/): go.mod is the Go build list and is
preferred over go.sum (which lists superseded versions too); Yarn Berry lockfiles are parsed;
`summary.lockfiles_parsed` + a `summary.notes` warning when no manifest was parsed; URL values
are never reported as hardcoded secrets.
v0.4.1 (2026-10-08): second secret heuristic beyond paths — value-shape hints (template/env
references, localized text, dotted identifier names, digit-less word-like values, form
placeholders, documented example keys and masked values) tag the evidence `(hint?)`, drop the raw
severity to low and are classified likely-false-positive by --triage; translation-catalogue paths
(locales/, i18n/, …) and __fixtures__/__mocks__/testutils paths likewise.
v0.4.2 (2026-10-08): Yarn Berry `pkg@patch:pkg@npm:…` / `workspace:` entries were split at the
last "@", so the skip-protocol check never saw them and a bogus `pkg@patch:pkg` package was emitted;
fixed (split after the scoped name). Regression tests in tests/ (python3 -m unittest discover -s tests).
"""
import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
import urllib.error
import urllib.request
from datetime import datetime, timezone

try:
    import tomllib
except ImportError:  # pragma: no cover - py<3.11
    tomllib = None

SCANNER = "feldspar-discovery-scan"
VERSION = "0.4.3"
OSV_BATCH = "https://api.osv.dev/v1/querybatch"
OSV_VULN = "https://api.osv.dev/v1/vulns/"
HTTP_TIMEOUT = 20
SKIP_DIRS = {".git", "node_modules", "vendor", "dist", "build", ".venv", "venv",
             "__pycache__", ".mypy_cache", ".tox", ".next", "target"}
BIN_EXT = {".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".pdf", ".zip", ".gz",
           ".tgz", ".bz2", ".xz", ".7z", ".jar", ".class", ".so", ".dylib", ".dll",
           ".exe", ".woff", ".woff2", ".ttf", ".eot", ".mp3", ".mp4", ".wasm", ".pyc"}
LOCKFILES = {"package-lock.json", "yarn.lock", "pnpm-lock.yaml", "poetry.lock",
             "uv.lock", "Cargo.lock", "Gemfile.lock", "go.sum", "go.mod", "composer.lock"}
MAX_TEXT = 1024 * 1024
SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}
ERRORS = []
PARSED_LOCKFILES = []   # relative paths of dependency manifests actually parsed (v0.4; summary.lockfiles_parsed)


# ---------------------------------------------------------------- utilities
def walk(root):
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for fn in filenames:
            yield os.path.join(dirpath, fn)


def read_text(path, limit=MAX_TEXT):
    try:
        if os.path.getsize(path) > limit:
            return None
        with open(path, "rb") as fh:
            raw = fh.read(limit)
    except OSError:
        return None
    if b"\x00" in raw:
        return None
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        try:
            return raw.decode("latin-1")
        except Exception:
            return None


def redact(value, n=4):
    value = value.strip()
    return value[:n] + "…" if len(value) > n else value + "…"


# ------------------------------------------------------------ dep parsers
def parse_requirements(text):
    out = []
    for line in text.splitlines():
        line = line.split("#", 1)[0].strip()
        if not line or line.startswith("-"):
            continue
        line = line.split(";", 1)[0].strip()
        if "==" not in line:
            continue
        name, _, ver = line.partition("==")
        name = re.split(r"[\[<>!~ ]", name.strip())[0].strip()
        ver = ver.strip().strip('"\'')
        if name and re.match(r"^[0-9][^\s,=<>!]*$", ver):
            out.append(("PyPI", name, ver))
    return out


def parse_toml_packages(text, ecosystem):
    out = []
    if tomllib:
        try:
            data = tomllib.loads(text)
            for pkg in data.get("package", []) or []:
                n, v = pkg.get("name"), pkg.get("version")
                if n and v:
                    out.append((ecosystem, n, str(v)))
            return out
        except Exception:
            pass
    name = ver = None
    for line in text.splitlines():
        s = line.strip()
        if s == "[[package]]":
            name = ver = None
        m = re.match(r'^name\s*=\s*"([^"]+)"', s)
        if m:
            name = m.group(1)
        m = re.match(r'^version\s*=\s*"([^"]+)"', s)
        if m:
            ver = m.group(1)
        if name and ver:
            out.append((ecosystem, name, ver))
            name = ver = None
    return out


def parse_package_lock(text):
    out = []
    try:
        data = json.loads(text)
    except Exception:
        return out
    pkgs = data.get("packages")
    if isinstance(pkgs, dict):
        for key, meta in pkgs.items():
            if not key or not isinstance(meta, dict):
                continue
            ver = meta.get("version")
            if "node_modules/" in key:
                name = key.rsplit("node_modules/", 1)[1]
            else:
                continue
            if name and ver:
                out.append(("npm", name, str(ver)))
    deps = data.get("dependencies")
    if isinstance(deps, dict) and not out:
        def rec(d):
            for name, meta in d.items():
                if isinstance(meta, dict):
                    if meta.get("version"):
                        out.append(("npm", name, str(meta["version"])))
                    if isinstance(meta.get("dependencies"), dict):
                        rec(meta["dependencies"])
        rec(deps)
    return out


YARN_SKIP_PROTOCOLS = {"workspace", "patch", "portal", "link", "file", "exec", "git", "github", "http", "https"}


def parse_yarn_lock(text):
    """Yarn v1 (`name@^1.0.0:` / `  version "1.0.0"`) and Yarn Berry v2+ (`"name@npm:^1.0.0":` /
    `  version: 1.0.0`, `__metadata:` header). Workspace/patch/portal entries are not registry packages
    and are skipped (v0.4 — before this, Berry lockfiles silently yielded 0 packages)."""
    out = []
    names = []
    for line in text.splitlines():
        if line.startswith("__metadata"):
            names = []
            continue
        if line and not line.startswith((" ", "\t", "#")) and line.rstrip().endswith(":"):
            names = []
            spec = line.rstrip()[:-1]
            for part in spec.split(","):
                part = part.strip().strip('"')
                if not part:
                    continue
                # split at the FIRST "@" after the (possibly @scoped/) name: a Berry
                # `pkg@patch:pkg@npm:1.0#…` entry has several, and rfind took the last one,
                # which hid the patch: protocol and emitted `pkg@patch:pkg` as a package (v0.4.2)
                at = part.find("@", 1)
                if at > 0:
                    rng = part[at + 1:]
                    proto = rng.split(":", 1)[0] if ":" in rng else None
                    if proto in YARN_SKIP_PROTOCOLS:
                        continue
                    names.append(part[:at])
        else:
            m = re.match(r'^\s+version:?\s+"?([^"\s]+)"?', line)
            if m and names:
                ver = m.group(1)
                if re.match(r"^\d", ver):
                    for n in dict.fromkeys(names):
                        out.append(("npm", n, ver))
                names = []
    return out


def parse_pnpm_lock(text):
    out = []
    in_pkgs = False
    for line in text.splitlines():
        if re.match(r"^packages:\s*$", line):
            in_pkgs = True
            continue
        if in_pkgs and line and not line.startswith((" ", "\t")):
            in_pkgs = False
        if not in_pkgs:
            continue
        m = re.match(r"^\s{2}'?(/?[^:'\s]+)'?:\s*$", line)
        if not m:
            continue
        key = m.group(1).lstrip("/")
        key = key.split("(", 1)[0]
        at = key.rfind("@")
        if at <= 0:
            continue
        name, ver = key[:at], key[at + 1:]
        if re.match(r"^\d", ver):
            out.append(("npm", name, ver))
    return out


def parse_go_sum(text):
    """go.sum lists EVERY module version the module graph ever touched, including superseded ones
    (dataset 2026-10-08: 1,089 of 1,099 vulnerable go.sum rows were not in go.mod). It is only used
    when no go.mod sits beside it (v0.4); prefer parse_go_mod."""
    out = []
    for line in text.splitlines():
        parts = line.split()
        if len(parts) < 2:
            continue
        mod, ver = parts[0], parts[1]
        if ver.endswith("/go.mod"):
            ver = ver[: -len("/go.mod")]
        if mod and ver.startswith("v"):
            out.append(("Go", mod, ver))
    return out


def parse_go_mod(text):
    """The `require` set of go.mod = the module's build list (direct + `// indirect`, Go 1.17+)."""
    out = []
    in_req = False
    for line in text.splitlines():
        s = line.split("//", 1)[0].strip()
        if not s:
            continue
        if s.startswith("require ("):
            in_req = True
            continue
        if in_req and s == ")":
            in_req = False
            continue
        m = None
        if in_req:
            m = re.match(r"^(\S+)\s+(v\S+)$", s)
        elif s.startswith("require "):
            m = re.match(r"^require\s+(\S+)\s+(v\S+)$", s)
        if m:
            out.append(("Go", m.group(1), m.group(2)))
    return out


def parse_gemfile_lock(text):
    out = []
    in_specs = False
    for line in text.splitlines():
        if re.match(r"^\s{2}specs:\s*$", line):
            in_specs = True
            continue
        if line and not line.startswith(" "):
            in_specs = False
        if not in_specs:
            continue
        m = re.match(r"^\s{4}([A-Za-z0-9_.\-]+) \(([^)]+)\)\s*$", line)
        if m:
            out.append(("RubyGems", m.group(1), m.group(2)))
    return out


DEP_HANDLERS = {
    "requirements.txt": parse_requirements,
    "poetry.lock": lambda t: parse_toml_packages(t, "PyPI"),
    "uv.lock": lambda t: parse_toml_packages(t, "PyPI"),
    "Cargo.lock": lambda t: parse_toml_packages(t, "crates.io"),
    "package-lock.json": parse_package_lock,
    "yarn.lock": parse_yarn_lock,
    "pnpm-lock.yaml": parse_pnpm_lock,
    "go.sum": parse_go_sum,
    "go.mod": parse_go_mod,
    "Gemfile.lock": parse_gemfile_lock,
}


def collect_packages(root, files):
    seen = {}
    gomod_dirs = {os.path.dirname(p) for p in files if os.path.basename(p) == "go.mod"}
    for path in files:
        base = os.path.basename(path)
        handler = DEP_HANDLERS.get(base)
        if handler is None and base.startswith("requirements") and base.endswith(".txt"):
            handler = parse_requirements
        if handler is None:
            continue
        if base == "go.sum" and os.path.dirname(path) in gomod_dirs:
            continue  # go.mod beside it is the build list; go.sum also records superseded versions
        text = read_text(path, 8 * 1024 * 1024)
        if text is None:
            continue
        try:
            pkgs = handler(text)
        except Exception as exc:
            ERRORS.append("parse %s: %s" % (os.path.relpath(path, root), exc))
            continue
        rel = os.path.relpath(path, root)
        PARSED_LOCKFILES.append(rel)
        scaffold = bool(TEST_PATH_RE.search(rel))
        for eco, name, ver in pkgs:
            key = (eco, name, ver)
            prev = seen.get(key)
            # attribute a package@version to a shipped lockfile over a fixture/example one when both list it
            if prev is None or (not scaffold and TEST_PATH_RE.search(prev)):
                seen[key] = rel
    return seen


# ------------------------------------------------------------------- OSV
def http_json(url, payload=None):
    data = json.dumps(payload).encode() if payload is not None else None
    req = urllib.request.Request(
        url, data=data,
        headers={"Content-Type": "application/json", "User-Agent": SCANNER + "/" + VERSION})
    with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT) as resp:
        return json.loads(resp.read().decode())


def sev_from_score(score):
    try:
        s = float(score)
    except (TypeError, ValueError):
        return None
    if s >= 9:
        return "critical"
    if s >= 7:
        return "high"
    if s >= 4:
        return "medium"
    return "low"


CVSS_SEV = {"CRITICAL": "critical", "HIGH": "high", "MODERATE": "medium",
            "MEDIUM": "medium", "LOW": "low"}


def parse_cvss_score(vector):
    # CVSS v3 vectors sometimes appear as raw scores in OSV `severity[].score`.
    m = re.match(r"^\d+(\.\d+)?$", str(vector).strip())
    return float(m.group(0)) if m else None


def vuln_details(vid, cache):
    if vid in cache:
        return cache[vid]
    info = {"severity": "unknown", "fixed_in": [], "summary": vid}
    try:
        v = http_json(OSV_VULN + vid)
    except Exception as exc:
        ERRORS.append("osv vuln %s: %s" % (vid, exc))
        cache[vid] = info
        return info
    info["summary"] = (v.get("summary") or (v.get("details") or "").split("\n")[0] or vid)[:200]
    ds = (v.get("database_specific") or {}).get("severity")
    if isinstance(ds, str) and ds.upper() in CVSS_SEV:
        info["severity"] = CVSS_SEV[ds.upper()]
    if info["severity"] == "unknown":
        for s in v.get("severity") or []:
            score = parse_cvss_score(s.get("score", ""))
            mapped = sev_from_score(score) if score is not None else None
            if mapped:
                info["severity"] = mapped
                break
    fixed = []
    for aff in v.get("affected") or []:
        for rng in aff.get("ranges") or []:
            for ev in rng.get("events") or []:
                if ev.get("fixed"):
                    fixed.append(ev["fixed"])
    info["fixed_in"] = sorted(dict.fromkeys(fixed))[:10]
    cache[vid] = info
    return info


def query_osv(packages):
    """packages: list of (eco, name, ver). Returns {(eco,name,ver): [vuln_ids]}"""
    result = {}
    keys = list(packages)
    for i in range(0, len(keys), 500):
        chunk = keys[i:i + 500]
        payload = {"queries": [
            {"package": {"name": n, "ecosystem": e}, "version": v} for (e, n, v) in chunk]}
        try:
            resp = http_json(OSV_BATCH, payload)
        except Exception as exc:
            ERRORS.append("osv querybatch: %s" % exc)
            continue
        for key, res in zip(chunk, resp.get("results") or []):
            ids = [x.get("id") for x in (res.get("vulns") or []) if x.get("id")]
            if ids:
                result[key] = ids
    return result


# --------------------------------------------------------------- secrets
# v0.4.1 value-shape hints. From the 2026-10-08 dataset (datasets/2026-10-08-popular-oss):
# of the 313 secret hits the path/placeholder rule left for review, roughly two thirds were
# template or env-variable references (`={{$credentials.apiKey}}`, `$__env{…}`, `#{…}`,
# `var(--…)`), localized UI strings, syntax-highlighter scope names (`token: 'entity.name'`)
# or AWS/Slack example values inside form `placeholder=` attributes. Each hint is appended
# to the (redacted) evidence as `(hint?)` and downgrades the raw severity to low; triage
# reads the same hints. A hint is a shape judgement, not proof — it never deletes a finding.
VALUE_HINTS = {
    "placeholder?": "value looks like a placeholder, not a real secret",
    "expression?": "value is a template/env-variable reference, not a literal credential",
    "non-ascii?": "value contains non-ASCII text (localized string or masked value); credentials are ASCII",
    "dotted-name?": "value is a dotted identifier with no digits (highlighter scope / flag / host name)",
    "form-placeholder?": "match sits in a form placeholder attribute (example text shown to users)",
    "example-key?": "value is a documented example key or an x/0/* masked pattern",
    "word-like?": "value is letters/underscores/hyphens only, no digits (constant name, enum value or field key)",
}
EXPR_RE = re.compile(r"^(=?\{\{|\$\{|\$__|\$[A-Za-z_]|\{env:|#\{|%\{|%\(|<%|var\(|@\{)")
DOTTED_RE = re.compile(r"^[A-Za-z_][A-Za-z_-]*(\.[A-Za-z_][A-Za-z_-]*)+$")
WORD_RE = re.compile(r"^[A-Za-z][A-Za-z_-]*$")
EXAMPLE_KEYS = {
    "AKIAIOSFODNN7EXAMPLE", "AKIAI44QH8DHBEXAMPLE",          # AWS documentation keys
    "ghp_16C7e42F292c6912E7710c838347Ae178B4a",               # GitHub docs example token
}
MASKED_RE = re.compile(r"x{6,}|X{6,}|0{8,}|\*{4,}|EXAMPLE")
PLACEHOLDER_ATTR_RE = re.compile(r"placeholder\s*[:=]\s*[{'\"]", re.I)


def _value_hint(value, line_prefix=""):
    """Shape hint for a generic `key = "value"` hit (None = looks like a literal credential)."""
    if re.search(r"example|changeme|your[_-]|xxx|dummy|placeholder|<|\$\{", value, re.I):
        return "placeholder?"
    if any(ord(c) > 127 for c in value):
        return "non-ascii?"
    if EXPR_RE.match(value):
        return "expression?"
    if DOTTED_RE.match(value):
        return "dotted-name?"
    if MASKED_RE.search(value):
        return "example-key?"
    if WORD_RE.match(value):
        # home-assistant dataset: `ATTR_TOKEN = "long_lived_access_token"`, growatt field names,
        # header names — identifiers, not credentials (random credentials carry digits)
        return "word-like?"
    if PLACEHOLDER_ATTR_RE.search(line_prefix[-40:]):
        return "form-placeholder?"
    return None


def _pattern_hint(matched, line_prefix=""):
    """Shape hint for a fixed-pattern hit (AWS/Slack/GitHub…): documented example or masked value."""
    if matched in EXAMPLE_KEYS or MASKED_RE.search(matched):
        return "example-key?"
    if PLACEHOLDER_ATTR_RE.search(line_prefix[-40:]):
        return "form-placeholder?"
    return None


def _generic_sev(match_value, line_prefix=""):
    note = _value_hint(match_value, line_prefix)
    return ("low", note) if note else ("medium", None)


SECRET_PATTERNS = [
    ("aws-access-key-id", re.compile(r"AKIA[0-9A-Z]{16}"), "high", "AWS access key ID"),
    ("github-token", re.compile(r"gh[pousr]_[A-Za-z0-9]{36,}"), "high", "GitHub token"),
    ("github-pat", re.compile(r"github_pat_[A-Za-z0-9_]{80,}"), "high", "GitHub fine-grained PAT"),
    ("slack-token", re.compile(r"xox[baprs]-[0-9A-Za-z-]{10,}"), "high", "Slack token"),
    ("stripe-live-key", re.compile(r"sk_live_[0-9a-zA-Z]{24,}"), "critical", "Stripe live secret key"),
    ("google-api-key", re.compile(r"AIza[0-9A-Za-z_\-]{35}"), "medium", "Google API key"),
    ("private-key", re.compile(r"-----BEGIN (RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----"),
     "critical", "Private key block"),
]
GENERIC = re.compile(
    r"""(?i)(api[_-]?key|secret|password|passwd|token)\s*[:=]\s*['"]([^'"\s]{16,})['"]""")


def scan_secrets(root, files, add):
    for path in files:
        base = os.path.basename(path)
        ext = os.path.splitext(base)[1].lower()
        if ext in BIN_EXT or base in LOCKFILES or base.endswith(".min.js"):
            continue
        text = read_text(path)
        if text is None:
            continue
        rel = os.path.relpath(path, root)
        lines = text.splitlines()
        for lineno, line in enumerate(lines, 1):
            if len(line) > 4000:
                continue
            for pid, rx, sev, desc in SECRET_PATTERNS:
                m = rx.search(line)
                if m:
                    if pid == "private-key":
                        # a real PEM block is followed by a base64 body line; a header inside
                        # source code (regex/validator/test string) is not a leaked key
                        nxt = lines[lineno] if lineno < len(lines) else ""
                        if not re.match(r"^\s*[A-Za-z0-9+/=]{20,}\s*$", nxt):
                            continue
                    ev = redact(m.group(0))
                    if pid != "private-key":
                        note = _pattern_hint(m.group(0), line[:m.start()])
                        if note:  # v0.4.1: AWS docs key / masked xoxb-xxxx… / form placeholder
                            sev = "low"
                            ev += " (%s)" % note
                    add("secret", sev, rel, lineno, summary=desc + " detected", evidence=ev)
            gm = GENERIC.search(line)
            if gm and re.match(r"^(https?|wss?)://", gm.group(2), re.I):
                gm = None  # `OAUTH2_TOKEN = "https://…"` is an endpoint URL, not a credential (v0.4)
            if gm:
                sev, note = _generic_sev(gm.group(2), line[:gm.start(2)])
                ev = redact(gm.group(2))
                if note:
                    ev += " (%s)" % note
                add("secret", sev, rel, lineno,
                    summary="Hardcoded %s assignment" % gm.group(1).lower(), evidence=ev)


# ---------------------------------------------------------------- config
def scan_config(root, files, add):
    for path in files:
        base = os.path.basename(path)
        rel = os.path.relpath(path, root)
        text = None

        def body():
            nonlocal text
            if text is None:
                text = read_text(path) or ""
            return text

        if (base == ".env" or base.startswith(".env.")) and not re.search(r"\.(example|sample|template|dist)$", base):
            for lineno, line in enumerate(body().splitlines(), 1):
                s = line.strip()
                if s and not s.startswith("#") and re.match(r"^[A-Za-z_][A-Za-z0-9_]*\s*=", s):
                    add("config", "high", rel, lineno,
                        summary="Committed .env file with assignments",
                        evidence=redact(s.split("=", 1)[0]) + "=…")
                    break
        if base == "Dockerfile" or base.startswith("Dockerfile."):
            lines = body().splitlines()
            if not any(re.match(r"^\s*USER\s+\S", l, re.I) for l in lines):
                add("config", "low", rel, None,
                    summary="Dockerfile has no USER instruction (runs as root)",
                    evidence="no USER directive")
            for lineno, line in enumerate(lines, 1):
                if re.match(r"^\s*ADD\s+https?://", line, re.I):
                    add("config", "low", rel, lineno,
                        summary="Dockerfile uses ADD with a remote URL",
                        evidence=line.strip()[:80])
        if re.match(r"^docker-compose.*\.ya?ml$", base) or base == "compose.yml":
            for lineno, line in enumerate(body().splitlines(), 1):
                if re.search(r"privileged:\s*true", line, re.I):
                    add("config", "medium", rel, lineno,
                        summary="docker-compose service runs privileged",
                        evidence="privileged: true")
        if os.sep + os.path.join(".github", "workflows") + os.sep in path + os.sep and \
                base.endswith((".yml", ".yaml")):
            t = body()
            if "pull_request_target" in t and "actions/checkout" in t and \
                    "${{ github.event.pull_request.head" in t:
                lineno = next((i for i, l in enumerate(t.splitlines(), 1)
                               if "pull_request_target" in l), None)
                add("config", "high", rel, lineno,
                    summary="pwn request pattern: pull_request_target checks out PR head",
                    evidence="pull_request_target + actions/checkout of PR head")
        if base in (".npmrc", ".pypirc"):
            for lineno, line in enumerate(body().splitlines(), 1):
                if "_authToken=" in line or re.match(r"^\s*password\s*[:=]", line, re.I):
                    add("config", "high", rel, lineno,
                        summary="Credential committed in %s" % base,
                        evidence=redact(line.strip()))
                    break


# ---------------------------------------------------------------- triage
# Deterministic interpretation layer (the paid "snapshot" value-add, W233).
# It discovers nothing and adds no findings; it only classifies and prioritises
# the deterministic findings above. The raw findings set and manifest_hash stay
# the verifiable trust anchor; triage is a separate, additive section surfaced
# only with --triage. This automates the hand-triage done on the first $49
# fulfilment dry run (mealie, 2026-10-05): fix-status action + secret FP filter.
TEST_PATH_RE = re.compile(
    r"(^|/)(__)?(tests?|spec|specs|fixtures?|test-?data|testing|test-?utils?|testutils?|mocks?|"
    r"snapshots?|examples?|samples?|demos?|e2e|cypress|\.github|docs?|stories|bench|benchmarks?|"
    r"benchmark-apps)(__)?(/|$)", re.I)  # v0.4.1: __fixtures__/__mocks__/testutils (sentry) join
TEST_FILE_RE = re.compile(
    r"(\.(test|spec|stories)\.[a-z0-9]+$|_test\.[a-z0-9]+$|^test_|^test-?utils?\.|^conftest\.py$|"
    r"\.(example|sample|template|dist)$)", re.I)
# v0.4.1: translation catalogues (`config/locales/server.ja.yml: password: "…"`) are UI copy
LOCALE_PATH_RE = re.compile(r"(^|/)(locales?|i18n|lang|langs|translations?|l10n)(/|$)", re.I)


def _secret_false_positive(f):
    """Return (is_fp, reason) for a secret finding from path + evidence heuristics."""
    path = f.get("file") or ""
    base = path.rsplit("/", 1)[-1]
    m = TEST_PATH_RE.search(path)
    if m:
        return True, "in a test/fixture/example path (%s)" % m.group(3).lower()
    if TEST_FILE_RE.search(base):
        return True, "filename marks it as a test/example/template"
    m = LOCALE_PATH_RE.search(path)
    if m:
        return True, "in a localization path (%s): translated UI text, not a credential" % m.group(2).lower()
    ev = f.get("evidence") or ""
    for note, reason in VALUE_HINTS.items():  # written by scan_secrets at detection time
        if "(%s)" % note in ev:
            return True, reason
    return False, None


def _triage_headline(up, mon, sec_review, sec_fp, scaffold=0):
    parts = []
    if up:
        parts.append("%d dependency advisory/ies fixable by upgrade" % up)
    if mon:
        parts.append("%d dependency advisory/ies with no patch yet (monitor/mitigate)" % mon)
    if scaffold:
        parts.append("%d of the dependency hits are in example/fixture/benchmark lockfiles (low priority)" % scaffold)
    if sec_review:
        parts.append("%d secret hit(s) needing review" % sec_review)
    if sec_fp:
        parts.append("%d secret hit(s) classified likely-false-positive" % sec_fp)
    return "; ".join(parts) if parts else "no actionable findings after triage"


def triage_findings(findings):
    """Deterministic interpretation of the raw findings. Returns (per_id, summary)."""
    per_id = {}
    dep_upgrade = dep_monitor = dep_scaffold = 0
    sec_total = sec_fp = 0
    for f in findings:
        cat = f["category"]
        t = {}
        if cat == "dependency-vuln":
            fixed = f.get("fixed_in") or []
            if fixed:
                t = {"action": "upgrade", "upgrade_to": fixed,
                     "note": "Patched release available: upgrade %s to %s."
                             % (f.get("package"), " / ".join(fixed))}
                dep_upgrade += 1
            else:
                t = {"action": "monitor",
                     "note": ("No patched release published for the advisory yet; pin the "
                              "version, monitor the advisory, and apply any documented "
                              "mitigation. Not fixable by upgrade today.")}
                dep_monitor += 1
            lock = f.get("file") or ""
            m = TEST_PATH_RE.search(lock)
            if m:
                # dataset 2026-10-08: react 546/618 and next.js 120/366 vulnerable rows came from
                # lockfiles under fixtures/, tests/, benchmark dirs — scaffolds, not the shipped graph
                dep_scaffold += 1
                t["scaffold"] = True
                t["priority"] = "low"
                t["reason"] = ("lockfile under a %s path: example/fixture/benchmark scaffold, "
                               "not the shipped dependency graph" % m.group(3).lower())
            if lock.endswith("go.sum"):
                t["note"] += (" Source is go.sum without a go.mod beside it: go.sum also lists "
                              "superseded module versions; confirm with govulncheck.")
        elif cat == "secret":
            sec_total += 1
            is_fp, reason = _secret_false_positive(f)
            if is_fp:
                sec_fp += 1
                t = {"action": "informational", "likely_false_positive": True,
                     "reason": reason,
                     "note": "Likely not a live secret (%s); verify, but low priority." % reason}
            else:
                t = {"action": "review", "likely_false_positive": False,
                     "note": ("In a non-test path; confirm it is not a live credential and, "
                              "if real, rotate it and purge it from history.")}
        else:  # config / other
            t = {"action": "review"}
        per_id[f["id"]] = t
    summary = {
        "dependency": {"upgradeable": dep_upgrade, "monitor_only": dep_monitor,
                       "in_scaffold_lockfiles": dep_scaffold},
        "secrets": {"total": sec_total, "likely_false_positive": sec_fp,
                    "needs_review": sec_total - sec_fp},
        "headline": _triage_headline(dep_upgrade, dep_monitor, sec_total - sec_fp, sec_fp, dep_scaffold),
    }
    return per_id, summary


# ------------------------------------------------------------------ main
def git_head(path):
    try:
        out = subprocess.run(["git", "-C", path, "rev-parse", "HEAD"],
                             capture_output=True, text=True, timeout=30)
        return out.stdout.strip() or None if out.returncode == 0 else None
    except Exception:
        return None


def main(argv):
    args = argv[1:]
    if not args or args[0] in ("-h", "--help"):
        print(__doc__.strip())
        return 0
    target = args[0]
    out_path, use_osv, fail_on, triage = None, True, None, False
    i = 1
    while i < len(args):
        if args[i] == "--json" and i + 1 < len(args):
            out_path = args[i + 1]
            i += 2
        elif args[i] == "--no-osv":
            use_osv = False
            i += 1
        elif args[i] == "--triage":
            triage = True
            i += 1
        elif args[i] == "--fail-on" and i + 1 < len(args):
            fail_on = args[i + 1].lower()
            if fail_on not in SEV_ORDER:
                sys.stderr.write("--fail-on must be one of critical|high|medium|low\n")
                return 2
            i += 2
        else:
            sys.stderr.write("unknown arg: %s\n" % args[i])
            return 2
    if re.match(r"^(https?|git)://|^git@", target):
        root = tempfile.mkdtemp(prefix="fds-clone-")
        r = subprocess.run(["git", "clone", "--depth", "1", target, root],
                           capture_output=True, text=True, timeout=600)
        if r.returncode != 0:
            sys.stderr.write(r.stderr[-2000:])
            return 3
    else:
        root = os.path.abspath(target)
        if not os.path.isdir(root):
            sys.stderr.write("not a directory: %s\n" % root)
            return 2

    files = sorted(walk(root))
    findings = []

    def add(category, severity, file, line, summary, evidence,
            package=None, ecosystem=None, version=None, vuln_ids=None, fixed_in=None):
        findings.append({
            "id": None, "category": category, "severity": severity, "file": file,
            "line": line, "package": package, "ecosystem": ecosystem, "version": version,
            "vuln_ids": vuln_ids or [], "summary": summary, "evidence": evidence,
            "fixed_in": fixed_in or [],
        })

    pkgs = collect_packages(root, files)
    vulnerable = set()
    if use_osv and pkgs:
        hits = query_osv(list(pkgs.keys()))
        cache = {}
        # prefetch advisory details concurrently (wall time was dominated by serial GETs)
        from concurrent.futures import ThreadPoolExecutor
        all_ids = sorted({v for ids in hits.values() for v in ids})
        with ThreadPoolExecutor(max_workers=16) as ex:
            list(ex.map(lambda vid: vuln_details(vid, cache), all_ids))
        for key in sorted(hits):
            eco, name, ver = key
            vulnerable.add(key)
            details = [vuln_details(v, cache) for v in hits[key]]
            order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "unknown": 4}
            worst = min((d["severity"] for d in details), key=lambda s: order.get(s, 4))
            fixed = sorted({f for d in details for f in d["fixed_in"]})
            add("dependency-vuln", worst, pkgs[key], None,
                summary="%s %s has %d known vulnerability/ies (%s)"
                        % (name, ver, len(details), details[0]["summary"][:120]),
                evidence=", ".join(hits[key][:5]),
                package=name, ecosystem=eco, version=ver,
                vuln_ids=sorted(hits[key]), fixed_in=fixed)

    scan_secrets(root, files, add)
    scan_config(root, files, add)

    findings.sort(key=lambda f: ({"critical": 0, "high": 1, "medium": 2, "low": 3,
                                  "unknown": 4}.get(f["severity"], 4),
                                 f["category"], f["file"] or "", f["line"] or 0,
                                 f["package"] or "", f["summary"]))
    by_sev = {"critical": 0, "high": 0, "medium": 0, "low": 0, "unknown": 0}
    for n, f in enumerate(findings, 1):
        f["id"] = "F-%03d" % n
        by_sev[f["severity"]] = by_sev.get(f["severity"], 0) + 1

    commit = git_head(root)
    doc = {
        "scanner": SCANNER, "version": VERSION, "target": target, "commit": commit,
        "scanned_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "summary": {
            "files_scanned": len(files),
            "packages_found": len(pkgs),
            "vulnerable_packages": len(vulnerable),
            "secret_hits": sum(1 for f in findings if f["category"] == "secret"),
            "config_issues": sum(1 for f in findings if f["category"] == "config"),
            "by_severity": by_sev,
            "lockfiles_parsed": sorted(PARSED_LOCKFILES),
        },
        "findings": findings,
    }
    if not PARSED_LOCKFILES:
        # a zero must not read as "clean" (dataset 2026-10-08: 3 of 25 repos scanned 0 packages)
        doc["summary"]["notes"] = [
            "No supported dependency manifest was parsed, so dependency advisories were NOT assessed. "
            "Supported: package-lock.json, yarn.lock (v1 + Berry), pnpm-lock.yaml, poetry.lock, uv.lock, "
            "Cargo.lock, Gemfile.lock, go.mod (go.sum only without go.mod), requirements*.txt."]
    canon = json.dumps({"findings": findings, "target": target, "commit": commit},
                       sort_keys=True, separators=(",", ":"))
    doc["manifest_hash"] = hashlib.sha256(canon.encode()).hexdigest()
    if triage:
        per_id, tsummary = triage_findings(findings)
        doc["triage_summary"] = tsummary
        doc["triage"] = per_id
    if ERRORS:
        doc["errors"] = ERRORS
    text = json.dumps(doc, indent=2)
    if out_path:
        with open(out_path, "w") as fh:
            fh.write(text + "\n")
        sys.stderr.write("wrote %s (%d findings)\n" % (out_path, len(findings)))
    else:
        print(text)
    if fail_on is not None and any(
            SEV_ORDER.get(f["severity"], 99) <= SEV_ORDER[fail_on] for f in findings):
        sys.stderr.write("gate: findings at or above %s severity\n" % fail_on)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
