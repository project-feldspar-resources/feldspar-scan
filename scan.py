#!/usr/bin/env python3
"""feldspar-discovery-scan: deterministic, dependency-free repo scanner.

Usage: scan.py <local-repo-path-or-git-https-url> [--json out.json] [--no-osv] [--fail-on SEV]

  --fail-on SEV   exit 1 when any finding is at or above SEV (critical|high|medium|low).
                  "unknown"-severity findings never trigger the gate.
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
VERSION = "0.2"
OSV_BATCH = "https://api.osv.dev/v1/querybatch"
OSV_VULN = "https://api.osv.dev/v1/vulns/"
HTTP_TIMEOUT = 20
SKIP_DIRS = {".git", "node_modules", "vendor", "dist", "build", ".venv", "venv",
             "__pycache__", ".mypy_cache", ".tox", ".next", "target"}
BIN_EXT = {".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".pdf", ".zip", ".gz",
           ".tgz", ".bz2", ".xz", ".7z", ".jar", ".class", ".so", ".dylib", ".dll",
           ".exe", ".woff", ".woff2", ".ttf", ".eot", ".mp3", ".mp4", ".wasm", ".pyc"}
LOCKFILES = {"package-lock.json", "yarn.lock", "pnpm-lock.yaml", "poetry.lock",
             "uv.lock", "Cargo.lock", "Gemfile.lock", "go.sum", "composer.lock"}
MAX_TEXT = 1024 * 1024
SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}
ERRORS = []


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


def parse_yarn_lock(text):
    out = []
    names = []
    for line in text.splitlines():
        if line and not line.startswith((" ", "\t", "#")) and line.rstrip().endswith(":"):
            names = []
            spec = line.rstrip()[:-1]
            for part in spec.split(","):
                part = part.strip().strip('"')
                if not part:
                    continue
                at = part.rfind("@")
                if at > 0:
                    names.append(part[:at])
        else:
            m = re.match(r'^\s+version\s+"?([^"\s]+)"?', line)
            if m and names:
                for n in dict.fromkeys(names):
                    out.append(("npm", n, m.group(1)))
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
    "Gemfile.lock": parse_gemfile_lock,
}


def collect_packages(root, files):
    seen = {}
    for path in files:
        base = os.path.basename(path)
        handler = DEP_HANDLERS.get(base)
        if handler is None and base.startswith("requirements") and base.endswith(".txt"):
            handler = parse_requirements
        if handler is None:
            continue
        text = read_text(path, 8 * 1024 * 1024)
        if text is None:
            continue
        try:
            pkgs = handler(text)
        except Exception as exc:
            ERRORS.append("parse %s: %s" % (os.path.relpath(path, root), exc))
            continue
        rel = os.path.relpath(path, root)
        for eco, name, ver in pkgs:
            seen.setdefault((eco, name, ver), rel)
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
def _generic_sev(match_value):
    if re.search(r"example|changeme|your[_-]|xxx|dummy|placeholder|<|\$\{", match_value, re.I):
        return "low", "placeholder?"
    return "medium", None


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
                    add("secret", sev, rel, lineno, summary=desc + " detected",
                        evidence=redact(m.group(0)))
            gm = GENERIC.search(line)
            if gm:
                sev, note = _generic_sev(gm.group(2))
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
    out_path, use_osv, fail_on = None, True, None
    i = 1
    while i < len(args):
        if args[i] == "--json" and i + 1 < len(args):
            out_path = args[i + 1]
            i += 2
        elif args[i] == "--no-osv":
            use_osv = False
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
        },
        "findings": findings,
    }
    canon = json.dumps({"findings": findings, "target": target, "commit": commit},
                       sort_keys=True, separators=(",", ":"))
    doc["manifest_hash"] = hashlib.sha256(canon.encode()).hexdigest()
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
