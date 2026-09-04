#!/usr/bin/env python3
"""feldspar-scan web endpoint.

A thin, stdlib-only HTTP wrapper around ../scan.py. Binds 127.0.0.1:8090
(override with SCAN_PORT). Intended to sit behind nginx at /scan/.

Routes:
    GET  /         landing page + form
    POST /scan     run a scan (form-encoded url= or JSON {"url": ...})
    GET  /healthz  liveness
    POST /mcp      Model Context Protocol (streamable-HTTP, stateless JSON-RPC)

Nothing here changes scan.py's behaviour: it is invoked as a subprocess
exactly as documented, with TMPDIR pointed at a per-request temp dir so
its clone is removed by a single rmtree.
"""
import html
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import urllib.parse
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HERE = os.path.dirname(os.path.abspath(__file__))
SCANNER_DIR = os.path.dirname(HERE)
SCAN_PY = os.path.join(SCANNER_DIR, "scan.py")

PORT = int(os.environ.get("SCAN_PORT", "8090"))
HOST = os.environ.get("SCAN_HOST", "127.0.0.1")
SCAN_TIMEOUT = 120          # hard wall-clock cap per scan
MAX_BODY = 4096             # 4 KB request body cap
MAX_CONCURRENT = 2
RATE_LIMIT = 5              # scans ...
RATE_WINDOW = 3600          # ... per hour, per client IP
MAX_ROWS = 200              # findings rendered in the HTML table

URL_RE = re.compile(
    r"^https://(github\.com|gitlab\.com|codeberg\.org|bitbucket\.org)"
    r"/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+(\.git)?/?$"
)

CTA_URL = "https://project-feldspar.com/"
CTA_TEXT = "Want a real audit? $49 deep audit by three review passes"
DISCLOSURE = ("This is an AI-operated service: the scan, this site and the "
              "follow-up audits are run by an autonomous agent (Project Feldspar).")

_slots = threading.Semaphore(MAX_CONCURRENT)
_rate_lock = threading.Lock()
_rate = {}  # ip -> [epoch seconds]

SEV_COLOR = {
    "critical": "#7f1d1d", "high": "#b45309", "medium": "#a16207",
    "moderate": "#a16207", "low": "#3f6212", "unknown": "#475569",
}

CSS = """
:root{color-scheme:light dark}
*{box-sizing:border-box}
body{margin:0;padding:2.5rem 1.25rem;font:16px/1.55 -apple-system,BlinkMacSystemFont,
 "Segoe UI",Roboto,Helvetica,Arial,sans-serif;color:#111;background:#fbfbf9}
main{max-width:60rem;margin:0 auto}
h1{font-size:1.6rem;margin:0 0 .5rem;letter-spacing:-.01em}
h2{font-size:1.1rem;margin:2rem 0 .5rem}
p{margin:.6rem 0}
.muted{color:#5b6470;font-size:.9rem}
form{display:flex;gap:.5rem;flex-wrap:wrap;margin:1.25rem 0}
input[type=text]{flex:1 1 24rem;padding:.6rem .7rem;font-size:1rem;
 border:1px solid #c8ccd2;border-radius:6px;background:#fff;color:#111}
button{padding:.6rem 1.1rem;font-size:1rem;border:0;border-radius:6px;
 background:#1f2937;color:#fff;cursor:pointer}
button:disabled{opacity:.55;cursor:progress}
.cta{display:block;margin:1.75rem 0;padding:.9rem 1rem;border:1px solid #d8cfae;
 border-radius:8px;background:#fdf8e6;text-decoration:none;color:#111;font-weight:600}
table{border-collapse:collapse;width:100%;font-size:.86rem;margin-top:.5rem}
th,td{text-align:left;padding:.4rem .5rem;border-bottom:1px solid #e5e7eb;
 vertical-align:top;word-break:break-word}
th{background:#f3f4f6;font-weight:600;white-space:nowrap}
code{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:.85em}
.badge{display:inline-block;padding:.1rem .45rem;border-radius:4px;color:#fff;
 font-size:.75rem;font-weight:700;text-transform:uppercase;letter-spacing:.02em}
.counts{display:flex;flex-wrap:wrap;gap:.4rem;margin:.6rem 0}
.counts span{padding:.2rem .55rem;border:1px solid #e5e7eb;border-radius:999px;
 background:#fff;font-size:.85rem}
details{margin:1.5rem 0}
pre{overflow:auto;background:#0f172a;color:#e2e8f0;padding:.8rem;border-radius:6px;
 font-size:.78rem;max-height:28rem}
.err{border-left:4px solid #b45309;padding:.5rem .8rem;background:#fff7ed}
footer{margin-top:3rem;font-size:.85rem;color:#5b6470}
a{color:#1d4ed8}
@media (prefers-color-scheme:dark){
 body{background:#0f1115;color:#e6e8eb}
 input[type=text]{background:#1a1d23;color:#e6e8eb;border-color:#333a44}
 th{background:#1a1d23}th,td{border-color:#252a32}
 .counts span{background:#1a1d23;border-color:#252a32}
 .cta{background:#1e1b12;border-color:#4a4227;color:#e6e8eb}
 .err{background:#1e1b12}a{color:#93c5fd}
}
"""

E = html.escape


def page(title, body):
    return ("<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">"
            "<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">"
            "<meta name=\"robots\" content=\"noindex\">"
            f"<title>{E(title)}</title><style>{CSS}</style></head>"
            f"<body><main>{body}"
            f"<footer><p>{E(DISCLOSURE)}</p>"
            "<p><a href=\"/\">New scan</a></p></footer></main></body></html>")


def cta_html():
    return (f"<a class=\"cta\" href=\"{E(CTA_URL)}\">{E(CTA_TEXT)} &mdash; "
            f"{E(CTA_URL)}</a>")


def index_html():
    return page(
        "Free repository discovery scan — Project Feldspar",
        "<h1>Free repository discovery scan</h1>"
        "<p>Paste a public git repository URL and get a deterministic discovery "
        "scan: dependency advisories resolved against "
        "<a href=\"https://osv.dev/\">OSV.dev</a>, secret patterns in the "
        "checked-out tree, and a handful of config checks (committed "
        "<code>.env</code>, rootful Dockerfiles, GitHub Actions pwn-request "
        "patterns). It is pure pattern matching and lockfile parsing &mdash; "
        "no LLM is involved, and <strong>results are not reviewed for false "
        "positives</strong>, so test fixtures, docs examples and rotated "
        "credentials will show up.</p>"
        "<form method=\"post\" action=\"scan\" id=\"f\">"
        "<input type=\"text\" name=\"url\" required "
        "placeholder=\"https://github.com/owner/repo\" "
        "pattern=\"https://(github\\.com|gitlab\\.com|codeberg\\.org|bitbucket\\.org)/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+(\\.git)?/?\" "
        "aria-label=\"Public git repository URL\">"
        "<button type=\"submit\" id=\"b\">Scan</button></form>"
        "<p class=\"muted\">GitHub, GitLab, Codeberg and Bitbucket only. "
        "A shallow clone is made, scanned, and deleted. Scans take roughly "
        "10&ndash;90 seconds; 5 scans per hour per IP.</p>"
        f"<p class=\"muted\">{E(DISCLOSURE)}</p>"
        "<p class=\"muted\">Automate it: <code>POST /scan/scan</code> with "
        "<code>url=</code> and <code>Accept: application/json</code> returns the raw "
        "report (<a href=\"https://project-feldspar.com/openapi.json\">OpenAPI</a>). "
        "The scanner is a single MIT-licensed Python file and a composite GitHub "
        "Action: <a href=\"https://github.com/project-feldspar-resources/feldspar-scan\">"
        "project-feldspar-resources/feldspar-scan</a>. Agents and IDEs can use it as an "
        "MCP server: <code>https://project-feldspar.com/mcp</code> "
        "(<code>com.project-feldspar/scan</code> in the official MCP registry).</p>"
        + cta_html() +
        "<script>document.getElementById('f').addEventListener('submit',function(){"
        "var b=document.getElementById('b');b.disabled=true;"
        "b.textContent='Scanning\\u2026';});</script>")


def message_page(title, heading, body_html, status_note=""):
    return page(title, f"<h1>{E(heading)}</h1><div class=\"err\">{body_html}</div>"
                + (f"<p class=\"muted\">{E(status_note)}</p>" if status_note else "")
                + cta_html())


def badge(sev):
    sev = (sev or "unknown").lower()
    return (f"<span class=\"badge\" style=\"background:"
            f"{SEV_COLOR.get(sev, SEV_COLOR['unknown'])}\">{E(sev)}</span>")


def results_html(doc):
    target = str(doc.get("target", ""))
    commit = str(doc.get("commit") or "")
    scanned = str(doc.get("scanned_at") or "")
    summary = doc.get("summary") or {}
    findings = doc.get("findings") or []

    counts = "".join(
        f"<span><strong>{E(str(k))}</strong>: {E(str(v))}</span>"
        for k, v in _flatten_summary(summary))
    rows = []
    for f in findings[:MAX_ROWS]:
        loc = str(f.get("file") or "")
        if f.get("line"):
            loc += ":" + str(f.get("line"))
        pkg = str(f.get("package") or "")
        if pkg and f.get("version"):
            pkg += "@" + str(f.get("version"))
        if pkg and f.get("ecosystem"):
            pkg = f"{pkg} <span class=\"muted\">({E(str(f.get('ecosystem')))})</span>"
        else:
            pkg = E(pkg)
        fixed = f.get("fixed_in") or []
        if isinstance(fixed, (list, tuple)):
            fixed = ", ".join(str(x) for x in fixed)
        rows.append(
            "<tr>"
            f"<td><code>{E(str(f.get('id') or ''))}</code></td>"
            f"<td>{E(str(f.get('category') or ''))}</td>"
            f"<td>{badge(f.get('severity'))}</td>"
            f"<td><code>{E(loc)}</code></td>"
            f"<td>{pkg}</td>"
            f"<td>{E(str(f.get('summary') or ''))}</td>"
            f"<td>{E(str(fixed))}</td>"
            f"<td><code>{E(str(f.get('evidence') or ''))}</code></td>"
            "</tr>")
    table = ("<table><thead><tr><th>ID</th><th>Category</th><th>Severity</th>"
             "<th>File:line</th><th>Package</th><th>Summary</th><th>Fixed in</th>"
             "<th>Evidence</th></tr></thead><tbody>"
             + "".join(rows) + "</tbody></table>") if rows else \
            "<p>No findings. That is not a clean bill of health &mdash; see the " \
            "limits above.</p>"
    more = ""
    if len(findings) > MAX_ROWS:
        more = (f"<p class=\"muted\">Showing the first {MAX_ROWS} of "
                f"{len(findings)} findings; the full set is in the raw JSON "
                "below.</p>")
    errs = doc.get("errors") or []
    err_html = ""
    if errs:
        err_html = ("<div class=\"err\"><strong>Degraded:</strong><ul>"
                    + "".join(f"<li>{E(str(e))}</li>" for e in errs)
                    + "</ul></div>")
    raw = json.dumps(doc, indent=2, sort_keys=True)
    return page(
        "Scan results — Project Feldspar",
        "<h1>Discovery scan results</h1>"
        f"<p><strong>Target:</strong> <code>{E(target)}</code><br>"
        f"<strong>Commit:</strong> <code>{E(commit)}</code><br>"
        f"<strong>Scanned at:</strong> <code>{E(scanned)}</code><br>"
        f"<strong>manifest_hash:</strong> <code>{E(str(doc.get('manifest_hash') or ''))}</code></p>"
        f"<div class=\"counts\">{counts}</div>"
        + err_html
        + "<h2>Findings</h2>"
        + more + table
        + "<p class=\"muted\">Deterministic output only: no false-positive "
          "review, no git-history scan, no reachability analysis.</p>"
        + cta_html()
        + f"<details><summary>Raw JSON</summary><pre>{E(raw)}</pre></details>")


def _flatten_summary(summary, prefix=""):
    out = []
    if isinstance(summary, dict):
        for k, v in summary.items():
            if isinstance(v, dict):
                out.extend(_flatten_summary(v, f"{prefix}{k}."))
            else:
                out.append((f"{prefix}{k}", v))
    return out


# ------------------------------------------------------------------ limits
def rate_check(ip):
    """True if the caller may start a scan now; records the attempt."""
    now = time.time()
    with _rate_lock:
        hits = [t for t in _rate.get(ip, []) if now - t < RATE_WINDOW]
        if len(hits) >= RATE_LIMIT:
            _rate[ip] = hits
            return False
        hits.append(now)
        _rate[ip] = hits
        if len(_rate) > 10000:                      # crude unbounded-growth guard
            for k in [k for k, v in _rate.items()
                      if not v or now - max(v) > RATE_WINDOW]:
                _rate.pop(k, None)
        return True


def rate_refund(ip):
    with _rate_lock:
        if _rate.get(ip):
            _rate[ip].pop()


def run_scan(url):
    """Run scan.py in a disposable TMPDIR. Returns (doc, error_string)."""
    tmp = tempfile.mkdtemp(prefix="fds-web-")
    try:
        out = os.path.join(tmp, "scan.json")
        env = dict(os.environ)
        env["TMPDIR"] = tmp            # scan.py's mkdtemp clone lands in here
        env["TMP"] = tmp
        env["TEMP"] = tmp
        env["HOME"] = env.get("HOME", tmp)
        env["GIT_TERMINAL_PROMPT"] = "0"
        env["GIT_ASKPASS"] = "/bin/true"
        try:
            proc = subprocess.run(
                [sys.executable, SCAN_PY, url, "--json", out],
                cwd=SCANNER_DIR, env=env, capture_output=True, text=True,
                stdin=subprocess.DEVNULL, timeout=SCAN_TIMEOUT)
        except subprocess.TimeoutExpired:
            return None, ("The scan exceeded the %d second limit. Very large "
                          "repositories are out of scope for the free scan."
                          % SCAN_TIMEOUT)
        if proc.returncode == 3:
            return None, ("Could not clone that repository. Is it public and "
                          "does the URL exist?")
        if proc.returncode != 0 or not os.path.exists(out):
            return None, "The scan did not complete."
        try:
            with open(out, "r", encoding="utf-8") as fh:
                return json.load(fh), None
        except (OSError, ValueError):
            return None, "The scan produced unreadable output."
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


# ----------------------------------------------------------------- MCP
# Model Context Protocol, streamable-HTTP transport, stateless: POST /mcp
# carries one JSON-RPC message; replies are plain application/json. No SSE
# stream, no sessions (GET/DELETE -> 405). Listed in the official MCP
# registry as com.project-feldspar/scan.
MCP_MAX_BODY = 16384
MCP_PROTOCOL_VERSIONS = ("2025-11-25", "2025-06-18", "2025-03-26")
MCP_ALLOWED_ORIGINS = ("https://project-feldspar.com", "https://www.project-feldspar.com")
MCP_MAX_FINDINGS = 200


def _scan_version():
    try:
        with open(SCAN_PY, "r", encoding="utf-8") as fh:
            m = re.search(r'^(?:VERSION|__version__)\s*=\s*["\']([^"\']+)', fh.read(), re.M)
            if m:
                return m.group(1)
    except OSError:
        pass
    return "0.2"


MCP_SERVER_INFO = {"name": "feldspar-scan", "title": "Feldspar free repository scan",
                   "version": _scan_version()}
MCP_INSTRUCTIONS = (
    "Free deterministic security discovery scan of a PUBLIC git repository "
    "(github.com, gitlab.com, codeberg.org, bitbucket.org): known-vulnerable "
    "dependencies via OSV.dev, hard-coded secrets (redacted), and risky config "
    "(Dockerfile, compose, GitHub workflows, .env, .npmrc). Limits: 5 scans per "
    "hour per client, 120 s per scan, no private repositories. Operated by an "
    "autonomous AI agent (Project Feldspar). For a paid human-readable deep audit "
    "(three independent LLM review passes, verified findings) call audit_pricing.")
MCP_TOOLS = [
    {
        "name": "scan_repository",
        "title": "Scan a public repository",
        "description": (
            "Clone a public git repository and run feldspar-scan: OSV.dev "
            "advisories for pinned dependencies in lockfiles (npm, pnpm, yarn, "
            "pip/uv/poetry, Cargo, Go, Gemfile.lock, composer), secret patterns "
            "with redacted evidence, and configuration lint. Returns a JSON "
            "report with summary counts and per-finding severity, file, line, "
            "advisory id and fixed versions. Deterministic, no LLM involved. "
            "Takes 2-90 s depending on repository size."),
        "inputSchema": {
            "type": "object",
            "properties": {
                "url": {"type": "string",
                        "description": "https://github.com/owner/repo (also gitlab.com, codeberg.org, bitbucket.org)"}
            },
            "required": ["url"],
            "additionalProperties": False,
        },
        "annotations": {"readOnlyHint": True, "destructiveHint": False,
                        "idempotentHint": True, "openWorldHint": True},
    },
    {
        "name": "audit_pricing",
        "title": "Paid deep audit: scope, price, how to order",
        "description": (
            "Describe Project Feldspar's paid code audit (security, correctness, "
            "maintainability; three independent review passes plus consolidation "
            "and manual verification of every reported file:line), its price, "
            "turnaround, and the Stripe checkout URL. No arguments."),
        "inputSchema": {"type": "object", "properties": {}, "additionalProperties": False},
        "annotations": {"readOnlyHint": True, "destructiveHint": False,
                        "idempotentHint": True, "openWorldHint": False},
    },
]
AUDIT_PRICING_TEXT = (
    "Project Feldspar deep code audit\n"
    "- Price: USD 49 for repositories up to about 30k lines of code; larger "
    "repositories are quoted (typically USD 99) before any work starts.\n"
    "- Scope: security, correctness and maintainability findings, each with "
    "file:line, severity, evidence and a recommended fix; exploitable security "
    "findings go to the maintainers privately first.\n"
    "- Method: three independent review passes (security / correctness / "
    "maintainability) over the source, a consolidation pass, then a manual "
    "spot-check of every reported location by the agent before delivery.\n"
    "- Turnaround: within 24 hours of payment; delivered by email as Markdown.\n"
    "- Order: https://buy.stripe.com/fZu4gy0MRgTgfpl8Vc4c800 (Stripe Checkout; "
    "enter the public repository URL in the form). Public sample reports: "
    "https://project-feldspar.com/samples/\n"
    "- Operator: an autonomous AI agent (Project Feldspar), disclosed as such. "
    "Contact: feldspar@agentmail.to")


def _rpc_error(rid, code, message, status=200):
    return status, {"jsonrpc": "2.0", "id": rid, "error": {"code": code, "message": message}}


def _tool_text(text, is_error=False, structured=None):
    out = {"content": [{"type": "text", "text": text}], "isError": bool(is_error)}
    if structured is not None:
        out["structuredContent"] = structured
    return out


def mcp_handle(msg, ip):
    """Process one JSON-RPC message. Returns (http_status, response_dict_or_None)."""
    if not isinstance(msg, dict) or msg.get("jsonrpc") != "2.0":
        return _rpc_error(None, -32600, "Invalid Request: expected a JSON-RPC 2.0 object")
    method = msg.get("method")
    rid = msg.get("id")
    params = msg.get("params") or {}
    if not isinstance(params, dict):
        return _rpc_error(rid, -32602, "params must be an object")
    if method is None:
        # A response from the client; nothing to do.
        return 202, None
    if rid is None:
        # Notification (initialized, cancelled, progress, ...) -> accept silently.
        return 202, None

    if method == "initialize":
        want = str(params.get("protocolVersion") or "")
        version = want if want in MCP_PROTOCOL_VERSIONS else MCP_PROTOCOL_VERSIONS[0]
        return 200, {"jsonrpc": "2.0", "id": rid, "result": {
            "protocolVersion": version,
            "capabilities": {"tools": {"listChanged": False}},
            "serverInfo": MCP_SERVER_INFO,
            "instructions": MCP_INSTRUCTIONS,
        }}
    if method == "ping":
        return 200, {"jsonrpc": "2.0", "id": rid, "result": {}}
    if method == "tools/list":
        return 200, {"jsonrpc": "2.0", "id": rid, "result": {"tools": MCP_TOOLS}}
    if method in ("resources/list", "resources/templates/list", "prompts/list"):
        key = "resourceTemplates" if method == "resources/templates/list" else method.split("/")[0]
        return 200, {"jsonrpc": "2.0", "id": rid, "result": {key: []}}
    if method == "tools/call":
        name = params.get("name")
        args = params.get("arguments") or {}
        if not isinstance(args, dict):
            return _rpc_error(rid, -32602, "arguments must be an object")
        if name == "audit_pricing":
            return 200, {"jsonrpc": "2.0", "id": rid, "result": _tool_text(AUDIT_PRICING_TEXT)}
        if name == "scan_repository":
            return 200, {"jsonrpc": "2.0", "id": rid, "result": mcp_scan(str(args.get("url") or ""), ip)}
        return _rpc_error(rid, -32602, "Unknown tool: %r" % (name,))
    return _rpc_error(rid, -32601, "Method not found: %s" % method)


def mcp_scan(url, ip):
    url = url.strip()
    if not URL_RE.match(url):
        return _tool_text("Invalid repository URL. Use https://github.com/owner/repo "
                          "(github.com, gitlab.com, codeberg.org or bitbucket.org only).", True)
    if not rate_check(ip):
        return _tool_text("Rate limited: %d scans per hour per client. Try again later, "
                          "or see audit_pricing for a full audit." % RATE_LIMIT, True)
    if not _slots.acquire(blocking=False):
        rate_refund(ip)
        return _tool_text("Busy: all scan slots are in use. Retry in a minute.", True)
    try:
        doc, err = run_scan(url)
    finally:
        _slots.release()
    if err:
        return _tool_text("Scan failed: " + err, True)
    findings = doc.get("findings") or []
    trimmed = dict(doc)
    if len(findings) > MCP_MAX_FINDINGS:
        trimmed["findings"] = findings[:MCP_MAX_FINDINGS]
        trimmed["truncated"] = {"shown": MCP_MAX_FINDINGS, "total": len(findings),
                                "full_report": "POST https://project-feldspar.com/scan/scan {\"url\": ...}"}
    summary = doc.get("summary") or {}
    head = ("feldspar-scan %s of %s: %d finding(s). Summary: %s. Full JSON follows; "
            "this is a deterministic discovery scan, not a security audit." % (
                doc.get("version", MCP_SERVER_INFO["version"]), url, len(findings),
                json.dumps(summary, sort_keys=True)))
    return {"content": [{"type": "text", "text": head},
                        {"type": "text", "text": json.dumps(trimmed, sort_keys=True)}],
            "structuredContent": trimmed, "isError": False}


# ----------------------------------------------------------------- handler
class Handler(BaseHTTPRequestHandler):
    server_version = "feldspar-scan"
    sys_version = ""
    protocol_version = "HTTP/1.1"

    # -- plumbing ---------------------------------------------------------
    def log_message(self, fmt, *args):        # silence the stderr default
        pass

    def access(self, status, started, target=""):
        line = "%s ip=%s %s %s -> %s %.2fs%s" % (
            datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            self.client_ip(), self.command, self.path, status,
            time.monotonic() - started,
            (" target=" + target) if target else "")
        sys.stdout.write(line + "\n")
        sys.stdout.flush()

    def client_ip(self):
        xff = self.headers.get("X-Forwarded-For")
        if xff:
            first = xff.split(",")[0].strip()
            if first:
                return first
        return self.client_address[0]

    def wants_json(self, body_was_json=False):
        if body_was_json:
            return True
        return "application/json" in (self.headers.get("Accept") or "")

    def send(self, status, body, ctype="text/html; charset=utf-8"):
        if isinstance(body, str):
            body = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def fail(self, status, heading, msg, as_json, note=""):
        if as_json:
            self.send(status, json.dumps({"error": msg}) + "\n",
                      "application/json; charset=utf-8")
        else:
            self.send(status, message_page(heading + " — Project Feldspar",
                                           heading, E(msg), note))

    # -- MCP ------------------------------------------------------------------
    def mcp_405(self):
        body = json.dumps({"error": "Method not allowed. This MCP endpoint is stateless: "
                           "POST one JSON-RPC message to /mcp."}) + "\n"
        body = body.encode("utf-8")
        self.send_response(405)
        self.send_header("Allow", "POST")
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def do_DELETE(self):
        started = time.monotonic()
        try:
            self.mcp_405()
        finally:
            self.access(405, started)

    def handle_mcp(self):
        """Returns (status, target) for the access log; sends the response itself."""
        origin = self.headers.get("Origin")
        if origin and origin.rstrip("/") not in MCP_ALLOWED_ORIGINS:
            self.send(403, json.dumps({"error": "Origin not allowed"}) + "\n",
                      "application/json; charset=utf-8")
            return 403, "mcp"
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            length = -1
        if length < 0 or length > MCP_MAX_BODY:
            st, resp = _rpc_error(None, -32600, "Body missing, malformed or over %d bytes" % MCP_MAX_BODY)
            self.send(413 if length > MCP_MAX_BODY else 400, json.dumps(resp) + "\n",
                      "application/json; charset=utf-8")
            return (413 if length > MCP_MAX_BODY else 400), "mcp"
        raw = self.rfile.read(length) if length else b""
        try:
            msg = json.loads(raw.decode("utf-8", "replace"))
        except ValueError:
            st, resp = _rpc_error(None, -32700, "Parse error")
            self.send(400, json.dumps(resp) + "\n", "application/json; charset=utf-8")
            return 400, "mcp"
        ip = self.client_ip()
        if isinstance(msg, list):                      # legacy batch
            out = []
            for m in msg[:16]:
                st, resp = mcp_handle(m, ip)
                if resp is not None:
                    out.append(resp)
            target = "mcp:batch"
            if not out:
                self.send(202, b"", "application/json; charset=utf-8")
                return 202, target
            self.send(200, json.dumps(out) + "\n", "application/json; charset=utf-8")
            return 200, target
        method = msg.get("method") if isinstance(msg, dict) else None
        target = "mcp:%s" % (method or "response")
        if method == "tools/call":
            target += ":%s" % ((msg.get("params") or {}).get("name"),)
        st, resp = mcp_handle(msg, ip)
        if resp is None:
            self.send(202, b"", "application/json; charset=utf-8")
            return 202, target
        self.send(st, json.dumps(resp) + "\n", "application/json; charset=utf-8")
        return st, target

    # -- routes -----------------------------------------------------------
    def do_GET(self):
        started = time.monotonic()
        status = 500
        try:
            path = urllib.parse.urlparse(self.path).path
            if path == "/mcp":
                status = 405
                self.mcp_405()
            elif path == "/healthz":
                status = 200
                self.send(200, "ok\n", "text/plain; charset=utf-8")
            elif path in ("/", "/index.html", "/scan", "/scan/"):
                status = 200
                self.send(200, index_html())
            else:
                status = 404
                self.fail(404, "Not found", "No such page.",
                          self.wants_json())
        except Exception:
            self._oops()
            status = 500
        finally:
            self.access(status, started)

    do_HEAD = do_GET

    def do_POST(self):
        started = time.monotonic()
        status = 500
        target = ""
        try:
            path = urllib.parse.urlparse(self.path).path
            if path == "/mcp":
                status, target = self.handle_mcp()
                return
            if path not in ("/scan", "/scan/", "/"):
                status = 404
                self.fail(404, "Not found", "No such endpoint.", self.wants_json())
                return

            try:
                length = int(self.headers.get("Content-Length") or 0)
            except ValueError:
                length = -1
            if length < 0:
                status = 400
                self.fail(400, "Bad request", "Bad Content-Length.", False)
                return
            if length > MAX_BODY:
                status = 413
                self.fail(413, "Request too large",
                          "Request body must be under 4 KB.", self.wants_json())
                return
            raw = self.rfile.read(length) if length else b""

            ctype = (self.headers.get("Content-Type") or "").lower()
            body_was_json = "application/json" in ctype
            url = ""
            if body_was_json:
                try:
                    url = str((json.loads(raw.decode("utf-8", "replace")) or {})
                              .get("url") or "")
                except (ValueError, AttributeError):
                    self.fail(400, "Bad request", "Body is not valid JSON.", True)
                    status = 400
                    return
            else:
                fields = urllib.parse.parse_qs(raw.decode("utf-8", "replace"))
                url = (fields.get("url") or [""])[0]
            url = url.strip()
            as_json = self.wants_json(body_was_json)

            if not URL_RE.match(url):
                status = 400
                self.fail(400, "Invalid repository URL",
                          "URL must look like "
                          "https://github.com/owner/repo (github.com, "
                          "gitlab.com, codeberg.org or bitbucket.org only).",
                          as_json)
                return
            target = url

            ip = self.client_ip()
            if not rate_check(ip):
                status = 429
                self.fail(429, "Rate limited",
                          "That is %d scans in the last hour from your address. "
                          "Try again later, or get a real audit below."
                          % RATE_LIMIT, as_json)
                return

            if not _slots.acquire(blocking=False):
                rate_refund(ip)
                status = 503
                self.fail(503, "Busy",
                          "All scan slots are in use right now. Please retry "
                          "in a minute.", as_json)
                return
            try:
                doc, err = run_scan(url)
            finally:
                _slots.release()

            if err:
                status = 502
                self.fail(502, "Scan failed", err, as_json)
                return

            status = 200
            if as_json:
                self.send(200, json.dumps(doc, sort_keys=True) + "\n",
                          "application/json; charset=utf-8")
            else:
                self.send(200, results_html(doc))
        except (BrokenPipeError, ConnectionResetError):
            status = 499
        except Exception:
            self._oops()
            status = 500
        finally:
            self.access(status, started, target)

    def _oops(self):
        """Generic 500. Traceback goes to our stdout, never to the client."""
        import traceback
        sys.stdout.write("ERROR %s %s\n%s\n" % (
            self.command, self.path, traceback.format_exc()))
        sys.stdout.flush()
        try:
            self.fail(500, "Server error",
                      "Something went wrong on our side. Please try again.",
                      self.wants_json())
        except Exception:
            pass


def main():
    if not os.path.exists(SCAN_PY):
        sys.stderr.write("scan.py not found at %s\n" % SCAN_PY)
        return 1
    httpd = ThreadingHTTPServer((HOST, PORT), Handler)
    httpd.daemon_threads = True
    sys.stdout.write("feldspar-scan listening on http://%s:%d (scan.py=%s)\n"
                     % (HOST, PORT, SCAN_PY))
    sys.stdout.flush()
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.server_close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
