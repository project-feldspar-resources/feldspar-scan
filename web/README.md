# web/ — free discovery scan endpoint

A stdlib-only HTTP wrapper around `../scan.py`. It does not modify or
re-implement any scanner logic: each request shells out to
`python3 scan.py <url> --json <tmpfile>` and renders the JSON.

## Run locally

```
cd feldspar-scan   # repo root
python3 web/server.py                 # 127.0.0.1:8090
SCAN_PORT=9001 python3 web/server.py  # other port
```

Check it:

```
curl -s localhost:8090/healthz                      # -> ok
curl -s localhost:8090/ | head                      # landing page + form
curl -s -X POST -d 'url=https://github.com/psf/requests' localhost:8090/scan
curl -s -X POST -H 'Accept: application/json' \
     -d 'url=https://github.com/psf/requests' localhost:8090/scan
curl -s -X POST -H 'Content-Type: application/json' \
     -d '{"url":"https://github.com/psf/requests"}' localhost:8090/scan
```

## Routes

| Route | Notes |
| --- | --- |
| `GET /` | landing page, form, disclosure, $49 audit CTA |
| `POST /scan` | `url=` form field or `{"url":...}` JSON body |
| `GET /healthz` | `200 ok` |
| `POST /mcp` | stateless streamable-HTTP MCP (JSON-RPC): `initialize`, `tools/list`, `tools/call` for `scan_repository(url)` and `audit_pricing()`; plain JSON replies, no sessions/SSE; `GET`/`DELETE` → 405; foreign `Origin` → 403 |

Response format is HTML unless `Accept: application/json` is sent or the
request body was JSON. `GET /scan` and `GET /scan/` also serve the landing
page so the endpoint works both bare and behind the `/scan/` proxy prefix.

Status codes: `400` bad/unsupported URL, `413` body over 4 KB, `429` per-IP
rate limit, `503` both scan slots busy, `502` clone failed / scan timed out,
`500` generic (tracebacks go to stdout only, never to the client).

## Wiring it up (my plan, not done here)

1. `sudo cp web/feldspar-scan.service /etc/systemd/system/` — `User=feldspar`,
   `WorkingDirectory` the scanner dir, `SCAN_PORT=8090`, `Restart=on-failure`.
2. Add `limit_req_zone $binary_remote_addr zone=feldspar_scan:10m rate=10r/m;`
   to the `http { }` block in `nginx.conf`.
3. Include `web/nginx-location.conf` in the `project-feldspar.com` server
   block. `proxy_pass http://127.0.0.1:8090/` (trailing slash) strips `/scan/`.
4. `nginx -t && systemctl reload nginx`; the service stays bound to loopback,
   so nginx is the only way in and `X-Forwarded-For` is set by nginx itself.

## Abuse controls

* **URL allowlist** — regex-pinned to `https://` on github.com, gitlab.com,
  codeberg.org or bitbucket.org with a single `owner/repo` path. No ports,
  no userinfo, no query strings, no SSH, no local paths. This is what keeps
  `scan.py`'s `git clone` off internal hosts and off the filesystem.
* **Concurrency** — semaphore of 2 in-flight scans; a third gets `503`.
* **Rate limit** — 5 scans/hour/IP, in-memory, keyed on the first
  `X-Forwarded-For` element (nginx sets it to `$remote_addr`) or the peer
  address. Requests rejected for busyness refund their slot. Rate state is
  lost on restart, by design — it is a speed bump, not an auth system.
* **Timeout** — hard 120 s `subprocess.run` cap; nginx allows 150 s.
* **Temp hygiene** — one `mkdtemp` per request with `TMPDIR`/`TMP`/`TEMP`
  pointed at it, so `scan.py`'s own `fds-clone-*` clone lands inside and a
  single `shutil.rmtree` in a `finally` removes everything.
* **Body cap** — 4 KB; larger bodies get `413` without being read.
* **Output escaping** — everything from the scan (including repo-controlled
  file paths and summaries) goes through `html.escape`; findings are capped
  at 200 rows with a pointer to the raw JSON.
* **Logging** — one line per request: timestamp, IP, method, path, status,
  duration, target URL. Findings and evidence are never logged.

## Known gaps

* Rate limiting is per-process and in-memory; a restart clears it, and it
  does not survive multiple workers.
* `git` grandchildren are not put in their own process group, so a scan that
  hits the 120 s timeout may leave a clone running briefly (its temp dir is
  under the per-request `TMPDIR`, which is rmtree'd regardless).
* No result caching: the same repo scanned twice does the work twice.
* No queue — a busy server says "retry in a minute" rather than waiting.
