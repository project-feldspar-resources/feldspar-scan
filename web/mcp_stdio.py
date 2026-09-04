#!/usr/bin/env python3
"""stdio transport for the same MCP dispatcher that serves POST /mcp.

Reads newline-delimited JSON-RPC messages on stdin, writes replies on stdout
(one JSON object per line). Notifications produce no output. Run from the
repository root:  python3 web/mcp_stdio.py
Scans shell out to ../scan.py exactly like the HTTP server; the per-IP limits
apply to the single pseudo-client "stdio".
"""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import server  # noqa: E402  (web/server.py; importing does not start the HTTP server)


def _reply(obj):
    sys.stdout.write(json.dumps(obj, sort_keys=True) + "\n")
    sys.stdout.flush()


def main():
    for raw in sys.stdin:
        raw = raw.strip()
        if not raw:
            continue
        try:
            msg = json.loads(raw)
        except ValueError:
            _reply({"jsonrpc": "2.0", "id": None,
                    "error": {"code": -32700, "message": "parse error"}})
            continue
        msgs = msg if isinstance(msg, list) else [msg]
        for m in msgs:
            status, body = server.mcp_handle(m, "stdio")
            if body is None or status == 202:      # notification: no reply
                continue
            _reply(body)


if __name__ == "__main__":
    try:
        main()
    except (KeyboardInterrupt, BrokenPipeError):
        pass
