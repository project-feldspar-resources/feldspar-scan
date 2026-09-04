# feldspar-scan: stdio MCP server (default) or the HTTP endpoint.
#   docker build -t feldspar-scan .
#   docker run -i --rm feldspar-scan                       # MCP over stdio
#   docker run -p 8090:8090 --rm feldspar-scan python3 web/server.py   # HTTP + /mcp
FROM python:3.12-slim
RUN apt-get update && apt-get install -y --no-install-recommends git ca-certificates \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY scan.py action_run.py LICENSE README.md ./
COPY web/ ./web/
ENV PYTHONUNBUFFERED=1 SCAN_PORT=8090
EXPOSE 8090
ENTRYPOINT ["python3"]
CMD ["web/mcp_stdio.py"]
