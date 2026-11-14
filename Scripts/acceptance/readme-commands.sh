#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT_DIR"

export PATH="${ROOT_DIR}/.venv/bin:${PATH}"
PYTHON="python3"
XRAY="agent-xray"
if ! command -v "$XRAY" >/dev/null 2>&1; then
  echo "Missing agent-xray in .venv/bin" >&2
  exit 1
fi

TMP_DIR="$(mktemp -d /tmp/xray-readme-cmds.XXXXXX)"
PIDS=()
cleanup() {
  for pid in ${PIDS[@]+"${PIDS[@]}"}; do
    if [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null; then
      kill "$pid" 2>/dev/null || true
      wait "$pid" 2>/dev/null || true
    fi
  done
  rm -rf "$TMP_DIR"
}
trap cleanup EXIT

echo "=== agent-xray README & README.zh-CN Command Verification ==="
echo "Isolated temp dir: <mktemp>/xray-readme-cmds (cleaned on exit)"

# Start local fake upstream so `run` and `serve` never touch external APIs
FAKE_PORT_FILE="$TMP_DIR/fake_port.txt"
"$PYTHON" - "$FAKE_PORT_FILE" <<'PY' &
import json, sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

port_file = sys.argv[1]

class FakeLLM(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        return

    def do_POST(self):
        length = int(self.headers.get("Content-Length") or "0")
        raw = self.rfile.read(length) if length else b"{}"
        payload = json.loads(raw.decode("utf-8"))
        if "responses" in self.path or "chat/completions" in self.path:
            resp = {
                "id": "chatcmpl_readme",
                "model": payload.get("model", "gpt-4o"),
                "usage": {
                    "prompt_tokens": 1200,
                    "completion_tokens": 120,
                    "prompt_tokens_details": {"cached_tokens": 900},
                },
            }
        else:
            resp = {
                "id": "msg_readme",
                "model": payload.get("model", "claude-sonnet-4-5"),
                "usage": {
                    "input_tokens": 300,
                    "cache_read_input_tokens": 2700,
                    "cache_creation_input_tokens": 0,
                    "output_tokens": 110,
                },
            }
        out = json.dumps(resp).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(out)))
        self.end_headers()
        self.wfile.write(out)

srv = ThreadingHTTPServer(("127.0.0.1", 0), FakeLLM)
with open(port_file, "w", encoding="utf-8") as fh:
    fh.write(str(srv.server_address[1]))
srv.serve_forever()
PY
PIDS+=("$!")

for _ in $(seq 1 50); do
  [[ -s "$FAKE_PORT_FILE" ]] && break
  sleep 0.05
done
FAKE_PORT="$(cat "$FAKE_PORT_FILE")"
export AGENT_XRAY_ANTHROPIC_UPSTREAM="http://127.0.0.1:${FAKE_PORT}"
export AGENT_XRAY_OPENAI_UPSTREAM="http://127.0.0.1:${FAKE_PORT}"

# Local Python mock coding agent used in place of `<your-agent-command>`
MOCK_AGENT="$TMP_DIR/mock_agent.py"
cat > "$MOCK_AGENT" <<'PY'
import json, os, urllib.request

base = os.environ["ANTHROPIC_BASE_URL"]
payload = {
    "model": "claude-sonnet-4-5",
    "system": "You are a coding assistant.\n<user_rules>Follow AGENTS.md</user_rules>",
    "tools": [
        {"name": "mcp__scholar__search_papers", "description": "Search papers", "input_schema": {"type": "object"}},
        {"name": "Bash", "description": "Run shell command", "input_schema": {"type": "object"}},
    ],
    "messages": [{"role": "user", "content": "Summarize repository test layout"}],
}
req = urllib.request.Request(
    f"{base}/v1/messages",
    data=json.dumps(payload).encode("utf-8"),
    headers={
        "Content-Type": "application/json",
        "x-api-key": "sk-ant-api03-MockAgentSessionKey1234567890",
        "x-stainless-os": "MacOS",
        "User-Agent": "mock-agent/1.0 (Darwin arm64)",
    },
)
with urllib.request.urlopen(req, timeout=5) as resp:
    assert resp.status == 200
PY

echo ""
echo "1) agent-xray --version"
"$XRAY" --version

echo ""
echo "2) agent-xray export-demo (EN & ZH)"
"$XRAY" --lang en export-demo --out "$TMP_DIR/demo-en.html"
"$XRAY" --lang zh export-demo --out "$TMP_DIR/demo-zh.html"
[[ -s "$TMP_DIR/demo-en.html" && -s "$TMP_DIR/demo-zh.html" ]]

echo ""
echo "3) agent-xray run --strip-telemetry-headers --block-secrets (EN & ZH)"
"$XRAY" --lang en run --db "$TMP_DIR/run-en.db" --strip-telemetry-headers --block-secrets -- "$PYTHON" "$MOCK_AGENT"
"$XRAY" --lang zh run --db "$TMP_DIR/run-zh.db" --strip-telemetry-headers --block-secrets -- "$PYTHON" "$MOCK_AGENT"

echo ""
echo "4) agent-xray serve + ANTHROPIC_BASE_URL & OPENAI_BASE_URL client requests"
SRV_PORT="$("$PYTHON" -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1]); s.close()')"
"$XRAY" --lang en serve --port "$SRV_PORT" --db "$TMP_DIR/serve.db" --strip-telemetry-headers --block-secrets >"$TMP_DIR/serve.log" 2>&1 &
SRV_PID="$!"
PIDS+=("$SRV_PID")
for _ in $(seq 1 50); do
  curl -fsS "http://127.0.0.1:${SRV_PORT}/_xray/api/summary" >/dev/null 2>&1 && break
  sleep 0.05
done
curl -fsS -X POST "http://127.0.0.1:${SRV_PORT}/anthropic/v1/messages" \
  -H "Content-Type: application/json" \
  -d '{"model":"claude-sonnet-4-5","messages":[{"role":"user","content":"ping anthropic"}]}' >/dev/null
curl -fsS -X POST "http://127.0.0.1:${SRV_PORT}/openai/v1/chat/completions" \
  -H "Content-Type: application/json" \
  -d '{"model":"gpt-4o","messages":[{"role":"user","content":"ping openai"}]}' >/dev/null
kill "$SRV_PID" 2>/dev/null || true
wait "$SRV_PID" 2>/dev/null || true
"$XRAY" --lang en report --db "$TMP_DIR/serve.db"
"$XRAY" --lang zh report --db "$TMP_DIR/serve.db"

echo ""
echo "5) agent-xray desktop --import-only + report + purge-db (EN & ZH)"
"$XRAY" --lang en desktop --db "$TMP_DIR/desktop.db" --import-only
"$XRAY" --lang en report --db "$TMP_DIR/desktop.db"
"$XRAY" --lang zh report --db "$TMP_DIR/desktop.db"
"$XRAY" --lang en purge-db --db "$TMP_DIR/desktop.db"
"$XRAY" --lang zh purge-db --db "$TMP_DIR/desktop.db"
[[ ! -e "$TMP_DIR/desktop.db" ]]

echo ""
echo "=== ALL README & README.zh-CN COMMANDS SUCCEEDED ==="
