#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT_DIR"

export PYTHONDONTWRITEBYTECODE=1
export BROWSER=true

resolve_python() {
  local cand
  for cand in \
    "${AGENT_XRAY_PYTHON:-}" \
    "${ROOT_DIR}/.venv/bin/python" \
    python3.14 python3.13 python3.12 python3.11 python3.10 python3 \
    /opt/homebrew/bin/python3.13 /opt/homebrew/bin/python3.12 /opt/homebrew/bin/python3.11 /opt/homebrew/bin/python3.10 /opt/homebrew/bin/python3; do
    [[ -z "$cand" ]] && continue
    if command -v "$cand" >/dev/null 2>&1; then
      if "$cand" -c 'import sys; raise SystemExit(0 if sys.version_info >= (3, 10) else 1)' 2>/dev/null; then
        command -v "$cand"
        return 0
      fi
    fi
  done
  echo "Error: Python >= 3.10 is required." >&2
  exit 1
}

PYTHON="$(resolve_python)"
export PYTHONPATH="${ROOT_DIR}/src${PYTHONPATH:+:${PYTHONPATH}}"

TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/xray-m0-accept.XXXXXX")"
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

export HOME="$TMP_DIR/isolated-home"
mkdir -p "$HOME" "$TMP_DIR/bin"

if [[ -x "${ROOT_DIR}/.venv/bin/agent-xray" ]]; then
  XRAY="${ROOT_DIR}/.venv/bin/agent-xray"
else
  XRAY="$TMP_DIR/bin/agent-xray"
  cat > "$XRAY" <<EOF
#!/usr/bin/env bash
exec env PYTHONDONTWRITEBYTECODE=1 PYTHONPATH="${ROOT_DIR}/src" "${PYTHON}" -m agent_xray.cli "\$@"
EOF
  chmod +x "$XRAY"
fi

echo "=== agent-xray M0 Acceptance Suite ==="
echo "Isolated temp dir: <mktemp>/xray-m0-accept (cleaned on exit)"

# Start local fake Anthropic/OpenAI upstream on 127.0.0.1 ephemeral port
FAKE_PORT_FILE="$TMP_DIR/fake_port.txt"
"$PYTHON" - "$FAKE_PORT_FILE" <<'PY' &
import json, sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

port_file = sys.argv[1]

class FakeUpstream(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        return

    def do_POST(self):
        length = int(self.headers.get("Content-Length") or "0")
        raw = self.rfile.read(length) if length else b"{}"
        try:
            payload = json.loads(raw.decode("utf-8"))
        except Exception:
            payload = {}
        model = str(payload.get("model") or "claude-sonnet-4-5")
        if self.headers.get("X-Mock-Status") == "429":
            err = json.dumps({"error": {"type": "rate_limit_error", "message": "rate limited"}}).encode("utf-8")
            self.send_response(429)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(err)))
            self.end_headers()
            self.wfile.write(err)
            return

        resp = {
            "id": "msg_fake_m0",
            "model": model,
            "usage": {
                "input_tokens": 200,
                "cache_read_input_tokens": 8000,
                "cache_creation_input_tokens": 1000,
                "output_tokens": 500,
            },
        }
        out = json.dumps(resp).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(out)))
        self.end_headers()
        self.wfile.write(out)

srv = ThreadingHTTPServer(("127.0.0.1", 0), FakeUpstream)
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
echo "Fake loopback upstream listening on 127.0.0.1:${FAKE_PORT}"

pick_free_port() {
  "$PYTHON" -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1]); s.close()'
}

wait_for_xray() {
  local port="$1"
  for _ in $(seq 1 60); do
    if curl -fsS "http://127.0.0.1:${port}/_xray/api/summary" >/dev/null 2>&1; then
      return 0
    fi
    sleep 0.05
  done
  echo "Timed out waiting for agent-xray on port ${port}" >&2
  return 1
}

# ---------------------------------------------------------------------------
# Row 1 & Row 2: Secret leakage (sk-ant, sk-or-v1, full PEM) with block ON/OFF
#                + store-previews ON/OFF + X-Custom-Token header persistence
# ---------------------------------------------------------------------------
echo ""
echo "--- [Row 1 & Row 2] Secret & Custom Header Persistence Audit (sqlite3 .dump) ---"

SECRET_PAYLOAD_FILE="$TMP_DIR/secret_payload.json"
"$PYTHON" - "$SECRET_PAYLOAD_FILE" <<'PY'
import json, sys

sk_ant = "sk-ant-api03-" + ("A9b8C7d6E5f4" * 3)
sk_or = "sk-or-v1-" + ("deadbeefcafe1234" * 4)
pem_block = (
    "-----BEGIN RSA PRIVATE KEY-----\n"
    "MIIEpAIBAAKCAQEA7VJTUt9Us8cKjMzEfYyjiWA4R4g8SecretPemLineOne999\n"
    "9vK2mPqR8xL1zW4nB6vC0yH3jF5dG7sA2kM9pQ4wE6rTSecretPemLineTwo888\n"
    "-----END RSA PRIVATE KEY-----"
)
text = (
    "Padding-" * 18
    + f" inline_ant={sk_ant} and router={sk_or}\n"
    + pem_block
)
payload = {
    "model": "claude-sonnet-4-5",
    "messages": [{"role": "user", "content": text}],
}
with open(sys.argv[1], "w", encoding="utf-8") as f:
    json.dump(payload, f)
PY

CUSTOM_HDR_VAL="XCustomSecretHeaderValue_998877665544"

for MODE_CASE in "noblock_default" "noblock_previews" "block_previews"; do
  PORT="$(pick_free_port)"
  DB_FILE="$TMP_DIR/row1_${MODE_CASE}.db"
  EXTRA_ARGS=()
  EXPECTED_HTTP="200"
  if [[ "$MODE_CASE" == "noblock_previews" ]]; then
    EXTRA_ARGS+=(--store-previews)
  elif [[ "$MODE_CASE" == "block_previews" ]]; then
    EXTRA_ARGS+=(--block-secrets --store-previews)
    EXPECTED_HTTP="400"
  fi

  "$XRAY" --lang en serve --port "$PORT" --db "$DB_FILE" --auth-token "tok-${MODE_CASE}" ${EXTRA_ARGS[@]+"${EXTRA_ARGS[@]}"} >"$TMP_DIR/${MODE_CASE}.log" 2>&1 &
  SRV_PID="$!"
  PIDS+=("$SRV_PID")
  wait_for_xray "$PORT"

  HTTP_CODE="$(curl -s -o "$TMP_DIR/${MODE_CASE}_resp.json" -w '%{http_code}' \
    -X POST "http://127.0.0.1:${PORT}/anthropic/v1/messages" \
    -H "Content-Type: application/json" \
    -H "X-Custom-Token: ${CUSTOM_HDR_VAL}" \
    -H "x-api-key: sk-ant-api03-HeaderKeySecretValue1234567890" \
    --data-binary "@${SECRET_PAYLOAD_FILE}")"

  kill "$SRV_PID" 2>/dev/null || true
  wait "$SRV_PID" 2>/dev/null || true

  echo "Case ${MODE_CASE}: HTTP=${HTTP_CODE} (expected ${EXPECTED_HTTP})"
  [[ "$HTTP_CODE" == "$EXPECTED_HTTP" ]]

  DUMP_FILE="$TMP_DIR/${MODE_CASE}.sql"
  sqlite3 "$DB_FILE" .dump > "$DUMP_FILE"

  for NEEDLE in \
    "sk-ant-" \
    "A9b8C7d6E5f4" \
    "sk-or-v1-" \
    "deadbeefcafe1234" \
    "BEGIN RSA PRIVATE KEY" \
    "SecretPemLineOne999" \
    "SecretPemLineTwo888" \
    "HeaderKeySecretValue" \
    "${CUSTOM_HDR_VAL}" \
    "998877665544"; do
    if grep -Fq "$NEEDLE" "$DUMP_FILE"; then
      echo "FAIL: Found leaked secret substring '$NEEDLE' in $DUMP_FILE!" >&2
      exit 1
    fi
  done

  "$PYTHON" - "$DB_FILE" "$MODE_CASE" "${#CUSTOM_HDR_VAL}" <<'PY'
import json, sqlite3, sys
db_file, mode_case, expected_len = sys.argv[1], sys.argv[2], int(sys.argv[3])
conn = sqlite3.connect(db_file)
row = conn.execute("SELECT headers_json, secrets_json, prompt_preview, blocked FROM traces").fetchone()
conn.close()
headers = json.loads(row[0])
secrets = json.loads(row[1])
preview = row[2]
blocked = row[3]
custom = [h for h in headers if h["name"].lower() == "x-custom-token"]
assert len(custom) == 1, f"Missing X-Custom-Token audit entry: {headers}"
assert custom[0]["value_length"] == expected_len, custom[0]
assert set(custom[0].keys()) == {"name", "value_length", "category", "action"}, custom[0]
if mode_case == "noblock_default":
    assert preview == "", f"Expected empty preview by default, got {preview!r}"
elif mode_case == "block_previews":
    assert blocked == 1 and preview == "", f"Expected empty preview on blocked request, got {preview!r}"
    assert len(secrets) >= 3 and all(set(s.keys()) == {"rule", "field"} for s in secrets), secrets
print(f"  Verified {mode_case}: sqlite3 .dump has 0 secret/header values; X-Custom-Token value_length={custom[0]['value_length']}; preview_len={len(preview)}")
PY
done

# ---------------------------------------------------------------------------
# Supplemental Row (X14): Enumerate ALL TEXT columns in traces.db, inject
#                         sk-ant-... into every reachable column with
#                         --block-secrets OFF and ON, dump full DB -> 0 hits
# ---------------------------------------------------------------------------
echo ""
echo "--- [Supplemental X14] Full TEXT-Column Secret Injection Audit (block OFF & ON) ---"

for BLOCK_MODE in "off" "on"; do
  PORT="$(pick_free_port)"
  DB_X14="$TMP_DIR/x14_${BLOCK_MODE}.db"
  SRV_ARGS=(--lang en serve --port "$PORT" --db "$DB_X14" --auth-token "x14-tok" --store-previews)
  EXPECTED_HTTP="200"
  if [[ "$BLOCK_MODE" == "on" ]]; then
    SRV_ARGS+=(--block-secrets)
    EXPECTED_HTTP="400"
  fi

  "$XRAY" "${SRV_ARGS[@]}" >"$TMP_DIR/x14_${BLOCK_MODE}.log" 2>&1 &
  SRV_PID="$!"
  PIDS+=("$SRV_PID")
  wait_for_xray "$PORT"

  X14_BODY="$TMP_DIR/x14_body_${BLOCK_MODE}.json"
  "$PYTHON" - "$X14_BODY" <<'PY'
import json, sys
body = {
    "model": "claude-sk-ant-api03-COLMODEL5555555555555555555555555555",
    "tools": [
        {
            "name": "mcp__sk-ant-api03-COLNS6666666666666666666666666666__exec",
            "description": "tool",
            "input_schema": {"type": "object"},
        }
    ],
    "messages": [
        {
            "role": "user",
            "content": "hello sk-ant-api03-COLPREVIEW7777777777777777777777777777",
        }
    ],
    "sk-ant-api03-COLFIELD8888888888888888888888888888": "sk-ant-api03-COLFVAL9999999999999999999999999999",
}
with open(sys.argv[1], "w", encoding="utf-8") as f:
    json.dump(body, f)
PY

  HTTP_X14="$(curl -s -o "$TMP_DIR/x14_resp_${BLOCK_MODE}.json" -w '%{http_code}' \
    -X POST "http://127.0.0.1:${PORT}/anthropic/v1/projects/sk-ant-api03-COLPATH1111111111111111111111111111/messages?key=sk-ant-api03-COLQUERY2222222222222222222222222222&gh=ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890" \
    -H "Content-Type: application/json" \
    -H "X-sk-ant-api03-COLHDRNAME3333333333333333333333333333: sk-ant-api03-COLHDRVAL4444444444444444444444444444" \
    --data-binary "@${X14_BODY}")"

  kill "$SRV_PID" 2>/dev/null || true
  wait "$SRV_PID" 2>/dev/null || true
  [[ "$HTTP_X14" == "$EXPECTED_HTTP" ]]

  # Also exercise buckets_json (session_id via desktop import) + provider / usage_json via TraceStore
  "$PYTHON" - "$DB_X14" "$TMP_DIR/x14_home_${BLOCK_MODE}" "$BLOCK_MODE" <<'PY'
import json, pathlib, sqlite3, sys
from agent_xray.local_sessions import import_local_desktop_sessions
from agent_xray.store import TraceStore

db_path, home_dir, block_mode = sys.argv[1], pathlib.Path(sys.argv[2]), sys.argv[3]
proj = home_dir / ".claude" / "projects" / "proj-x14"
proj.mkdir(parents=True, exist_ok=True)
jf = proj / "sk-ant-api03-COLSESSAAAABBBBCCCCDDDDEEEEFFFF1111.jsonl"
jf.write_text(
    json.dumps(
        {
            "type": "assistant",
            "timestamp": "2026-11-14T00:00:00Z",
            "requestId": "req_x14",
            "message": {
                "id": "msg_x14",
                "role": "assistant",
                "model": "claude-sk-ant-api03-COLIMPMODEL222222222222222222222222",
                "usage": {"input_tokens": 10, "output_tokens": 5},
            },
        }
    )
    + "\n",
    encoding="utf-8",
)
store = TraceStore(db_path)
import_local_desktop_sessions(store, home=home_dir, max_turns=10)
store.record_turn(
    provider="prov-sk-ant-api03-COLPROV3333333333333333333333333333",
    model="claude-sk-ant-api03-COLDIRECTMODEL444444444444444444444444",
    path="/v1/sk-ant-api03-COLDIRECTPATH555555555555555555555555?api_key=sk-ant-api03-COLDIRECTQ666666666666666666666666",
    status_code=400 if block_mode == "on" else 200,
    latency_ms=5,
    blocked=(block_mode == "on"),
    buckets={"system_prompt": 1, "session_id": "sess-sk-ant-api03-COLBUCKETS777777777777777777777777"},
    tool_namespaces=[{"namespace": "mcp:sk-ant-api03-COLNSDIR888888888888888888888888", "tool_count": 1, "estimated_tokens": 1}],
    usage={"input_tokens": 1, "output_tokens": 1, "sk-ant-api03-COLUSAGE999999999999999999999999": 1},
    header_audit=[{"name": "X-sk-ant-api03-COLHDRDIR000000000000000000000000", "value_length": 12}],
    secret_findings=[{"rule": "Rule-sk-ant-api03-COLRULE121212121212121212121212", "field": "sk-ant-api03-COLSECFIELD343434343434343434343434"}],
    prompt_preview="preview sk-ant-api03-COLPREVDIR565656565656565656565656",
    store_previews=True,
)
store.close()

conn = sqlite3.connect(db_path)
text_cols = [r[1] for r in conn.execute("PRAGMA table_info(traces)").fetchall() if r[2].upper() == "TEXT"]
expected_cols = [
    "provider", "model", "path", "buckets_json", "namespaces_json",
    "usage_json", "headers_json", "secrets_json", "prompt_preview",
]
assert text_cols == expected_cols, (text_cols, expected_cols)
paths = [r[0] for r in conn.execute("SELECT path FROM traces").fetchall()]
assert all("?" not in p for p in paths), f"Query string leaked into path column: {paths}"
dump_text = "\n".join(conn.iterdump())
conn.close()

forbidden = [
    "sk-ant-", "ghp_",
    "COLPATH", "COLQUERY", "COLHDRNAME", "COLHDRVAL", "COLMODEL",
    "COLNS", "COLPREVIEW", "COLFIELD", "COLFVAL", "COLSESS",
    "COLIMPMODEL", "COLPROV", "COLDIRECTMODEL", "COLDIRECTPATH",
    "COLDIRECTQ", "COLBUCKETS", "COLNSDIR", "COLUSAGE",
    "COLHDRDIR", "COLRULE", "COLSECFIELD", "COLPREVDIR",
]
hits = [tok for tok in forbidden if tok in dump_text]
assert not hits, f"Leaked tokens in dump ({block_mode}): {hits}"
print(f"  block_secrets={block_mode}: HTTP={400 if block_mode == 'on' else 200}, text_columns={len(text_cols)} ({','.join(text_cols)}), dump_secret_hits=0")
PY
done

# ---------------------------------------------------------------------------
# Row 3 & Row 4: Host DNS-rebinding check, Cross-Origin POST check, Token Auth,
#                and --allow-lan guard (tested in EN and ZH)
# ---------------------------------------------------------------------------
echo ""
echo "--- [Row 3 & Row 4] Host Validation, Cross-Origin POST & Token Auth (EN & ZH) ---"

for LANG_CODE in en zh; do
  PORT="$(pick_free_port)"
  DB_SEC="$TMP_DIR/sec_${LANG_CODE}.db"
  TOK="m0-guard-token-${LANG_CODE}"
  "$XRAY" --lang "$LANG_CODE" serve --port "$PORT" --db "$DB_SEC" --auth-token "$TOK" >"$TMP_DIR/sec_${LANG_CODE}.log" 2>&1 &
  SRV_PID="$!"
  PIDS+=("$SRV_PID")
  wait_for_xray "$PORT"

  CODE_BAD_HOST="$(curl -s -o /dev/null -w '%{http_code}' -H 'Host: attacker.example' "http://127.0.0.1:${PORT}/_xray/api/summary")"
  CODE_CROSS_ORIGIN="$(curl -s -o /dev/null -w '%{http_code}' -X POST -H 'Origin: http://attacker.example' "http://127.0.0.1:${PORT}/_xray/api/scan-desktop")"
  CODE_NO_TOKEN="$(curl -s -o /dev/null -w '%{http_code}' -X POST "http://127.0.0.1:${PORT}/_xray/api/clear")"
  CODE_WITH_TOKEN="$(curl -s -o /dev/null -w '%{http_code}' -X POST -H "X-Xray-Token: ${TOK}" "http://127.0.0.1:${PORT}/_xray/api/clear")"

  kill "$SRV_PID" 2>/dev/null || true
  wait "$SRV_PID" 2>/dev/null || true

  echo "Lang=${LANG_CODE}: Host:attacker.example -> HTTP ${CODE_BAD_HOST} | Cross-Origin POST -> HTTP ${CODE_CROSS_ORIGIN} | Missing-Token POST -> HTTP ${CODE_NO_TOKEN} | Valid-Token POST -> HTTP ${CODE_WITH_TOKEN}"
  [[ "$CODE_BAD_HOST" == "403" ]]
  [[ "$CODE_CROSS_ORIGIN" == "403" ]]
  [[ "$CODE_NO_TOKEN" == "401" ]]
  [[ "$CODE_WITH_TOKEN" == "200" ]]

  set +e
  LAN_ERR="$("$XRAY" --lang "$LANG_CODE" serve --allow-lan --db "$TMP_DIR/never_${LANG_CODE}.db" 2>&1)"
  LAN_RC=$?
  set -e
  echo "Lang=${LANG_CODE}: serve --allow-lan (no --auth-token) -> exit=${LAN_RC} | msg=${LAN_ERR}"
  [[ "$LAN_RC" -ne 0 ]]
done

# ---------------------------------------------------------------------------
# Row 5: Cache Hit Rate (87% = 8000/9200), Sonnet vs Opus Pricing, Unknown Price,
#        Unverified Pricing Label, and Failed Upstream 429 = $0.0000 (EN & ZH)
# ---------------------------------------------------------------------------
echo ""
echo "--- [Row 5] Cache Hit Rate (87%) & Per-Model Pricing (Sonnet vs Opus vs Unknown vs 429, EN & ZH) ---"

for MODEL_CASE in "claude-sonnet-4-5:0.01425" "claude-opus-4-1:0.07125" "unknown-private-llm:null"; do
  MODEL_NAME="${MODEL_CASE%%:*}"
  EXP_COST="${MODEL_CASE##*:}"
  PORT="$(pick_free_port)"
  DB_COST="$TMP_DIR/cost_${MODEL_NAME}.db"
  "$XRAY" --lang en serve --port "$PORT" --db "$DB_COST" --auth-token "cost-tok" >"$TMP_DIR/cost_${MODEL_NAME}.log" 2>&1 &
  SRV_PID="$!"
  PIDS+=("$SRV_PID")
  wait_for_xray "$PORT"

  curl -fsS -X POST "http://127.0.0.1:${PORT}/anthropic/v1/messages" \
    -H "Content-Type: application/json" \
    -d "{\"model\":\"${MODEL_NAME}\",\"messages\":[{\"role\":\"user\",\"content\":\"Compute token usage\"}]}" >/dev/null

  if [[ "$MODEL_NAME" == "claude-sonnet-4-5" ]]; then
    curl -s -o /dev/null -X POST "http://127.0.0.1:${PORT}/anthropic/v1/messages" \
      -H "Content-Type: application/json" \
      -H "X-Mock-Status: 429" \
      -d "{\"model\":\"${MODEL_NAME}\",\"messages\":[{\"role\":\"user\",\"content\":\"Rate limit test\"}]}"
  fi

  SUMMARY_JSON="$(curl -fsS "http://127.0.0.1:${PORT}/_xray/api/summary")"
  UI_EN="$(curl -fsS "http://127.0.0.1:${PORT}/_xray/?lang=en")"
  UI_ZH="$(curl -fsS "http://127.0.0.1:${PORT}/_xray/?lang=zh")"

  kill "$SRV_PID" 2>/dev/null || true
  wait "$SRV_PID" 2>/dev/null || true

  REP_EN="$("$XRAY" --lang en report --db "$DB_COST" 2>&1)"
  REP_ZH="$("$XRAY" --lang zh report --db "$DB_COST" 2>&1)"

  "$PYTHON" - "$MODEL_NAME" "$EXP_COST" "$SUMMARY_JSON" "$UI_EN" "$UI_ZH" "$REP_EN" "$REP_ZH" <<'PY'
import json, math, sys
model, exp_cost, sum_raw, ui_en, ui_zh, rep_en, rep_zh = sys.argv[1:8]
data = json.loads(sum_raw)
s = data["summary"]
t0 = data["traces"][0]
expected_ratio = round(8000 / 9200, 6)
assert math.isclose(t0["cache_hit_ratio"], expected_ratio, rel_tol=0, abs_tol=1e-6), t0["cache_hit_ratio"]
assert "87%" in rep_en and "87%" in rep_zh, (rep_en, rep_zh)
if exp_cost == "null":
    assert t0["estimated_cost_usd"] is None, t0["estimated_cost_usd"]
    assert s["estimated_cost_usd"] is None, s["estimated_cost_usd"]
    assert "Unknown price" in rep_en and "Unknown price" in ui_en
    assert "未知价格" in rep_zh and "未知价格" in ui_zh
    print(f"  Model={model}: hit_ratio={t0['cache_hit_ratio']} (87%), cost=null ('Unknown price' / '未知价格') OK")
else:
    want = float(exp_cost)
    assert math.isclose(t0["estimated_cost_usd"], want, rel_tol=0, abs_tol=1e-9), (t0["estimated_cost_usd"], want)
    assert math.isclose(s["estimated_cost_usd"], want, rel_tol=0, abs_tol=1e-9), (s["estimated_cost_usd"], want)
    cost_token = f"${exp_cost}"
    assert cost_token in rep_en and cost_token in rep_zh, (cost_token, rep_en, rep_zh)
    assert "(unverified)" in rep_en and "（未核对）" in rep_zh, (rep_en, rep_zh)
    if len(data["traces"]) > 1:
        assert data["traces"][1]["status_code"] == 429 and data["traces"][1]["estimated_cost_usd"] == 0.0
    print(f"  Model={model}: hit_ratio={t0['cache_hit_ratio']} (87%), exact_cost=${exp_cost} (unverified / 未核对) OK")
PY
done

# ---------------------------------------------------------------------------
# Row 6 (X17): Isolated Empty-HOME + Authentic OpenCode Schema Fixture Scan
#              (Aggregate Usage Only, Zero Fixed Ratios, Cache Hit <= 100%)
# ---------------------------------------------------------------------------
echo ""
echo "--- [Row 6 & X17] Isolated Desktop Scan (Empty HOME + Real OpenCode DDL Fixture, EN & ZH) ---"

EMPTY_HOME="$TMP_DIR/empty_home"
mkdir -p "$EMPTY_HOME"
EMPTY_OUT="$("$XRAY" --lang en desktop --home "$EMPTY_HOME" --db "$TMP_DIR/empty_desk.db" --import-only 2>&1)"
echo "$EMPTY_OUT"
[[ "$EMPTY_OUT" == *"Imported 0 recent Desktop/local turns"* ]]

FIXTURE_HOME="$TMP_DIR/fixture_home"
"$PYTHON" - "$FIXTURE_HOME" "${ROOT_DIR}/tests/fixtures/opencode_schema.sql" <<'PY'
import json, pathlib, sqlite3, sys

home = pathlib.Path(sys.argv[1])
schema_sql = pathlib.Path(sys.argv[2]).read_text(encoding="utf-8")

oc_dir = home / ".local" / "share" / "opencode"
oc_dir.mkdir(parents=True, exist_ok=True)
conn = sqlite3.connect(str(oc_dir / "opencode.db"))
conn.execute("PRAGMA foreign_keys = ON")
conn.executescript(schema_sql)
conn.execute(
    "INSERT INTO project (id, worktree, sandboxes, time_created, time_updated) VALUES (?, ?, ?, ?, ?)",
    ("proj_1", "/workspace/demo", "[]", 1762000000000, 1762000000000),
)
conn.execute(
    """
    INSERT INTO session_v2 (
        id, project_id, slug, directory, title, version,
        cost, tokens_input, tokens_output, tokens_reasoning,
        tokens_cache_read, tokens_cache_write, time_created, time_updated
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """,
    (
        "ses_m0_1", "proj_1", "demo-slug", "/workspace/demo", "Demo Session", "2.3.0",
        99.99, 999999, 88888, 0, 7777777, 666666, 1762000000000, 1762000050000,
    ),
)
for seq_no, (mid, ts, in_t, out_t, cr_t, cw_t) in enumerate(
    (
        ("msg_m0_1", 1762000010000, 500, 120, 2000, 500),
        ("msg_m0_2", 1762000020000, 300, 90, 2500, 200),
    ),
    start=1,
):
    data = {
        "model": {"id": "claude-sonnet-4-5", "providerID": "anthropic"},
        "tokens": {
            "input": in_t,
            "output": out_t,
            "reasoning": 0,
            "cache": {"read": cr_t, "write": cw_t},
        },
        "time": {"created": ts, "completed": ts + 450},
    }
    conn.execute(
        "INSERT INTO session_message VALUES (?, ?, 'assistant', ?, ?, ?, ?)",
        (mid, "ses_m0_1", seq_no, ts, ts + 450, json.dumps(data)),
    )
conn.commit()
conn.close()

cl_dir = home / ".claude" / "projects" / "demo-proj"
cl_dir.mkdir(parents=True, exist_ok=True)
chunks = [
    {
        "type": "assistant",
        "timestamp": "2026-11-10T10:00:01Z",
        "requestId": "req_cl_1",
        "message": {
            "id": "msg_cl_1",
            "role": "assistant",
            "model": "claude-sonnet-4-5",
            "usage": {"input_tokens": 200, "cache_read_input_tokens": 1800, "cache_creation_input_tokens": 0, "output_tokens": 10},
        },
    },
    {
        "type": "assistant",
        "timestamp": "2026-11-10T10:00:02Z",
        "requestId": "req_cl_1",
        "message": {
            "id": "msg_cl_1",
            "role": "assistant",
            "model": "claude-sonnet-4-5",
            "usage": {"input_tokens": 200, "cache_read_input_tokens": 1800, "cache_creation_input_tokens": 0, "output_tokens": 80},
        },
    },
]
(cl_dir / "session-a.jsonl").write_text("\n".join(json.dumps(c) for c in chunks) + "\n", encoding="utf-8")
PY

for LANG_CODE in en zh; do
  DB_DESK="$TMP_DIR/desktop_fixture_${LANG_CODE}.db"
  DESK_OUT="$("$XRAY" --lang "$LANG_CODE" desktop --home "$FIXTURE_HOME" --db "$DB_DESK" --limit 24 --import-only 2>&1)"
  echo "$DESK_OUT"
  "$PYTHON" - "$DB_DESK" "$LANG_CODE" <<'PY'
import sys
from agent_xray.store import TraceStore

db_path, lang_code = sys.argv[1], sys.argv[2]
store = TraceStore(db_path)
data = store.build_summary(limit=100)
store.close()

traces = data["traces"]
summary = data["summary"]
assert len(traces) == 3, f"Expected 3 deduplicated per-turn records (2 OpenCode + 1 Claude), got {len(traces)}"
assert summary["total_actual_input"] == 1000, summary["total_actual_input"]
assert summary["total_cache_read"] == 6300, summary["total_cache_read"]
assert summary["total_cache_write"] == 700, summary["total_cache_write"]
assert summary["total_output_tokens"] == 290, summary["total_output_tokens"]
assert 0.0 <= summary["cache_hit_ratio"] <= 1.0, summary["cache_hit_ratio"]
assert summary["total_estimated_input"] == 0, summary["total_estimated_input"]
for tr in traces:
    assert tr["has_bucket_breakdown"] is False
    assert all(v == 0 for v in tr["buckets"].values())
    assert tr["prompt_preview"] == ""
    assert 0.0 <= tr["cache_hit_ratio"] <= 1.0
print(
    f"  Verified fixture desktop ({lang_code}): imported_turns={len(traces)}, "
    f"all_buckets_zero=True, has_bucket_breakdown=False, "
    f"summary_cache_hit_ratio={summary['cache_hit_ratio']:.4f} (6300/8000 <= 1.0), "
    f"cost_usd={summary['estimated_cost_usd']}"
)
PY
done

# ---------------------------------------------------------------------------
# Row 7 (W4 & X16): Non-UI Python Source Scan for Fixed-Ratio Multipliers +
#                   Genuine CSS Restoration Check + pyproject Description Check
# ---------------------------------------------------------------------------
echo ""
echo "--- [Row 7, W4 & X16] Source Ratio Scan (excluding ui_html.py CSS) & Metadata Check ---"
if grep -rnE '\b0\.(12|28|34)\b' src/ --include='*.py' --exclude='ui_html.py'; then
  echo "FAIL: Found fixed-ratio multipliers in non-UI Python source!" >&2
  exit 1
fi
grep -Fq 'oklch(0.515 0.092 188 / 0.12)' src/agent_xray/ui_html.py
grep -Fq 'oklch(0.665 0.175 32 / 0.28)' src/agent_xray/ui_html.py
echo "grep -rnE '\\b0\\.(12|28|34)\\b' src/ --exclude='ui_html.py' -> 0 matches; ui_html.py oklch 0.12 & 0.28 intact (PASS)"

if grep -in 'streaming' pyproject.toml; then
  echo "FAIL: pyproject.toml still claims streaming proxy!" >&2
  exit 1
fi
echo "grep -in 'streaming' pyproject.toml -> 0 matches (PASS)"

# ---------------------------------------------------------------------------
# Supplemental Row (W1): Scripted Mutation Suite in Isolated Temp Copy
#                        Apply each fault -> run named test -> assert FAILED
# ---------------------------------------------------------------------------
echo ""
echo "--- [Supplemental W1] Automated Mutation Verification (7 M0 Acceptance Rows) ---"

MUT_DIR="$TMP_DIR/mut_copy"
mkdir -p "$MUT_DIR"
cp -R "${ROOT_DIR}/src" "${ROOT_DIR}/tests" "${ROOT_DIR}/pyproject.toml" "$MUT_DIR/"

"$PYTHON" - "$MUT_DIR" "$PYTHON" <<'PY'
import pathlib, subprocess, sys

mut_dir = pathlib.Path(sys.argv[1])
python_bin = sys.argv[2]

mutations = [
    (
        "X14_sqlite_write_boundary_sanitizer",
        "src/agent_xray/store.py",
        "sanitized_params = tuple(_sanitize_db_value(p) for p in params)",
        "sanitized_params = tuple(json.dumps(p) if isinstance(p, (dict, list, tuple)) else p for p in params)",
        "tests.test_proxy.ProxySecurityAndPrivacyTests.test_all_sqlite_columns_sanitized_against_request_secrets",
    ),
    (
        "Row1_prompt_preview_truncate_before_redact",
        "src/agent_xray/store.py",
        "safe_preview = redact_secrets_in_text(prompt_preview).strip()[:140]",
        "safe_preview = prompt_preview.strip()[:140]",
        "tests.test_privacy.PrivacyAndRedactionTests.test_default_zero_preview_and_redact_before_truncate_and_blocked_metadata",
    ),
    (
        "Row2_header_display_value_persisted",
        "src/agent_xray/privacy.py",
        '"action": self.action,',
        '"action": self.action, "display_value": str(self.value_length),',
        "tests.test_privacy.PrivacyAndRedactionTests.test_headers_persist_only_name_and_value_length",
    ),
    (
        "Row3_dns_rebinding_host_guard_bypassed",
        "src/agent_xray/proxy.py",
        "if raw_host not in loopback_hosts:",
        "if False and raw_host not in loopback_hosts:",
        "tests.test_proxy.ProxySecurityAndPrivacyTests.test_host_origin_and_token_guards_on_ui_and_api",
    ),
    (
        "Row4_mutation_post_token_guard_bypassed",
        "src/agent_xray/proxy.py",
        "if require_token or is_lan_mode:",
        "if False and (require_token or is_lan_mode):",
        "tests.test_proxy.ProxySecurityAndPrivacyTests.test_host_origin_and_token_guards_on_ui_and_api",
    ),
    (
        "Row5_cache_hit_denominator_missing_cache_write",
        "src/agent_xray/store.py",
        "denom = max(0, int(input_tokens)) + max(0, int(cache_read_tokens)) + max(0, int(cache_write_tokens))",
        "denom = max(0, int(input_tokens)) + max(0, int(cache_read_tokens))",
        "tests.test_store.StorePricingCacheAndLabelsTests.test_sonnet_vs_opus_pricing_cache_write_and_87pct_hit_rate",
    ),
    (
        "Row6_desktop_fabricated_bucket_flag",
        "src/agent_xray/local_sessions.py",
        '"has_bucket_breakdown": False,',
        '"has_bucket_breakdown": True,',
        "tests.test_desktop.DesktopLocalSessionTests.test_opencode_per_turn_import_ignores_session_v2_cumulative_totals",
    ),
]

for label, rel_path, target, replacement, dotted_test in mutations:
    fpath = mut_dir / rel_path
    orig = fpath.read_text(encoding="utf-8")
    assert target in orig, f"Target not found for mutation {label} in {rel_path}"
    try:
        fpath.write_text(orig.replace(target, replacement, 1), encoding="utf-8")

        proc = subprocess.run(
            [python_bin, "-m", "unittest", dotted_test],
            cwd=str(mut_dir),
            env={"PYTHONPATH": str(mut_dir / "src"), "PYTHONDONTWRITEBYTECODE": "1", "PATH": "/usr/bin:/bin"},
            capture_output=True,
            text=True,
            timeout=30,
        )
        combined = (proc.stdout or "") + "\n" + (proc.stderr or "")
        assert proc.returncode != 0, f"Mutation {label} SURVIVED (exit 0)!\n{combined}"
        for bad_err in ("SyntaxError", "ImportError", "ModuleNotFoundError", "IndentationError"):
            assert bad_err not in combined, f"Mutation {label} broke import/syntax instead of test assertion:\n{combined}"
        assert ("FAIL:" in combined or "AssertionError" in combined), f"Unexpected failure output for {label}:\n{combined}"
        print(f"  [KILLED] {label} -> {dotted_test} failed with AssertionError (exit={proc.returncode})")
    finally:
        fpath.write_text(orig, encoding="utf-8")
PY

diff -ru "${ROOT_DIR}/src" "${MUT_DIR}/src"
echo "All 7 mutations killed by named tests and isolated copy cleanly restored (PASS)"

echo ""
echo "=== ALL M0 ACCEPTANCE & SUPPLEMENTAL CHECKS PASSED (EN & ZH) ==="
