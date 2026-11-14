#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT_DIR"

PYTHON="${ROOT_DIR}/.venv/bin/python"
XRAY="${ROOT_DIR}/.venv/bin/agent-xray"
if [[ ! -x "$XRAY" ]]; then
  echo "Missing $XRAY" >&2
  exit 1
fi

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
# Place secrets both early and past character 140 to verify redact-before-truncate
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

  # Verify X-Custom-Token recorded ONLY name + value_length (37)
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
#        and Failed Upstream 429 = $0.0000 (tested in EN and ZH)
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
    # Also send a 429 turn to verify error turns contribute $0.0000 to cost
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
expected_ratio = round(8000 / 9200, 6)  # 0.869565 -> 87%
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
    if len(data["traces"]) > 1:
        assert data["traces"][1]["status_code"] == 429 and data["traces"][1]["estimated_cost_usd"] == 0.0
    print(f"  Model={model}: hit_ratio={t0['cache_hit_ratio']} (87%), exact_cost=${exp_cost} (EN & ZH CLI + UI) OK")
PY
done

# ---------------------------------------------------------------------------
# Row 6: Local `desktop` Session Scan (Aggregate Usage Only, Zero Fixed Ratios,
#        Cache Hit Rate <= 100%, Zero Conversation Text Logged, EN & ZH)
# ---------------------------------------------------------------------------
echo ""
echo "--- [Row 6] Local Desktop Session Scan Audit (Numeric Metrics Only, EN & ZH) ---"

for LANG_CODE in en zh; do
  DB_DESK="$TMP_DIR/desktop_local_${LANG_CODE}.db"
  DESK_OUT="$("$XRAY" --lang "$LANG_CODE" desktop --db "$DB_DESK" --limit 24 --import-only 2>&1)"
  echo "$DESK_OUT"
  "$PYTHON" - "$DB_DESK" "$LANG_CODE" <<'PY'
import sqlite3, sys
from agent_xray.store import TraceStore

db_path, lang_code = sys.argv[1], sys.argv[2]
store = TraceStore(db_path)
data = store.build_summary(limit=100)
store.close()

traces = data["traces"]
summary = data["summary"]
assert 0.0 <= summary["cache_hit_ratio"] <= 1.0, f"Summary cache_hit_ratio > 100%: {summary['cache_hit_ratio']}"
assert summary["total_estimated_input"] == 0, f"Expected 0 estimated bucket input on desktop import, got {summary['total_estimated_input']}"
for tr in traces:
    assert tr["has_bucket_breakdown"] is False, "Local session turn falsely marked has_bucket_breakdown=True"
    for k, v in tr["buckets"].items():
        assert v == 0, f"Non-zero bucket {k}={v} on local session import"
    assert tr["prompt_preview"] == "", "Prompt preview must be empty on local session import"
    assert 0.0 <= tr["cache_hit_ratio"] <= 1.0, f"Turn cache_hit_ratio > 100%: {tr['cache_hit_ratio']}"
print(
    f"  Verified local desktop ({lang_code}): imported_turns={len(traces)}, "
    f"all_buckets_zero=True, has_bucket_breakdown=False, "
    f"max_turn_cache_hit_ratio={max((t['cache_hit_ratio'] for t in traces), default=0.0):.4f} (<=1.0), "
    f"summary_cache_hit_ratio={summary['cache_hit_ratio']:.4f}, "
    f"known_cost_usd={summary['estimated_cost_usd']}, unknown_price_turns={summary['unknown_price_turn_count']}"
)
PY
done

# ---------------------------------------------------------------------------
# Row 7: Zero Fixed-Ratio Multipliers in src/
# ---------------------------------------------------------------------------
echo ""
echo "--- [Row 7] Source Scan for Fixed-Ratio Bucket Multipliers ---"
if rg -n '0\.12|0\.28|0\.34' src/; then
  echo "FAIL: Found fixed-ratio multipliers in src/!" >&2
  exit 1
fi
echo "rg '0\\.12|0\\.28|0\\.34' src/ -> 0 matches (PASS)"

echo ""
echo "=== ALL 7 M0 ACCEPTANCE CHECKS PASSED (EN & ZH) ==="
