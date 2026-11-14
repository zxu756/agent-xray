#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
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
  echo "Error: Python >= 3.10 is required to run agent-xray tests." >&2
  exit 1
}

PYTHON="$(resolve_python)"
export AGENT_XRAY_PYTHON="$PYTHON"

HAS_PYTEST=0
PYTEST_BIN=""
if [[ -x "${ROOT_DIR}/.venv/bin/pytest" ]]; then
  HAS_PYTEST=1
  PYTEST_BIN="${ROOT_DIR}/.venv/bin/pytest"
elif "$PYTHON" -c 'import pytest' 2>/dev/null; then
  HAS_PYTEST=1
fi

run_pytest_or_unittest_all() {
  if [[ "$HAS_PYTEST" -eq 1 ]]; then
    if [[ -n "$PYTEST_BIN" ]]; then
      PYTHONPATH="${ROOT_DIR}/src" "$PYTEST_BIN" -q -o cache_dir="${TMPDIR:-/tmp}/xray-pytest-cache-$$"
      rm -rf "${TMPDIR:-/tmp}/xray-pytest-cache-$$"
    else
      PYTHONPATH="${ROOT_DIR}/src" "$PYTHON" -m pytest -q -o cache_dir="${TMPDIR:-/tmp}/xray-pytest-cache-$$"
      rm -rf "${TMPDIR:-/tmp}/xray-pytest-cache-$$"
    fi
  else
    PYTHONPATH="${ROOT_DIR}/src" "$PYTHON" -m unittest discover -s tests -p 'test_*.py'
  fi
}

scrub_report_paths() {
  local infile="$1"
  local outfile="$2"
  "$PYTHON" - "$infile" "$outfile" "$ROOT_DIR" <<'PY'
import pathlib, re, sys

src, dst, root_dir = sys.argv[1], sys.argv[2], sys.argv[3]
text = pathlib.Path(src).read_text(encoding="utf-8")
text = text.replace(root_dir, "<repo>")
text = re.sub(r"/private/var/folders/[^\s\"')]+", "<mktemp>", text)
text = re.sub(r"/var/folders/[^\s\"')]+", "<mktemp>", text)
text = re.sub(r"/tmp/xray-[A-Za-z0-9._-]+", "<mktemp>", text)
macos_home_re = "/" + "Users" + r"/[^\s/\"')]+"
text = re.sub(macos_home_re, "<user-home>", text)
pathlib.Path(dst).parent.mkdir(parents=True, exist_ok=True)
pathlib.Path(dst).write_text(text, encoding="utf-8")
PY
}

usage() {
  cat >&2 <<'EOF'
Usage:
  Scripts/test.sh scope <classifier|proxy|privacy|store|desktop|cli|i18n> [...]
  Scripts/test.sh milestone <N> [--record]
  Scripts/test.sh release
EOF
  exit 2
}

if [[ $# -lt 1 ]]; then
  usage
fi

MODE="$1"
shift

case "$MODE" in
  scope)
    if [[ $# -lt 1 ]]; then
      usage
    fi
    FILES=()
    K_EXPR=()
    for mod in "$@"; do
      case "$mod" in
        classifier)
          [[ -f tests/test_classifier.py ]] && FILES+=("tests/test_classifier.py")
          K_EXPR+=("five_bucket" "openai_responses")
          ;;
        privacy)
          [[ -f tests/test_privacy.py ]] && FILES+=("tests/test_privacy.py")
          K_EXPR+=("header_stripping_and_secret_redaction")
          ;;
        store)
          [[ -f tests/test_store.py ]] && FILES+=("tests/test_store.py")
          K_EXPR+=("demo_dataset")
          ;;
        proxy)
          [[ -f tests/test_proxy.py ]] && FILES+=("tests/test_proxy.py")
          K_EXPR+=("sse_streaming_passthrough")
          ;;
        desktop)
          [[ -f tests/test_desktop.py ]] && FILES+=("tests/test_desktop.py")
          ;;
        cli)
          [[ -f tests/test_cli.py ]] && FILES+=("tests/test_cli.py")
          K_EXPR+=("version_and_bilingual_cli")
          ;;
        i18n)
          [[ -f tests/test_i18n.py ]] && FILES+=("tests/test_i18n.py")
          ;;
        *)
          echo "Unknown scope: $mod" >&2
          usage
          ;;
      esac
    done
    if [[ "$HAS_PYTEST" -eq 1 ]]; then
      CACHE_TMP="${TMPDIR:-/tmp}/xray-pytest-cache-$$"
      if [[ ${#FILES[@]} -gt 0 ]]; then
        if [[ -n "$PYTEST_BIN" ]]; then
          PYTHONPATH="${ROOT_DIR}/src" "$PYTEST_BIN" -q -o cache_dir="$CACHE_TMP" "${FILES[@]}"
        else
          PYTHONPATH="${ROOT_DIR}/src" "$PYTHON" -m pytest -q -o cache_dir="$CACHE_TMP" "${FILES[@]}"
        fi
      fi
      if [[ ${#K_EXPR[@]} -gt 0 ]]; then
        EXPR=""
        for k in "${K_EXPR[@]}"; do
          if [[ -z "$EXPR" ]]; then EXPR="$k"; else EXPR="$EXPR or $k"; fi
        done
        if [[ -n "$PYTEST_BIN" ]]; then
          PYTHONPATH="${ROOT_DIR}/src" "$PYTEST_BIN" -q -o cache_dir="$CACHE_TMP" tests/test_xray.py -k "$EXPR"
        else
          PYTHONPATH="${ROOT_DIR}/src" "$PYTHON" -m pytest -q -o cache_dir="$CACHE_TMP" tests/test_xray.py -k "$EXPR"
        fi
      fi
      rm -rf "$CACHE_TMP"
    else
      UNIT_TARGETS=()
      for f in ${FILES[@]+"${FILES[@]}"}; do
        UNIT_TARGETS+=("$f")
      done
      if [[ ${#K_EXPR[@]} -gt 0 ]]; then
        UNIT_TARGETS+=("tests/test_xray.py")
      fi
      if [[ ${#UNIT_TARGETS[@]} -gt 0 ]]; then
        PYTHONPATH="${ROOT_DIR}/src" "$PYTHON" -m unittest "${UNIT_TARGETS[@]}"
      fi
    fi
    ;;

  milestone)
    if [[ $# -lt 1 || $# -gt 2 ]]; then
      usage
    fi
    MS="$1"
    RECORD=0
    if [[ $# -eq 2 ]]; then
      if [[ "$2" == "--record" ]]; then
        RECORD=1
      else
        usage
      fi
    fi
    if [[ "$MS" != "0" ]]; then
      echo "Milestone M${MS} acceptance script is not implemented yet." >&2
      exit 2
    fi

    run_pytest_or_unittest_all

    if [[ ! -x Scripts/acceptance/m0-acceptance.sh ]]; then
      echo "Missing executable Scripts/acceptance/m0-acceptance.sh" >&2
      exit 1
    fi
    if [[ ! -x Scripts/acceptance/readme-commands.sh ]]; then
      echo "Missing executable Scripts/acceptance/readme-commands.sh" >&2
      exit 1
    fi

    if [[ "$RECORD" -eq 1 ]]; then
      REC_TMP="$(mktemp -d "${TMPDIR:-/tmp}/xray-record.XXXXXX")"
      trap 'rm -rf "$REC_TMP"' EXIT
      Scripts/acceptance/m0-acceptance.sh | tee "$REC_TMP/m0-acceptance.raw"
      Scripts/acceptance/readme-commands.sh | tee "$REC_TMP/readme-commands.raw"
      scrub_report_paths "$REC_TMP/m0-acceptance.raw" "${ROOT_DIR}/reports/m0-acceptance.txt"
      scrub_report_paths "$REC_TMP/readme-commands.raw" "${ROOT_DIR}/reports/readme-commands.txt"
      rm -rf "$REC_TMP"
      trap - EXIT
    else
      Scripts/acceptance/m0-acceptance.sh
      Scripts/acceptance/readme-commands.sh
    fi
    ;;

  release)
    run_pytest_or_unittest_all
    Scripts/acceptance/m0-acceptance.sh
    Scripts/acceptance/readme-commands.sh
    if [[ "${XRAY_REAL_API:-0}" == "1" ]]; then
      echo "XRAY_REAL_API=1 enabled: live tokenizer accuracy harness belongs to M1 (not implemented in M0)." >&2
      exit 2
    else
      echo "Real API checks: SKIPPED (XRAY_REAL_API!=1)"
    fi
    ;;

  *)
    usage
    ;;
esac
