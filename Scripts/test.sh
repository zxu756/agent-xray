#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

PYTEST="${ROOT_DIR}/.venv/bin/pytest"
if [[ ! -x "$PYTEST" ]]; then
  PYTEST="pytest"
fi

usage() {
  cat >&2 <<'EOF'
Usage:
  Scripts/test.sh scope <classifier|proxy|privacy|store|desktop|cli> [...]
  Scripts/test.sh milestone <N>
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
        *)
          echo "Unknown scope: $mod" >&2
          usage
          ;;
      esac
    done
    if [[ ${#FILES[@]} -gt 0 ]]; then
      "$PYTEST" -q "${FILES[@]}"
    fi
    if [[ ${#K_EXPR[@]} -gt 0 ]]; then
      EXPR=""
      for k in "${K_EXPR[@]}"; do
        if [[ -z "$EXPR" ]]; then EXPR="$k"; else EXPR="$EXPR or $k"; fi
      done
      "$PYTEST" -q tests/test_xray.py -k "$EXPR"
    fi
    ;;

  milestone)
    if [[ $# -ne 1 ]]; then
      usage
    fi
    MS="$1"
    if [[ "$MS" != "0" ]]; then
      echo "Milestone M${MS} acceptance script is not implemented yet." >&2
      exit 2
    fi
    "$PYTEST" -q
    if [[ -x Scripts/acceptance/m0-acceptance.sh ]]; then
      Scripts/acceptance/m0-acceptance.sh
    else
      echo "Missing executable Scripts/acceptance/m0-acceptance.sh" >&2
      exit 1
    fi
    if [[ -x Scripts/acceptance/readme-commands.sh ]]; then
      Scripts/acceptance/readme-commands.sh
    else
      echo "Missing executable Scripts/acceptance/readme-commands.sh" >&2
      exit 1
    fi
    ;;

  release)
    "$PYTEST" -q
    if [[ -x Scripts/acceptance/m0-acceptance.sh ]]; then
      Scripts/acceptance/m0-acceptance.sh
    else
      echo "Missing executable Scripts/acceptance/m0-acceptance.sh" >&2
      exit 1
    fi
    if [[ -x Scripts/acceptance/readme-commands.sh ]]; then
      Scripts/acceptance/readme-commands.sh
    else
      echo "Missing executable Scripts/acceptance/readme-commands.sh" >&2
      exit 1
    fi
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
