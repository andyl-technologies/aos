# Shares compilation while retaining exact discovery and per-case execution.
{
  label,
  selectors,
  enterCrates ? true,
}: ''
  ${
    if enterCrates
    then "cd crates"
    else ""
  }
  mkdir -p "$out/logs"
  inventory_log="$out/logs/${label}-inventory.log"
  if "$TERRANE_NATIVE_SDK_TEST_BINARY" --list > "$inventory_log" 2>&1; then
    inventory_status=0
  else
    inventory_status=$?
  fi
  cat "$inventory_log"
  if [ "$inventory_status" -ne 0 ]; then
    exit "$inventory_status"
  fi
  python3 ../tests/terrane/check_native_gate.py inventory \
    "$inventory_log" '${builtins.toJSON selectors}' > /dev/null
  python3 - "$inventory_log" '${builtins.toJSON selectors}' <<'PY_INVENTORY'
  import json
  import pathlib
  import sys

  lines = pathlib.Path(sys.argv[1]).read_text().splitlines()
  required = json.loads(sys.argv[2])
  if any(lines.count(name + ": test") != 1 for name in required):
      raise SystemExit("required native selectors must each occur exactly once")
  PY_INVENTORY

  # Each executable owns fresh protected storage; successful cases release it.
  case_number=0
  for test_name in ${builtins.concatStringsSep " " selectors}; do
    case_number=$((case_number + 1))
    case_tmp=$(mktemp -d "$TMPDIR/tc.XXXXXXXX")
    chmod 700 "$case_tmp"
    case_log="$out/logs/${label}-case-$case_number.log"
    if TMPDIR="$case_tmp" "$TERRANE_NATIVE_SDK_TEST_BINARY" "$test_name" \
      --exact --test-threads=1 > "$case_log" 2>&1; then
      case_status=0
    else
      case_status=$?
    fi
    cat "$case_log"
    if [ "$case_status" -ne 0 ]; then
      exit "$case_status"
    fi
    python3 ../tests/terrane/check_native_gate.py execution \
      "$case_log" "[\"$test_name\"]" > /dev/null
    python3 - "$case_log" "$test_name" <<'PY_EXECUTION'
  import pathlib
  import sys

  lines = pathlib.Path(sys.argv[1]).read_text().splitlines()
  summary = "test result: ok. 1 passed; 0 failed; 0 ignored;"
  if (lines.count("test " + sys.argv[2] + " ... ok") != 1
          or sum(line.startswith("test result:") for line in lines) != 1
          or sum(line.startswith(summary) for line in lines) != 1):
      raise SystemExit("native selector must execute exactly one passing, nonignored test")
  PY_EXECUTION
    rm -rf -- "$case_tmp"
  done
''
