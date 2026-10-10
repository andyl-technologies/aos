{
  sourceGate,
  coreutils,
}: let
  names = [
    "native_index_multi_edit_batches_and_resynchronizes_canonically"
    "native_index_multi_edit_batches_and_resynchronizes_canonically_1024_adversarial"
    "native_index_multi_edit_batches_and_resynchronizes_canonically_2048_ordinary"
    "native_index_multi_edit_batches_and_resynchronizes_canonically_2048_adversarial"
    "native_index_multi_edit_batches_and_resynchronizes_canonically_4096_ordinary"
    "native_index_multi_edit_batches_and_resynchronizes_canonically_4096_adversarial"
  ];
  selectors = map (name: "guard::index_contract_tests::${name}") names;
in
  # This focused prerequisite preserves the owning index gate's deliberate
  # qualification blocker until every growing-population witness passes.
  sourceGate "native-index-populations" ''
    cd crates
    mkdir -p "$out/logs"
    inventory_log="$out/logs/index-populations-tests.txt"
    "$TERRANE_NATIVE_SDK_TEST_BINARY" --list > "$inventory_log" 2>&1
    python3 ../tests/terrane/check_native_gate.py inventory \
      "$inventory_log" '${builtins.toJSON selectors}'
    python3 - "$inventory_log" '${builtins.toJSON selectors}' <<'PY_INVENTORY'
    import json
    import pathlib
    import sys

    lines = pathlib.Path(sys.argv[1]).read_text().splitlines()
    required = json.loads(sys.argv[2])
    if any(lines.count(name + ": test") != 1 for name in required):
        raise SystemExit("capacity selectors must each occur exactly once")
    PY_INVENTORY

    # Each process gets fresh native storage and the same finite outer bound
    # as its nextest override. Publication policy and first-pack clocks remain
    # enforced by the genuine repository, not by the harness timeout.
    case_number=0
    for test_name in ${builtins.concatStringsSep " " selectors}; do
      case_number=$((case_number + 1))
      case_tmp=$(mktemp -d "$TMPDIR/index-populations-case.XXXXXXXX")
      chmod 700 "$case_tmp"
      case_log="$out/logs/index-populations-case-$case_number.log"
      if TMPDIR="$case_tmp" ${coreutils}/bin/timeout --signal=TERM --kill-after=30s 1800s \
        "$TERRANE_NATIVE_SDK_TEST_BINARY" "$test_name" \
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
        "$case_log" "[\"$test_name\"]"
      python3 - "$case_log" "$test_name" <<'PY_EXECUTION'
    import pathlib
    import sys

    lines = pathlib.Path(sys.argv[1]).read_text().splitlines()
    summary = "test result: ok. 1 passed; 0 failed; 0 ignored;"
    if (lines.count("test " + sys.argv[2] + " ... ok") != 1
            or sum(line.startswith("test result:") for line in lines) != 1
            or sum(line.startswith(summary) for line in lines) != 1):
        raise SystemExit("capacity selector must execute exactly one passing, nonignored test")
    PY_EXECUTION
    done
    printf 'PASS: six growing native populations retain exact work and canonical-output checks\n' > "$out/result"
  ''
