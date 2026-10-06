{sourceGate}: let
  tests = [
    "separate_invocations_initialize_commit_fork_merge_and_checkout"
    "local_commands_refuse_reinitialization_and_unsafe_existing_authority"
    "configured_role_parser_and_unavailable_dispatch_remain_compatible"
  ];
in
  sourceGate "local-cli-workflow" ''
    cd crates
    cargo test --frozen --offline -p terrane-cli --test local_cli \
      -- --list > "$TMPDIR/cli-tests.txt"
    python3 ../tests/terrane/check_native_gate.py inventory \
      "$TMPDIR/cli-tests.txt" '${builtins.toJSON tests}'
    for test_name in ${builtins.concatStringsSep " " tests}; do
      if ! cargo test --frozen --offline -p terrane-cli --test local_cli \
        "$test_name" -- --exact > "$TMPDIR/cli-test.log" 2>&1; then
        cat "$TMPDIR/cli-test.log"
        exit 1
      fi
      python3 ../tests/terrane/check_native_gate.py execution \
        "$TMPDIR/cli-test.log" "[\"$test_name\"]"
    done
    printf 'PASS: public local CLI workflow (3 exact cases); ext4 deployment remains separate\n' \
      > "$out/result"
  ''
